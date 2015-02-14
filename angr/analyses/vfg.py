from collections import defaultdict

import networkx

import logging
import simuvex
import claripy
import angr
from .entry_wrapper import EntryWrapper, CallStack
from .cfg_base import CFGBase
from ..analysis import Analysis
from ..errors import AngrVFGError

l = logging.getLogger(name="angr.analyses.vfg")

# The maximum tracing times of a basic block before we widen the results
MAX_TRACING_TIMES = 5

class VFG(Analysis, CFGBase):
    '''
    This class represents a control-flow graph with static analysis result.
    '''

    def __init__(self, cfg=None, context_sensitivity_level=2, function_start=None, interfunction_level=0):
        '''

        :param project: The project object.
        :param context_sensitivity_level: The level of context-sensitivity of this CFG.
                                        It ranges from 1 to infinity.
        :return:
        '''
        self._cfg = cfg if cfg else self._p.results.CFG

        CFGBase.__init__(self, self._p, context_sensitivity_level)

        # Initial states for start analyzing different functions
        # It maps function key to its states
        self._function_initial_states = defaultdict(dict)

        # All final states are put in this list
        self.final_states = [ ]

        self.construct(function_start=function_start, interfunction_level=interfunction_level)


    def copy(self):
        new_vfg = VFG(self._project)
        new_vfg._cfg = self._cfg
        new_vfg._graph = networkx.DiGraph(self._graph)
        new_vfg._bbl_dict = self._bbl_dict.copy()
        new_vfg._edge_map = self._edge_map.copy()
        new_vfg._loop_back_edges = self._loop_back_edges[::]
        new_vfg._overlapped_loop_headers = self._overlapped_loop_headers[::]
        new_vfg._function_manager = self._function_manager
        new_vfg._thumb_addrs = self._thumb_addrs.copy()
        return new_vfg

    def _prepare_state(self, function_start, initial_state, function_key):
        # Crawl the binary, create CFG and fill all the refs inside project!
        if initial_state is None:
            if function_start not in self._function_initial_states:
                # We have never saved any initial states for this function
                # Gotta create a fresh state for it
                s = self._project.initial_state(mode="static",
                                              add_options={simuvex.o.ABSTRACT_MEMORY,
                                                            simuvex.o.ABSTRACT_SOLVER}
                )

                if function_start != self._project.main_binary.entry:
                    # This function might have arguments passed on stack, so make
                    # some room for them.
                    # TODO: Decide the number of arguments and their positions
                    #  during CFG analysis
                    sp = s.reg_expr('sp')
                    # Set the address mapping
                    sp_val = s.se.any_int(sp) # FIXME: What will happen if we lose track of multiple sp values?
                    s.memory.set_stack_address_mapping(sp_val,
                                                       s.memory.stack_id(function_start) + '_pre',
                                                       0x0)
                    new_sp = sp - 160
                    s.store_reg('sp', new_sp)
            else:
                if function_key is None:
                    l.debug('We should combine all existing states for this function, then analyze it.')
                    merged_state = None
                    for state in self._function_initial_states[function_start].values():
                        if merged_state is None:
                            merged_state = state
                        else:
                            merged_state, _, _ = merged_state.merge(state)
                    s = merged_state
                elif function_key in self._function_initial_states[function_start]:
                    l.debug('Loading previously saved state for function 0x%x %s', function_start,
                            CallStack.stack_suffix_to_string(function_key))
                    s = self._function_initial_states[function_start][function_key]
                else:
                    raise AngrVFGError('Initial state for function 0x%x and function key %s is not found.' %
                                       (function_start, CallStack.stack_suffix_to_string(function_key)))
        else:
            if function_key is not None:
                # Warn the user
                l.warning('Arguments "function_key" and "initial_state" should not be specified together. ' +
                          'Using specified initial_state as the state.')
            s = initial_state

        # Set the stack address mapping for the initial stack
        s.memory.set_stack_size(s.arch.stack_size)
        initial_sp = s.se.any_int(s.reg_expr('sp')) # FIXME: This is bad, as it may lose tracking of multiple sp values
        s.memory.set_stack_address_mapping(initial_sp,
                                           s.memory.stack_id(function_start),
                                           function_start)

        return s

    # Construct the CFG from an angr. binary object
    def construct(self, function_start=None, interfunction_level=0, avoid_runs=None, initial_state=None, function_key=None):
        '''
        Construct the value-flow graph, starting at a specific start, until we come to a fixpoint

        Params:

        @param binary: The binary object that you wanna construct the CFG for

        Optional params:

        @param avoid_runs: A collection of basic block addresses that you want
                        to avoid during CFG generation.
                        e.g.: [0x400100, 0x605100]
        '''
        avoid_runs = [ ] if avoid_runs is None else avoid_runs

        # Traverse all the IRSBs, and put them to a dict
        # It's actually a multi-dict, as each SIRSB might have different states
        # on different call predicates
        if self._bbl_dict is None:
            self._bbl_dict = {}
        if function_start is None:
            function_start = self._project.main_binary.entry
        l.debug("Starting from 0x%x", function_start)

        # Prepare the state
        loaded_state = self._prepare_state(function_start, initial_state, function_key)
        loaded_state.ip = function_start
        # Create the initial SimExit
        entry_point_path = self._project.exit_to(state=loaded_state.copy())

        exit_wrapper = EntryWrapper(entry_point_path, self._context_sensitivity_level)
        worklist = [exit_wrapper]
        traced_sim_blocks = defaultdict(lambda: defaultdict(int)) # Counting how many times a basic block is traced into
        traced_sim_blocks[exit_wrapper.call_stack_suffix()][function_start] = 1

        self._loop_back_edges = []
        self._overlapped_loop_headers = []

        # For each call, we are always getting two exits: an Ijk_Call that
        # stands for the real call exit, and an Ijk_Ret that is a simulated exit
        # for the retn address. There are certain cases that the control flow
        # never returns to the next instruction of a callsite due to
        # imprecision of the concrete execution. So we save those simulated
        # exits here to increase our code coverage. Of course the real retn from
        # that call always precedes those "fake" retns.
        # Tuple --> (Initial state, call_stack, bbl_stack)
        fake_func_retn_paths = {}
        # A dict to log edges and the jumpkind between each basic block
        self._edge_map = defaultdict(list)
        exit_targets = self._edge_map
        # A dict to record all blocks that returns to a specific address
        retn_target_sources = defaultdict(list)
        # Iteratively analyze every exit
        while len(worklist) > 0:
            path_wrapper = worklist.pop()

            # Print out the debugging memory information
            # current_exit_wrapper.sim_exit().state.memory.dbg_print()

            # Process the popped path
            self._handle_entry(path_wrapper, worklist,
                              exit_targets, fake_func_retn_paths,
                              traced_sim_blocks, retn_target_sources,
                              avoid_runs, interfunction_level)

            while len(worklist) == 0 and len(fake_func_retn_paths) > 0:
                # We don't have any exits remaining. Let's pop a fake exit to
                # process
                fake_exit_tuple = fake_func_retn_paths.keys()[0]
                fake_exit_state, fake_exit_call_stack, fake_exit_bbl_stack = \
                    fake_func_retn_paths.pop(fake_exit_tuple)
                fake_exit_addr = fake_exit_tuple[len(fake_exit_tuple) - 1]
                # Let's check whether this address has been traced before.
                targets = filter(lambda r: r == fake_exit_tuple,
                                 exit_targets)
                if len(targets) > 0:
                    # That block has been traced before. Let's forget about it
                    l.debug("Target 0x%08x has been traced before." + \
                            "Trying the next one...", fake_exit_addr)
                    continue

                # FIXME: Remove those assertions
                assert fake_exit_state.se.exactly_n_int(fake_exit_state.ip, 1)[0] == fake_exit_addr
                assert fake_exit_state.log.jumpkind == 'Ijk_Ret'

                new_path = self._project.exit_to(state=fake_exit_state)
                new_path_wrapper = EntryWrapper(new_path,
                                                  self._context_sensitivity_level,
                                                  call_stack=fake_exit_call_stack,
                                                  bbl_stack=fake_exit_bbl_stack)
                worklist.append(new_path_wrapper)
                l.debug("Tracing a missing retn exit 0x%08x, %s", fake_exit_addr, "->".join([hex(i) for i in fake_exit_tuple if i is not None]))
                break

        new_graph = self._create_graph(return_target_sources=retn_target_sources)
        if self._graph is None:
            self._graph = new_graph
        else:
            self._graph.add_edges_from(new_graph.edges(data=True))

        # Determine the last basic block
        for n in self._graph.nodes():
            if self._graph.out_degree(n) == 0:
                self.final_states.extend(n.successors)

    def _create_graph(self, return_target_sources=None):
        '''
        Create a DiGraph out of the existing edge map.
        :param return_target_sources: Used for making up those missing returns
        :return: A networkx.DiGraph() object
        '''
        exit_targets = self._edge_map

        if return_target_sources is None:
            # We set it to a defaultdict in order to be consistent with the
            # actual parameter.
            return_target_sources = defaultdict(list)

        cfg = networkx.DiGraph()
        # The corner case: add a node to the graph if there is only one block
        if len(self._bbl_dict) == 1:
            cfg.add_node(self._bbl_dict[self._bbl_dict.keys()[0]])

        # Adding edges
        for tpl, targets in exit_targets.items():
            basic_block = self._bbl_dict[tpl] # Cannot fail :)
            for ex, jumpkind in targets:
                if ex in self._bbl_dict:
                    target_bbl = self._bbl_dict[ex]
                    cfg.add_edge(basic_block, target_bbl, jumpkind=jumpkind)

                    # Add edges for possibly missing returns
                    if basic_block.addr in return_target_sources:
                        for src_irsb_key in \
                                return_target_sources[basic_block.addr]:
                            cfg.add_edge(self._bbl_dict[src_irsb_key],
                                               basic_block, jumpkind="Ijk_Ret")
                else:
                    # Debugging output
                    def addr_formalize(addr):
                        if addr is None:
                            return "None"
                        else:
                            return "0x%08x" % addr

                    s = "(["
                    for addr in ex[:-1]:
                        s += addr_formalize(addr) + ", "
                    s += "] %s)" % addr_formalize(ex[-1])
                    l.warning("Key %s does not exist.", s)

        return cfg

    def _get_simrun(self, state, current_path, addr):
        error_occured = False

        try:
            sim_run = self._project.sim_run(current_path.state)
        except simuvex.SimIRSBError as ex:
            # It's a tragedy that we came across some instructions that VEX
            # does not support. I'll create a terminating stub there
            l.error("SimIRSBError occurred(%s). Creating a PathTerminator.", ex)
            error_occured = True
            sim_run = \
                simuvex.procedures.SimProcedures["stubs"]["PathTerminator"](
                    state, addr=addr)
        except claripy.ClaripyError as ex:
            l.error("ClaripyError: ", exc_info=True)
            error_occured = True
            # Generate a PathTerminator to terminate the current path
            sim_run = \
                simuvex.procedures.SimProcedures["stubs"]["PathTerminator"](
                    state, addr=addr)
        except simuvex.SimError as ex:
            l.error("SimError: ", exc_info=True)

            error_occured = True
            # Generate a PathTerminator to terminate the current path
            sim_run = \
                simuvex.procedures.SimProcedures["stubs"]["PathTerminator"](
                    state, addr=addr)
        except angr.errors.AngrError as ex:
            segment = self._project.ld.main_bin.in_which_segment(addr)
            l.error("AngrError %s when creating SimRun at 0x%x (segment %s)",
                    ex, addr, segment)
            # We might be on a wrong branch, and is likely to encounter the
            # "No bytes in memory xxx" exception
            # Just ignore it
            error_occured = True
            sim_run = None

        return sim_run, error_occured

    def _handle_entry(self, entry_wrapper, remaining_exits, exit_targets,
                     fake_func_retn_exits, traced_sim_blocks, retn_target_sources,
                     avoid_runs, interfunction_level):
        '''
        Handles an SimExit instance

        In static mode, we create a unique stack region for each function, and
        normalize its stack pointer to the default stack offset.
        '''
        current_path = entry_wrapper.path
        call_stack_suffix = entry_wrapper.call_stack_suffix()
        current_function_address = entry_wrapper.current_function_address
        addr = current_path.addr
        initial_state = current_path.state

        # Prepare the state
        initial_state = initial_state.arch.prepare_state(initial_state,
                                                         {'current_function': current_function_address, }
        )


        simrun, error_occured = self._get_simrun(initial_state, current_path, addr)

        if simrun is None:
            return

        # Adding the new sim_run to our dict
        self._bbl_dict[call_stack_suffix + (addr,)] = simrun

        if addr not in avoid_runs:
            # Obtain successors
            tmp_successors = simrun.successors
        else:
            tmp_successors = []

        if isinstance(simrun, simuvex.SimIRSB) and \
                self._project.is_thumb_state(current_path.state):
            self._thumb_addrs.update(simrun.imark_addrs())

        if len(tmp_successors) == 0:
            if isinstance(simrun,
                simuvex.procedures.SimProcedures["stubs"]["PathTerminator"]):
                # If there is no valid exit in this branch and it's not
                # intentional (e.g. caused by a SimProcedure that does not
                # do_return) , we should make it
                # return to its callsite. However, we don't want to use its
                # state as it might be corrupted. Just create a link in the
                # exit_targets map.
                retn_target = entry_wrapper.call_stack.get_ret_target()
                if retn_target is not None:
                    new_call_stack = entry_wrapper.call_stack_copy()
                    exit_target_tpl = new_call_stack.stack_suffix(self._context_sensitivity_level) + (retn_target,)
                    exit_targets[call_stack_suffix + (addr,)].append(
                        (exit_target_tpl, 'Ijk_Ret'))
            else:
                # This is intentional. We shall remove all the fake
                # returns generated before along this path.

                # Build the tuples that we want to remove from
                # the dict fake_func_retn_exits
                tpls_to_remove = []
                call_stack_copy = entry_wrapper.call_stack_copy()
                while call_stack_copy.get_ret_target() is not None:
                    ret_target = call_stack_copy.get_ret_target()
                    # Remove the current call stack frame
                    call_stack_copy.ret(ret_target)
                    call_stack_suffix = call_stack_copy.stack_suffix(self._context_sensitivity_level)
                    tpl = call_stack_suffix + (ret_target,)
                    tpls_to_remove.append(tpl)
                # Remove those tuples from the dict
                for tpl in tpls_to_remove:
                    if tpl in fake_func_retn_exits:
                        del fake_func_retn_exits[tpl]
                        l.debug("Removed (%s) from FakeExits dict.", \
                                ",".join([hex(i) if i is not None else 'None' for i in tpl]))

        # If there is a call exit, we shouldn't put the default exit (which
        # is artificial) into the CFG. The exits will be Ijk_Call and
        # Ijk_Ret, and Ijk_Call always goes first
        is_call_exit = False
        call_target = None

        exits_to_append = []

        # For debugging purpose!
        _dbg_exit_status = {}

        i = 0
        while i < len(tmp_successors):
            suc_state = tmp_successors[i]
            i += 1 # Notice: DO NOT USE i LATER

            _dbg_exit_status[suc_state] = ""

            new_initial_state = suc_state.copy()
            new_jumpkind = suc_state.log.jumpkind

            if new_jumpkind == "Ijk_Call":
                is_call_exit = True

            try:
                new_addr = suc_state.se.exactly_n_int(suc_state.ip, 1)[0]
            except simuvex.SimValueError:
                # TODO: Should fall back to reading targets from CFG
                # It cannot be concretized currently. Maybe we could handle
                # it later, maybe it just cannot be concretized
                continue

            # Get the new call stack of target block
            if new_jumpkind == "Ijk_Call":
                call_target = new_addr

                # Check if that function is returning
                if self._cfg is not None:
                    func = self._cfg.function_manager.function(call_target)
                    if func is not None and not func.has_return and len(tmp_successors) == 2:
                        # Remove the fake return as it is not returning anyway...
                        tmp_successors = tmp_successors[: 1]

                if len(entry_wrapper.call_stack) < interfunction_level:
                    new_call_stack = entry_wrapper.call_stack_copy()
                    # Notice that in ARM, there are some freaking instructions
                    # like
                    # BLEQ <address>
                    # It should give us three exits: Ijk_Call, Ijk_Boring, and
                    # Ijk_Ret. The last exit is simulated.
                    # Notice: We assume the last exit is the simulated one
                    retn_target_addr = tmp_successors[-1].se.exactly_n_int(tmp_successors[-1].ip, 1)[0]
                    new_call_stack.call(addr, new_addr,
                            retn_target=retn_target_addr)
                else:
                    l.debug('We are not tracing into a new function because we run out of energy :-(')
                    # However, we do want to save out the state here
                    new_call_stack_suffix = entry_wrapper.call_stack.stack_suffix(self._context_sensitivity_level)
                    function_key = new_call_stack_suffix + (addr, )
                    function_addr = new_addr
                    l.debug('Saving out the state for function 0x%x with function_key %s', function_addr, CallStack.stack_suffix_to_string(function_key))
                    if function_addr in self._function_initial_states and \
                                    function_key in self._function_initial_states[function_addr]:
                        existing_state = self._function_initial_states[function_addr][function_key]
                        merged_state, _, _ = existing_state.merge(new_initial_state)
                        self._function_initial_states[function_addr][function_key] = merged_state
                    else:
                        self._function_initial_states[function_addr][function_key] = new_initial_state

                    # Go on to handle the next exit
                    continue
            elif new_jumpkind == "Ijk_Ret" and not is_call_exit:
                new_call_stack = entry_wrapper.call_stack_copy()
                new_call_stack.ret(new_addr)
            else:
                # Normal control flow transition
                new_call_stack = entry_wrapper.call_stack

            new_call_stack_suffix = new_call_stack.stack_suffix(self._context_sensitivity_level)
            new_tpl = new_call_stack_suffix + (new_addr,)

            if isinstance(simrun, simuvex.SimIRSB):
                self._detect_loop(simrun, new_tpl, addr,
                                  exit_targets, call_stack_suffix,
                                  new_call_stack_suffix, new_addr,
                                  new_jumpkind, entry_wrapper)

            # Generate the new BBL stack of target block
            if new_jumpkind == "Ijk_Call":
                new_bbl_stack = entry_wrapper.bbl_stack_copy()
                new_bbl_stack.call(new_call_stack_suffix)
                new_bbl_stack.push(new_call_stack_suffix, new_addr)
            elif new_jumpkind == "Ijk_Ret" and not is_call_exit:
                new_bbl_stack = entry_wrapper.bbl_stack_copy()
                new_bbl_stack.ret(call_stack_suffix)
            else:
                new_bbl_stack = entry_wrapper.bbl_stack_copy()
                new_bbl_stack.push(new_call_stack_suffix, new_addr)

            # Generate new exits
            if new_jumpkind == "Ijk_Ret" and not is_call_exit:
                # This is the real retn exit
                # Remember this retn!
                retn_target_sources[new_addr].append(call_stack_suffix + (addr,))
                # Check if this retn is inside our fake_func_retn_exits set
                if new_tpl in fake_func_retn_exits:
                    del fake_func_retn_exits[new_tpl]

            if new_jumpkind == "Ijk_Ret" and is_call_exit:
                # This is the default "fake" retn that generated at each
                # call. Save them first, but don't process them right
                # away

                # Clear the useless values (like return addresses, parameters) on stack if needed
                if self._cfg is not None:
                    current_function = self._cfg.function_manager.function(call_target)
                    if current_function is not None:
                        sp_difference = current_function.sp_difference
                    else:
                        sp_difference = 0
                    reg_sp_offset = new_initial_state.arch.sp_offset
                    reg_sp_expr = new_initial_state.reg_expr(reg_sp_offset) + sp_difference
                    new_initial_state.store_reg(new_initial_state.arch.sp_offset, reg_sp_expr)

                    # Clear the return value with a TOP
                    top_si = new_initial_state.se.TopStridedInterval(new_initial_state.arch.bits)
                    new_initial_state.store_reg(new_initial_state.arch.ret_offset, top_si)

                    fake_func_retn_exits[new_tpl] = \
                        (new_initial_state, new_call_stack, new_bbl_stack)
                    _dbg_exit_status[suc_state] = "Appended to fake_func_retn_exits"

            else:
                #traced_sim_blocks[new_call_stack_suffix][new_addr] < MAX_TRACING_TIMES:
                traced_sim_blocks[new_call_stack_suffix][new_addr] += 1

                # FIXME: Remove this line later
                assert new_initial_state.se.exactly_n_int(new_initial_state.ip, 1)[0] == new_addr
                assert new_initial_state.log.jumpkind == suc_state.log.jumpkind

                new_exit = self._project.exit_to(state=new_initial_state)
                if simuvex.o.ABSTRACT_MEMORY in suc_state.options and \
                                suc_state.log.jumpkind == "Ijk_Call":
                    # If this is a call, we create a new stack address mapping
                    reg_sp_offset = new_exit.state.arch.sp_offset
                    reg_sp_expr = new_exit.state.reg_expr(reg_sp_offset).model
                    assert type(reg_sp_expr) == claripy.vsa.ValueSet

                    assert len(reg_sp_expr.items()) == 1
                    reg_sp_si = reg_sp_expr.items()[0][1]
                    reg_sp_val = reg_sp_si.min - new_exit.state.arch.bits / 8 # TODO: Is it OK?
                    new_stack_region_id = new_exit.state.memory.stack_id(new_addr)
                    new_exit.state.memory.set_stack_address_mapping(reg_sp_val,
                                                                    new_stack_region_id,
                                                                    new_addr)
                    new_si = new_exit.state.se.StridedInterval(bits=new_exit.state.arch.bits,
                                                               stride=0,
                                                               lower_bound=0,
                                                               upper_bound=0)
                    new_reg_sp_expr = new_exit.state.se.ValueSet()
                    new_reg_sp_expr.model.set_si('global', reg_sp_si.copy())
                    # Save the new sp register
                    new_exit.state.store_reg(reg_sp_offset, new_reg_sp_expr)
                elif simuvex.o.ABSTRACT_MEMORY in suc_state.options and \
                                suc_state.log.jumpkind == "Ijk_Ret":
                    # Remove the existing stack address mapping
                    # FIXME: Now we are assuming the sp is restored to its original value
                    reg_sp_offset = new_exit.state.arch.sp_offset
                    reg_sp_expr = new_exit.state.reg_expr(reg_sp_offset).model
                    assert type(reg_sp_expr) == claripy.vsa.ValueSet

                    assert len(reg_sp_expr.items()) == 1
                    reg_sp_si = reg_sp_expr.items()[0][1]
                    reg_sp_val = reg_sp_si.min
                    # TODO: Finish it!

                # Examine each exit and see if it brings a newer state. Only recalculate
                # it when there is a newer state
                if new_tpl in self._bbl_dict:
                    l.debug("Analyzing %s for the %dth time...", self._bbl_dict[new_tpl],
                            traced_sim_blocks[new_call_stack_suffix][new_addr])
                    new_state = new_exit.state
                    old_state = self._bbl_dict[new_tpl].initial_state

                    if traced_sim_blocks[new_call_stack_suffix][new_addr] >= MAX_TRACING_TIMES:
                        diff = traced_sim_blocks[new_call_stack_suffix][new_addr] - MAX_TRACING_TIMES
                        if diff % 2 == 0:
                            new_state.options.add(simuvex.s_options.WIDEN_ON_MERGE)
                        else:
                            new_state.options.add(simuvex.s_options.REFINE_AFTER_WIDENING)

                    merged_state, _, merging_occured = new_state.merge(old_state)

                    if simuvex.s_options.WIDEN_ON_MERGE in merged_state.options:
                        merged_state.options.remove(simuvex.s_options.WIDEN_ON_MERGE)
                    if simuvex.s_options.REFINE_AFTER_WIDENING in merged_state.options:
                        merged_state.options.remove(simuvex.s_options.REFINE_AFTER_WIDENING)

                    if merging_occured:
                        new_exit.state = merged_state
                        new_exit_wrapper = EntryWrapper(new_exit,
                                                          self._context_sensitivity_level,
                                                          call_stack=new_call_stack,
                                                          bbl_stack=new_bbl_stack)
                        remaining_exits.append(new_exit_wrapper)
                        _dbg_exit_status[suc_state] = "Appended"
                        l.debug("Merging occured for %s!", self._bbl_dict[new_tpl])
                    else:
                        _dbg_exit_status[suc_state] = "Reached fixpoint"
                else:
                    new_exit_wrapper = EntryWrapper(new_exit,
                                                      self._context_sensitivity_level,
                                                      call_stack=new_call_stack,
                                                      bbl_stack=new_bbl_stack)
                    remaining_exits.append(new_exit_wrapper)
                    _dbg_exit_status[suc_state] = "Appended"

            if not is_call_exit or new_jumpkind != "Ijk_Ret":
                exit_targets[call_stack_suffix + (addr,)].append((new_tpl, new_jumpkind))
            else:
                # This is the fake return!
                exit_targets[call_stack_suffix + (addr,)].append((new_tpl, "Ijk_FakeRet"))

        # Debugging output
        l.debug("Basic block %s %s", simrun, "->".join([hex(i) for i in call_stack_suffix if i is not None]))
        l.debug("(Function %s)" % self._project.ld.main_bin.function_name(int(simrun.id_str,16)))
        l.debug("|    Has simulated retn: %s", is_call_exit)
        for suc_state in tmp_successors:
            if is_call_exit and suc_state.log.jumpkind == "Ijk_Ret":
                exit_type_str = "Simulated Ret"
            else:
                exit_type_str = "-"
            try:
                l.debug("|    target: 0x%08x %s [%s] %s", suc_state.se.exactly_n_int(suc_state.ip, 1)[0], _dbg_exit_status[suc_state], exit_type_str, suc_state.log.jumpkind)
            except simuvex.SimValueError:
                l.debug("|    target cannot be concretized. %s [%s] %s", _dbg_exit_status[suc_state], exit_type_str, suc_state.log.jumpkind)
        l.debug("len(remaining_exits) = %d, len(fake_func_retn_exits) = %d", len(remaining_exits), len(fake_func_retn_exits))

    def _detect_loop(self, sim_run, new_tpl, addr, exit_targets,
                     call_stack_suffix, new_call_stack_suffix,
                     new_addr, new_jumpkind, current_exit_wrapper):
        # Loop detection
        assert isinstance(sim_run, simuvex.SimIRSB)

        # Loop detection only applies to SimIRSBs
        # The most f****** case: An IRSB branches to itself
        if new_tpl == call_stack_suffix + (addr,):
            l.debug("%s is branching to itself. That's a loop.", sim_run)
            self._loop_back_edges.append((sim_run, sim_run))
        elif new_jumpkind != "Ijk_Call" and new_jumpkind != "Ijk_Ret" and \
                current_exit_wrapper.bbl_in_stack(
                                                new_call_stack_suffix, new_addr):
            '''
            There are two cases:
            # The loop header we found is a single IRSB that doesn't overlap with
            other IRSBs
            or
            # The loop header we found is a subset of the original loop header IRSB,
            as IRSBa could be inside IRSBb if they don't start at the same address but
            end at the same address
            We should take good care of these two cases.
            ''' #pylint:disable=W0105
            # First check if this is an overlapped loop header
            next_irsb = self._bbl_dict[new_tpl]
            assert next_irsb is not None
            other_preds = set()
            for k_tpl, v_lst in exit_targets.items():
                a = k_tpl[-1]
                for v_tpl in v_lst:
                    b = v_tpl[-2] # The last item is the jumpkind :)
                    if b == next_irsb.addr and a != sim_run.addr:
                        other_preds.add(self._bbl_dict[k_tpl])
            if len(other_preds) > 0:
                is_overlapping = False
                for p in other_preds:
                    if isinstance(p, simuvex.SimIRSB):
                        if p.addr + p.irsb.size() == sim_run.addr + sim_run.irsb.size():
                            # Overlapping!
                            is_overlapping = True
                            break
                if is_overlapping:
                    # Case 2, it's overlapped with another loop header
                    # Pending. We should remove all exits from sim_run
                    self._overlapped_loop_headers.append(sim_run)
                    l.debug("Found an overlapped loop header %s", sim_run)
                else:
                    # Case 1
                    self._loop_back_edges.append((sim_run, next_irsb))
                    l.debug("Found a loop, back edge %s --> %s", sim_run, next_irsb)
            else:
                # Case 1, it's not over lapping with any other things
                self._loop_back_edges.append((sim_run, next_irsb))
                l.debug("Found a loop, back edge %s --> %s", sim_run, next_irsb)

    def _get_block_addr(self, b): #pylint:disable=R0201
        if isinstance(b, simuvex.SimIRSB):
            return b.first_imark.addr
        elif isinstance(b, simuvex.SimProcedure):
            return b.addr
        else:
            raise Exception("Unsupported block type %s" % type(b))

    def get_lbe_exits(self):
        """
        -> Generator
        Returns a generator of exits of the loops
        based on the back egdes
        """
        for lirsb, firsb in self._loop_back_edges:
            exits = lirsb.exits()
            yield exits

    def remove_cycles(self):
        l.debug("Removing cycles...")
        l.debug("There are %d loop back edges.", len(self._loop_back_edges))
        l.debug("And there are %d overlapping loop headers.", len(self._overlapped_loop_headers))
        # First break all detected loops
        for b1, b2 in self._loop_back_edges:
            if self._graph.has_edge(b1, b2):
                l.debug("Removing loop back edge %s -> %s", b1, b2)
                self._graph.remove_edge(b1, b2)
        # Then remove all outedges from overlapped loop headers
        for b in self._overlapped_loop_headers:
            successors = self._graph.successors(b)
            for succ in successors:
                self._graph.remove_edge(b, succ)
                l.debug("Removing partial loop header edge %s -> %s", b, succ)
