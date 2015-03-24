from collections import defaultdict
import logging

import networkx
import simuvex
import claripy

from ..entry_wrapper import EntryWrapper, CallStack
from .cfg_base import CFGBase
from ..analysis import Analysis
from ..errors import AngrVFGError, AngrVFGRestartAnalysisNotice, AngrError

l = logging.getLogger(name="angr.analyses.vfg")

# The maximum tracing times of a basic block before we widen the results
MAX_ANALYSIS_TIMES_WITHOUT_MERGING = 10
MAX_ANALYSIS_TIMES = 20

class VFG(Analysis):
    '''
    This class represents a control-flow graph with static analysis result.
    '''

    def __init__(self, cfg=None, context_sensitivity_level=2, function_start=None, interfunction_level=0, initial_state=None, avoid_runs=None):
        '''

        :param project: The project object.
        :param context_sensitivity_level: The level of context-sensitivity of this VFG.
                                        It ranges from 0 to infinity.
        :return:
        '''

        # Related CFG.
        # We can still perform analysis if you don't specify a CFG. But providing a CFG may give you better result.
        self._cfg = cfg

        # Where to start the analysis
        self._start = function_start

        # Other parameters
        self._avoid_runs = [ ] if avoid_runs is None else avoid_runs
        self._context_sensitivity_level = context_sensitivity_level
        self._interfunction_level = interfunction_level

        self.graph = None # TODO: Maybe we want to remove this line?
        self._nodes = { } # TODO: Maybe we want to remove this line?
        self._graph = None # TODO: Maybe we want to remove this line?

        self._project = self._p

        self._normal_states = { } # Last available state for each program point without widening
        self._widened_states = { } # States on which widening has occurred

        # Initial states for start analyzing different functions
        # It maps function key to its states
        self._function_initial_states = defaultdict(dict)

        # All final states are put in this list
        self.final_states = [ ]

        self._uninitialized_access = { }
        self._state_initialization_map = defaultdict(list)

        # Begin VFG construction!
        self._construct(initial_state)

        self.result = {
            "graph": self.graph,
            "final_states": self.final_states
        }

    def copy(self):
        new_vfg = VFG(self._project)
        new_vfg._cfg = self._cfg
        new_vfg._graph = networkx.DiGraph(self._graph)
        new_vfg._nodes = self._nodes.copy()
        new_vfg._edge_map = self._edge_map.copy()
        return new_vfg

    def _prepare_state(self, function_start, initial_state, function_key):
        # Crawl the binary, create CFG and fill all the refs inside project!
        import ipdb; ipdb.set_trace()
        if initial_state is None:
            if function_start not in self._function_initial_states:
                # We have never saved any initial states for this function
                # Gotta create a fresh state for it
                s = self._project.state_generator.blank_state(mode="static",
                                              add_options={ simuvex.o.FRESHNESS_ANALYSIS }
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

    def _construct(self, initial_state=None):
        """
        Perform abstract intepretation analysis starting from the given function address. The output is an invariant at
        the beginning (or the end) of each basic block.

        Steps:
        # Generate a CFG first if CFG is not provided.
        # Identify all merge points (denote the set of merge points as Pw) in the CFG.
        # Cut those loop back edges (can be derived from Pw) so that we gain an acyclic CFG.
        # Identify all variables that are 1) from memory loading 2) from initial values, or 3) phi functions. Denote
            the set of those variables as S_{var}.
        # Start real AI analysis and try to compute a fix point of each merge point. Perfrom widening/narrowing only on
            variables \in S_{var}.
        """

        start = self._start

        if not self._cfg:
            # Generate a CFG if no CFG is provided
            l.debug("Generating a CFG starting at 0x%x", start)
            self._cfg = self._p.analyses.CFG(context_sensitivity_level=self._context_sensitivity_level,
                starts=(start, )
            )

        cfg = self._cfg

        # Identify all program points to perform a widening
        self._widen_points = cfg.get_loop_back_edges()

        # Cut the loops
        # TODO: I'm directly modifying the CFG. Is it OK, or we should make a copy of it first?
        #for src, dst in merge_points:
        #    self._cfg.graph.remove_edge(src, dst)

        restart_analysis = True

        while restart_analysis:

            restart_analysis = False

            # Initialization
            self._normal_states = { } # Last available state for each program point without widening
            self._widened_states = { } # States on which widening has occurred
            self._function_initial_states = defaultdict(dict)
            # All final states are put in this list
            self.final_states = [ ]

            self._nodes = { } # TODO: Remove it later

            try:
                self._ai_analyze(initial_state)
            except AngrVFGRestartAnalysisNotice:
                l.info("Restarting analysis.")
                restart_analysis = True

    '''
    def _identify_fresh_variables(self):
        """
        Identify all "fresh" variables at each merge point as well as in the beginning of the program.

        :return: Nothing
        """

        all_points = self._merge_points

        # Traverse the CFG starting from the start
        start = self._start

        # Listing all fresh variables at each merge point
        fresh_variables = { }

        worklist = [ start ]
        analyzed_paths = set()

        while len(worklist):
            addr = worklist.pop()

            p = self._p.path_generator.blank_path(address=addr, mode='static', add_options={ simuvex.o.FRESHNESS_ANALYSIS })
            successors = p.successors

            if p.addr == start or p.addr in set([ dst.addr for (src, dst) in all_points]):
                fresh_variables[p.addr] = successors[0].state.fresh_variables

            successors_in_cfg = self._cfg.get_successors(self._cfg.get_any_node(p.addr))

            for successor in successors_in_cfg:
                tpl = (p.addr, successor.addr)
                if tpl not in analyzed_paths:
                    analyzed_paths.add(tpl)
                    worklist.append(successor.addr)

        from simuvex import SimRegisterVariable, SimMemoryVariable

        for key, s in fresh_variables.items():
            print "0x%x: %s" % (key, [ self._p.arch.register_names[i.reg] for i in s.register_variables ])
            print "0x%x: %s" % (key, [ i for i in s.memory_variables ])

        __import__('ipdb').set_trace()
    '''

    def _ai_analyze(self, initial_state=None, function_key=None):
        """
        Construct the value-flow graph, starting at a specific start, until we come to a fixpoint for each merge point.
        """

        # Traverse all the IRSBs, and put them to a dict
        # It's actually a multi-dict, as each SIRSB might have different states
        # on different call predicates
        if self._nodes is None:
            self._nodes = { }

        function_start = self._start
        if function_start is None:
            function_start = self._project.main_binary.entry
        l.debug("Starting from 0x%x", function_start)

        # Prepare the state
        loaded_state = self._prepare_state(function_start, initial_state, function_key)
        loaded_state.ip = function_start
        loaded_state.uninitialized_access_handler = self._uninitialized_access_handler

        loaded_state = loaded_state.arch.prepare_state(loaded_state,
                                                         {'current_function': function_start, }
        )

        # Create the initial path
        # Also we want to identify all fresh variables at each merge point
        entry_point_path = self._project.path_generator.blank_path(
            state=loaded_state.copy(),
            add_options={ simuvex.o.FRESHNESS_ANALYSIS }
        )

        entry_wrapper = EntryWrapper(entry_point_path, self._context_sensitivity_level)

        # Initialize a worklist
        worklist = [ entry_wrapper ]

        # Counting how many times a basic block has been traced
        traced_sim_blocks = defaultdict(lambda: defaultdict(int))
        traced_sim_blocks[entry_wrapper.call_stack_suffix()][function_start] = 1

        # For each call, we are always getting two exits: an Ijk_Call that
        # stands for the real call exit, and an Ijk_Ret that is a simulated exit
        # for the retn address. There are certain cases that the control flow
        # never returns to the next instruction of a callsite due to
        # imprecision of the concrete execution. So we save those simulated
        # exits here to increase our code coverage. Of course the real retn from
        # that call always precedes those "fake" retns.
        # Tuple --> (Initial state, call_stack, bbl_stack)
        fake_func_return_paths = { }
        # A dict to log edges and the jumpkind between each basic block
        self._edge_map = defaultdict(list)
        exit_targets = self._edge_map
        # A dict to record all blocks that returns to a specific address
        retn_target_sources = defaultdict(list)

        # Iteratively analyze every exit
        while len(worklist):
            entry_wrapper = worklist.pop()

            # Process the popped path
            self._handle_entry(entry_wrapper, worklist,
                              exit_targets, fake_func_return_paths,
                              traced_sim_blocks, retn_target_sources
                              )

            while len(worklist) == 0 and len(fake_func_return_paths) > 0:
                # We don't have any paths remaining. Let's pop a previously-missing return to
                # process
                fake_exit_tuple = fake_func_return_paths.keys()[0]
                fake_exit_state, fake_exit_call_stack, fake_exit_bbl_stack = \
                    fake_func_return_paths.pop(fake_exit_tuple)
                fake_exit_addr = fake_exit_tuple[len(fake_exit_tuple) - 1]
                # Let's check whether this address has been traced before.
                targets = filter(lambda r: r == fake_exit_tuple,
                                 exit_targets)
                if len(targets) > 0:
                    # That block has been traced before. Let's forget about it
                    l.debug("Target 0x%08x has been traced before." +
                            "Trying the next one...",
                            fake_exit_addr)
                    continue

                new_path = self._project.path_generator.blank_path(state=fake_exit_state)
                new_path_wrapper = EntryWrapper(new_path,
                                                  self._context_sensitivity_level,
                                                  call_stack=fake_exit_call_stack,
                                                  bbl_stack=fake_exit_bbl_stack)
                worklist.append(new_path_wrapper)
                l.debug("Tracing a missing return 0x%08x, %s", fake_exit_addr,
                        "->".join([hex(i) for i in fake_exit_tuple if i is not None]))
                break

        # Create the real graph
        new_graph = self._create_graph(return_target_sources=retn_target_sources)
        if self._graph is None:
            self._graph = new_graph
        else:
            self._graph.add_edges_from(new_graph.edges(data=True))

        # Determine the last basic block
        for n in self._graph.nodes():
            if self._graph.out_degree(n) == 0:
                # TODO: Fix the issue when n.successors is empty
                if n.successors:
                    self.final_states.extend(n.successors)
                else:
                    self.final_states.append(n.initial_state)

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
        if len(self._nodes) == 1:
            cfg.add_node(self._nodes[self._nodes.keys()[0]])

        # Adding edges
        for tpl, targets in exit_targets.items():
            basic_block = self._nodes[tpl] # Cannot fail :)
            for ex, jumpkind in targets:
                if ex in self._nodes:
                    target_bbl = self._nodes[ex]
                    cfg.add_edge(basic_block, target_bbl, jumpkind=jumpkind)

                    # Add edges for possibly missing returns
                    if basic_block.addr in return_target_sources:
                        for src_irsb_key in \
                                return_target_sources[basic_block.addr]:
                            cfg.add_edge(self._nodes[src_irsb_key],
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
        restart_analysis = False

        try:
            sim_run = self._project.sim_run(current_path.state)
        except simuvex.SimUninitializedAccessError as ex:
            l.error("Found an uninitialized access (used as %s) at expression %s.", ex.expr_type, ex.expr)
            self._add_expression_to_initialize(ex.expr, ex.expr_type)
            sim_run = None
            error_occured = True
            restart_analysis = True
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
        except AngrError as ex:
            segment = self._project.ld.main_bin.in_which_segment(addr)
            l.error("AngrError %s when creating SimRun at 0x%x (segment %s)",
                    ex, addr, segment)
            # We might be on a wrong branch, and is likely to encounter the
            # "No bytes in memory xxx" exception
            # Just ignore it
            error_occured = True
            sim_run = None

        return sim_run, error_occured, restart_analysis

    def _remove_pending_return(self, entry_wrapper, pending_returns):
        """
        Remove all pending returns that are related to the current entry.
        """

        # Build the tuples that we want to remove from the dict fake_func_retn_exits
        tpls_to_remove = [ ]
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
            if tpl in pending_returns:
                del pending_returns[tpl]
                l.debug("Removed (%s) from FakeExits dict.",
                        ",".join([hex(i) if i is not None else 'None' for i in tpl]))

    def _handle_entry(self, entry_wrapper, remaining_entries, exit_targets,
                     pending_returns, traced_sim_blocks, retn_target_sources):
        '''
        Handles an entry in the program.

        In static mode, we create a unique stack region for each function, and
        normalize its stack pointer to the default stack offset.
        '''

        #
        # Extract initial values
        #
        avoid_runs = self._avoid_runs

        current_path = entry_wrapper.path
        call_stack_suffix = entry_wrapper.call_stack_suffix()
        current_function_address = entry_wrapper.current_function_address
        # We want to narrow the state if widening has occurred before
        widening_occurred = entry_wrapper.widening_occurred

        addr = current_path.addr
        input_state = current_path.state
        simrun_key = call_stack_suffix + (addr,)

        # Initialize the state with necessary values
        self._initialize_state(input_state)

        # Get the SimRun object
        simrun, error_occured, restart_analysis = self._get_simrun(input_state, current_path, addr)

        if restart_analysis:
            # We should restart the analysis because of something must be changed in the very initial state
            raise AngrVFGRestartAnalysisNotice()

        if simrun is None:
            # Ouch, we cannot get the simrun for some reason
            return

        # Adding the new sim_run to our dict
        self._nodes[simrun_key] = simrun

        if not widening_occurred:
            self._normal_states[simrun_key] = input_state

        if addr not in avoid_runs:
            # Obtain successors
            all_successors = simrun.successors
        else:
            all_successors = [ ]

        # Update thumb_addrs. TODO: Do we need it in VFG?
        if isinstance(simrun, simuvex.SimIRSB) and \
                self._project.is_thumb_state(current_path.state):
            self._thumb_addrs.update(simrun.imark_addrs())

        if len(all_successors) == 0:
            if isinstance(simrun,
                simuvex.procedures.SimProcedures["stubs"]["PathTerminator"]):
                # If there is no valid exit in this branch and it's not
                # intentional (e.g. caused by a SimProcedure that does not
                # do_return) , we should make it return to its callsite.
                # However, we don't want to use its state as it might be
                # corrupted. Just create a link in the exit_targets map.
                retn_target = entry_wrapper.call_stack.get_ret_target()
                if retn_target is not None:
                    new_call_stack = entry_wrapper.call_stack_copy()
                    exit_target_tpl = new_call_stack.stack_suffix(self._context_sensitivity_level) + (retn_target,)
                    exit_targets[call_stack_suffix + (addr,)].append(
                        (exit_target_tpl, 'Ijk_Ret'))
            else:
                # This is intentional. We shall remove all the pending returns generated before along this path.
                self._remove_pending_return(entry_wrapper, pending_returns)

        # If this is a call exit, we shouldn't put the default exit (which
        # is artificial) into the CFG. The exits will be Ijk_Call and
        # Ijk_Ret, and Ijk_Call always goes first
        is_call_jump = any([ i.log.jumpkind == 'Ijk_Call' for i in all_successors ])
        call_targets = [ i.se.exactly_int(i.ip) for i in all_successors if i.log.jumpkind == 'Ijk_Call' ]
        call_target = None if not call_targets else call_targets[0]

        is_return_jump = len(all_successors) and all_successors[0].log.jumpkind == 'Ijk_Ret'

        exits_to_append = []

        # For debugging purpose!
        _dbg_exit_status = { }

        for suc_state in all_successors:

            _dbg_exit_status[suc_state] = ""

            self._handle_successor(suc_state, entry_wrapper, all_successors, is_call_jump, is_return_jump, call_target, current_function_address,
                                   call_stack_suffix, retn_target_sources, pending_returns, traced_sim_blocks, remaining_entries,
                                   exit_targets, widening_occurred, _dbg_exit_status)


        # Debugging output
        function_name = self._project.ld.find_symbol_name(simrun.addr)
        module_name = self._project.ld.find_module_name(simrun.addr)

        l.debug("Basic block %s %s", simrun, "->".join([hex(i) for i in call_stack_suffix if i is not None]))
        l.debug("(Function %s of binary %s)", function_name, module_name)
        l.debug("|    Has simulated retn: %s", is_call_jump)
        for suc_state in all_successors:
            if is_call_jump and suc_state.log.jumpkind == "Ijk_Ret":
                exit_type_str = "Simulated Ret"
            else:
                exit_type_str = "-"
            try:
                l.debug("|    target: 0x%08x %s [%s] %s", suc_state.se.exactly_int(suc_state.ip), _dbg_exit_status[suc_state], exit_type_str, suc_state.log.jumpkind)
            except simuvex.SimValueError:
                l.debug("|    target cannot be concretized. %s [%s] %s", _dbg_exit_status[suc_state], exit_type_str, suc_state.log.jumpkind)
        l.debug("len(remaining_exits) = %d, len(fake_func_retn_exits) = %d", len(remaining_entries), len(pending_returns))

    def _handle_successor(self, suc_state, entry_wrapper, all_successors, is_call_jump, is_return_jump, call_target,
                          current_function_address, call_stack_suffix, retn_target_sources, pending_returns,
                          traced_sim_blocks, remaining_entries, exit_targets, should_narrow, _dbg_exit_status):

        #
        # Extract initial values
        #
        addr = entry_wrapper.path.addr
        jumpkind = suc_state.log.jumpkind
        se = suc_state.se

        #
        # Get instruction pointer
        #
        try:
            if is_return_jump:
                # FIXME: This is a bad practice...
                suc_state.ip = entry_wrapper.call_stack.get_ret_target()

            if len(suc_state.se.any_n_int(suc_state.ip, 2)) > 1:
                if is_return_jump:
                    # It might be caused by state merging
                    # We may retrieve the correct ip from call stack
                    suc_state.ip = entry_wrapper.call_stack.get_ret_target()
                else:
                    __import__('ipdb').set_trace()
                    l.warning("IP can be concretized to more than one value, which means it is corrupted.")
                    return

            successor_ip = suc_state.se.exactly_int(suc_state.ip)
        except simuvex.SimValueError:
            # TODO: Should fall back to reading targets from CFG
            # It cannot be concretized currently. Maybe we could handle
            # it later, maybe it just cannot be concretized
            return

        # Make a copy of the state in case we use it later
        successor_state = suc_state.copy()

        # Try to remove the unnecessary fakeret successor
        fakeret_successor = None
        if jumpkind == "Ijk_Call":
            fakeret_successor = all_successors[-1]

            # Check if that function is returning
            if self._cfg is not None:
                func = self._cfg.function_manager.function(call_target)
                if func is not None and not func.has_return and len(all_successors) == 2:
                    # Remove the fake return as it is not returning anyway...
                    del all_successors[-1]
                    fakeret_successor = None

        if jumpkind == "Ijk_Call" and \
                len(entry_wrapper.call_stack) > self._interfunction_level:
            l.debug('We are not tracing into a new function 0x%x because we run out of energy :-(', successor_ip)
            # However, we do want to save out the state here
            self._save_state(entry_wrapper, successor_ip, successor_state)

            # Go on to handle the next exit
            return

        # Create a new call stack
        new_call_stack = self._create_callstack(entry_wrapper, successor_ip, jumpkind, is_call_jump, fakeret_successor)
        if new_call_stack is None:
            l.debug("Cannot create a new callstack for address 0x%x", successor_ip)
            return
        new_call_stack_suffix = new_call_stack.stack_suffix(self._context_sensitivity_level)
        new_tpl = new_call_stack_suffix + (successor_ip, )

        # Generate the new BBL stack of target block
        new_bbl_stack = self._create_bblstack(entry_wrapper, jumpkind, successor_ip, is_call_jump, call_stack_suffix,
                                              new_call_stack_suffix, current_function_address)

        # Generate new exits
        if jumpkind == "Ijk_Ret" and not is_call_jump:
            # This is the real retn exit
            # Remember this retn!
            retn_target_sources[successor_ip].append(call_stack_suffix + (addr, ))
            # Check if this retn is inside our fake_func_retn_exits set
            if new_tpl in pending_returns:
                del pending_returns[new_tpl]

        if jumpkind == "Ijk_Ret" and is_call_jump:
            # This is the default "fake" return successor generated at each
            # call. Save them first, but don't process them right
            # away

            # Clear the useless values (like return addresses, parameters) on stack if needed
            if self._cfg is not None:
                current_function = self._cfg.function_manager.function(call_target)
                if current_function is not None:
                    sp_difference = current_function.sp_delta
                else:
                    sp_difference = 0
                reg_sp_offset = successor_state.arch.sp_offset
                reg_sp_expr = successor_state.reg_expr(reg_sp_offset) + sp_difference
                successor_state.store_reg(successor_state.arch.sp_offset, reg_sp_expr)

                # Clear the return value with a TOP
                top_si = successor_state.se.TopStridedInterval(successor_state.arch.bits)
                successor_state.store_reg(successor_state.arch.ret_offset, top_si)

                pending_returns[new_tpl] = \
                    (successor_state, new_call_stack, new_bbl_stack)
                _dbg_exit_status[suc_state] = "Appended to fake_func_retn_exits"

        else:
            traced_times = traced_sim_blocks[new_call_stack_suffix][successor_ip]

            if traced_times > MAX_ANALYSIS_TIMES:
                return

            if not should_narrow:
                traced_times += 1
                traced_sim_blocks[new_call_stack_suffix][successor_ip] = traced_times
            else:
                l.debug('Narrowing 0x%x', successor_ip)

            successor_path = self._project.path_generator.blank_path(state=successor_state)
            if simuvex.o.ABSTRACT_MEMORY in suc_state.options:
                if suc_state.log.jumpkind == "Ijk_Call":
                    # If this is a call, we create a new stack address mapping
                    reg_sp_si = self._create_stack_region(successor_path.state, successor_path.addr)

                    # Save the new sp register
                    new_reg_sp_expr = successor_path.state.se.ValueSet()
                    new_reg_sp_expr.model.set_si('global', reg_sp_si.copy())
                    reg_sp_offset = successor_state.arch.sp_offset
                    successor_path.state.store_reg(reg_sp_offset, new_reg_sp_expr)

                elif suc_state.log.jumpkind == "Ijk_Ret":
                    # Remove the existing stack address mapping
                    # FIXME: Now we are assuming the sp is restored to its original value
                    reg_sp_offset = successor_path.state.arch.sp_offset
                    reg_sp_expr = successor_path.state.reg_expr(reg_sp_offset).model

                    reg_sp_si = reg_sp_expr.items()[0][1]
                    reg_sp_val = reg_sp_si.min
                    # TODO: Finish it!

            # This is where merging happens
            if new_tpl in self._nodes:
                l.debug("Analyzing %s for the %dth time", self._nodes[new_tpl], traced_times)

                # Extract two states
                new_state = successor_path.state
                old_state = self._normal_states[new_tpl]

                # The widening flag
                widening_occurred = False

                if successor_ip in set([dst.addr for (src, dst) in self._widen_points]):
                    # We reached a merge point

                    if traced_times >= MAX_ANALYSIS_TIMES_WITHOUT_MERGING:

                        if should_narrow:
                            # We want to narrow the state
                            widened_state = self._widened_states[new_tpl]
                            merged_state, narrowing_occurred = self._narrow_states(old_state, new_state, widened_state)
                            merging_occurred = narrowing_occurred

                        else:
                            # We want to widen the state
                            merged_state, widening_occurred = self._widen_states(old_state, new_state)

                            merging_occurred = widening_occurred

                    else:
                        # We want to merge them
                        merged_state, merging_occurred = self._merge_states(old_state, new_state)

                else:
                    # Not a merge point
                    # Always merge the state with existing states
                    merged_state, merging_occurred = self._merge_states(old_state, new_state)

                if widening_occurred:
                    self._widened_states[new_tpl] = merged_state

                if merging_occurred:
                    successor_path.state = merged_state
                    new_exit_wrapper = EntryWrapper(
                        successor_path,
                        self._context_sensitivity_level,
                        call_stack=new_call_stack,
                        bbl_stack=new_bbl_stack,
                        widening_occurred=widening_occurred
                    )
                    remaining_entries.append(new_exit_wrapper)
                    _dbg_exit_status[suc_state] = "Appended"
                    l.debug("Merging occured for %s!", self._nodes[new_tpl])

                else:
                    _dbg_exit_status[suc_state] = "Reached fixpoint"

                """
                if merging_occured:
                   # Perform an intersection between the guarding state and the merged_state
                print merged_state.guarding_irsb

                if merged_state.guarding_irsb:
                    # TODO: This is hackish...
                    guarding_irsb, guarding_stmt_indices = merged_state.guarding_irsb
                    # Re-execute each statement
                    guarding_state = merged_state
                    guarding_state.temps = { }
                    for idx in guarding_stmt_indices:
                        stmt = guarding_irsb.statements[idx]
                        stmt.state = merged_state
                        stmt._process(guarding_irsb.irsb.statements[idx], idx, guarding_irsb)
                        guarding_state = stmt.state

                    if simuvex.s_options.WIDEN_ON_MERGE in merged_state.options:
                        merged_state.add_constraints(guarding_state.temps[max(guarding_state.temps.keys())] != 0)
                """

                # if simuvex.s_options.WIDEN_ON_MERGE in merged_state.options:
                #    merged_state.options.remove(simuvex.s_options.WIDEN_ON_MERGE)

            else:
                if not should_narrow:
                    new_exit_wrapper = EntryWrapper(successor_path,
                                                    self._context_sensitivity_level,
                                                    call_stack=new_call_stack,
                                                    bbl_stack=new_bbl_stack)
                    remaining_entries.append(new_exit_wrapper)
                    _dbg_exit_status[suc_state] = "Appended"

        if not is_call_jump or jumpkind != "Ijk_Ret":
            exit_targets[call_stack_suffix + (addr,)].append((new_tpl, jumpkind))
        else:
            # This is the fake return!
            exit_targets[call_stack_suffix + (addr,)].append((new_tpl, "Ijk_FakeRet"))

    def _widen_states(self, old_state, new_state):
        """
        Perform widen operation on the given states, and return a new one.

        :param old_state:
        :param new_state:
        :return: The widened state, and whether widening has occurred
        """

        widened_state, widening_occurred = old_state.widen(new_state)

        return widened_state, widening_occurred

    def _narrow_states(self, old_state, new_state, previously_widened_state):
        """
        Try to narrow the state!

        :param old_state:
        :param new_state:
        :param previously_widened_state:
        :return: The narrowed state, and whether a narrowing has occurred
        """

        se = new_state.se
        s = previously_widened_state.copy()

        narrowing_occurred = False

        # Check each fresh variable in new_state, and update them in previously_widened_state if needed.
        # Registers
        fresh_register_vars = new_state.fresh_variables.register_variables

        for var in fresh_register_vars:
            offset, size = var.reg, var.size

            if not se.is_true(new_state.reg_expr(offset) == s.reg_expr(offset)):
                s.store_reg(offset, new_state.reg_expr(offset))

                narrowing_occurred = True

        fresh_memory_vars = new_state.fresh_variables.memory_variables

        for var in fresh_memory_vars:
            region, offset, _, _ = var.addr
            size = var.size

            if region not in s.memory.regions:
                continue
                
            val = new_state.memory.regions[region].memory.load(offset, size)[0]
            if not se.is_true(val == s.memory.regions[region].memory.load(offset, size)[0]):
                s.memory.regions[region].memory.store(offset, val)

                narrowing_occurred = True

        return s, narrowing_occurred

    def _merge_states(self, old_state, new_state):
        """
        Merge two given states, and return a new one.

        :param old_state:
        :param new_state:
        :return: The merged state, and whether a merging has occurred
        """

        merged_state, _, merging_occurred = old_state.merge(new_state)

        return merged_state, merging_occurred

    def _create_stack_region(self, successor_state, successor_ip):
        reg_sp_offset = successor_state.arch.sp_offset
        reg_sp_expr = successor_state.reg_expr(reg_sp_offset).model

        reg_sp_si = reg_sp_expr.items()[0][1]
        reg_sp_val = reg_sp_si.min - successor_state.arch.bits / 8  # TODO: Is it OK?
        new_stack_region_id = successor_state.memory.stack_id(successor_ip)
        successor_state.memory.set_stack_address_mapping(reg_sp_val,
                                                        new_stack_region_id,
                                                        successor_ip)

        return reg_sp_si

    def _create_callstack(self, entry_wrapper, successor_ip, jumpkind, is_call_jump, fakeret_successor):
        addr = entry_wrapper.path.addr

        if jumpkind == "Ijk_Call":
            if len(entry_wrapper.call_stack) <= self._interfunction_level:
                new_call_stack = entry_wrapper.call_stack_copy()
                # Notice that in ARM, there are some freaking instructions
                # like
                # BLEQ <address>
                # It should give us three exits: Ijk_Call, Ijk_Boring, and
                # Ijk_Ret. The last exit is simulated.
                # Notice: We assume the last exit is the simulated one
                if fakeret_successor is None:
                    retn_target_addr = None
                else:
                    retn_target_addr = fakeret_successor.se.exactly_n_int(fakeret_successor.ip, 1)[0]

                # Create call stack
                new_call_stack.call(addr, successor_ip,
                                    retn_target=retn_target_addr)
            else:
                return None

        elif jumpkind == "Ijk_Ret" and not is_call_jump:
            new_call_stack = entry_wrapper.call_stack_copy()
            new_call_stack.ret(successor_ip)

        else:
            # Normal control flow transition
            new_call_stack = entry_wrapper.call_stack

        return new_call_stack

    def _create_bblstack(self, entry_wrapper, jumpkind, successor_ip, is_call_jump, call_stack_suffix,
                         new_call_stack_suffix, current_function_address):
        if jumpkind == "Ijk_Call":
            new_bbl_stack = entry_wrapper.bbl_stack_copy()
            new_bbl_stack.call(new_call_stack_suffix, current_function_address)
            new_bbl_stack.push(new_call_stack_suffix, current_function_address, successor_ip)
        elif jumpkind == "Ijk_Ret" and not is_call_jump:
            new_bbl_stack = entry_wrapper.bbl_stack_copy()
            new_bbl_stack.ret(call_stack_suffix, current_function_address)
        else:
            new_bbl_stack = entry_wrapper.bbl_stack_copy()
            new_bbl_stack.push(new_call_stack_suffix, current_function_address, successor_ip)

        return new_bbl_stack

    def _save_state(self, entry_wrapper, successor_ip, successor_state):
        addr = entry_wrapper.path.addr

        new_call_stack_suffix = entry_wrapper.call_stack.stack_suffix(self._context_sensitivity_level)
        function_key = new_call_stack_suffix + (addr, )
        function_addr = successor_ip
        l.debug('Saving out the state for function 0x%x with function_key %s',
                function_addr,
                CallStack.stack_suffix_to_string(function_key))
        if function_addr in self._function_initial_states and \
                        function_key in self._function_initial_states[function_addr]:
            existing_state = self._function_initial_states[function_addr][function_key]
            merged_state, _, _ = existing_state.merge(successor_state)
            self._function_initial_states[function_addr][function_key] = merged_state
        else:
            self._function_initial_states[function_addr][function_key] = successor_state

    def _uninitialized_access_handler(self, mem_id, addr, length, expr, bbl_addr, stmt_idx):
        self._uninitialized_access[expr.model.name] = (bbl_addr, stmt_idx, mem_id, addr, length)

    def _find_innermost_uninitialized_expr(self, expr):
        result = [ ]

        if not expr.args:
            if hasattr(expr.model, 'uninitialized') and expr.model.uninitialized:
                result.append(expr)

        else:
            tmp_result = [ ]

            for a in expr.args:
                if isinstance(a, claripy.A):
                    r = self._find_innermost_uninitialized_expr(a)

                    if r:
                        tmp_result.extend(r)

            if tmp_result:
                result = tmp_result

            elif not tmp_result and \
                    hasattr(expr.model, 'uninitialized') and \
                    expr.model.uninitialized:
                result.append(expr)

        return result

    def _add_expression_to_initialize(self, expr, expr_type):

        expr = self._find_innermost_uninitialized_expr(expr)

        for ex in expr:
            name = ex.model.name

            if name in self._uninitialized_access:
                bbl_addr, stmt_idx, mem_id, addr, length = self._uninitialized_access[name]
                # FIXME: Here we are reusing expr_type for all uninitialized variables.
                # FIXME: However, it will cause problems for the following case:
                # FIXME: addr(uninit) = addr_a(uninit) + offset_b(uninit)
                # FIXME: In this case, both addr_a and offset_b will be treated as addresses
                # FIXME: We should consider a fix for that
                self._state_initialization_map[bbl_addr].append((mem_id, addr, length, expr_type, stmt_idx))
            else:
                raise Exception('TODO: Please report it to Fish')

    def _initialize_state(self, state):

        se = state.se
        bbl_addr = se.exactly_int(state.ip)

        if bbl_addr in self._state_initialization_map:
            for data in self._state_initialization_map[bbl_addr]:
                mem_id, addr, length, expr_type, stmt_idx = data

                # Initialize it
                if expr_type == 'addr':
                    # Give it an address
                    value = se.VS(region='_init_%x_%d' % (bbl_addr, stmt_idx), bits=state.arch.bits, val=0)

                    # Write to the state
                    if mem_id == 'reg':
                        state.store_reg(addr, value)
                    else:
                        # TODO: This is completely untested!
                        __import__('ipdb').set_trace()
                        target_addr = se.VS(region=mem_id, bits=state.arch.bits, val=addr)

                        state.store_mem(target_addr, length, value)

                else:
                    raise NotImplementedError('Please report to Fish.')

    def _get_block_addr(self, b): #pylint:disable=R0201
        if isinstance(b, simuvex.SimIRSB):
            return b.first_imark.addr
        elif isinstance(b, simuvex.SimProcedure):
            return b.addr
        else:
            raise Exception("Unsupported block type %s" % type(b))
