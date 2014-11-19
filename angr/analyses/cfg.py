from collections import defaultdict

import networkx

import logging
import pyvex
import simuvex
import claripy
import angr
from .exit_wrapper import SimExitWrapper
from .cfg_base import CFGBase
from ..analysis import Analysis

l = logging.getLogger(name="angr.cfg")

# The maximum tracing times of a basic block before we widen the results
MAX_TRACING_TIMES = 1

class CFG(Analysis, CFGBase):
    '''
    This class represents a control-flow graph.
    '''
    def __init__(self, context_sensitivity_level=2, start=None, avoid_runs=None, treat_constants_as_exits=False):
        '''

        :param project: The project object.
        :param context_sensitivity_level: The level of context-sensitivity of this CFG.
                                        It ranges from 1 to infinity.
        :return:
        '''
        CFGBase.__init__(self, self._p, context_sensitivity_level)

        self._symbolic_function_initial_state = {}

        self._unresolvable_runs = set()
        self._start = start
        self._avoid_runs = avoid_runs
        self._treat_constants_as_exits = treat_constants_as_exits

        self.construct()

    def copy(self):
        # Create a new instance of CFG without calling the __init__ method of CFG class
        new_cfg = Analysis.copy(self)

        # Intelligently (or stupidly... you tell me) fill it up
        new_cfg._graph = networkx.DiGraph(self._graph)
        new_cfg._bbl_dict = self._bbl_dict.copy()
        new_cfg._edge_map = self._edge_map.copy()
        new_cfg._loop_back_edges_set = self._loop_back_edges_set.copy()
        new_cfg._loop_back_edges = self._loop_back_edges[::]
        new_cfg._overlapped_loop_headers = self._overlapped_loop_headers[::]
        new_cfg._function_manager = self._function_manager
        new_cfg._thumb_addrs = self._thumb_addrs.copy()

        return new_cfg

    @property
    def unresolvables(self):
        return self._unresolvable_runs

    def _push_unresolvable_run(self, simrun_address):
        self._unresolvable_runs.add(simrun_address)

    # Construct the CFG from an angr. binary object
    def construct(self):
        '''
        Construct the CFG.

        Fastpath means the CFG generation will work in an IDA-like way, in
        which it will not try to execute every single statement in the emulator,
        but will just do the decoding job. This is much faster than the old
        way.
        '''

        binary = self._p.main_binary
        avoid_runs = [ ] if self._avoid_runs is None else self._avoid_runs

        # Create the function manager
        self._function_manager = angr.FunctionManager(self._project, binary)

        self._initialize_cfg()

        # Traverse all the IRSBs, and put them to a dict
        # It's actually a multi-dict, as each SIRSB might have different states
        # on different call predicates
        self._bbl_dict = {}
        if self._start is None:
            entry_point = binary.entry_point
        else:
            entry_point = self._start
        l.debug("We start analysis from 0x%x", entry_point)

        # Crawl the binary, create CFG and fill all the refs inside project!
        loaded_state = self._project.initial_state(mode="fastpath")

        # THIS IS A HACK FOR MIPS
        if self._start is not None and isinstance(self._project.arch, simuvex.SimMIPS32):
            # We assume this is a function start
            self._symbolic_function_initial_state[entry_point] = {
                                                            'current_function': loaded_state.se.BVV(self._start, 32)}

        loaded_state = self._project.arch.prepare_state(loaded_state, self._symbolic_function_initial_state)

        entry_point_exit = self._project.exit_to(addr=entry_point,
                                           state=loaded_state.copy(),
                                           jumpkind="Ijk_boring")
        exit_wrapper = SimExitWrapper(entry_point_exit, self._context_sensitivity_level)
        remaining_exits = [exit_wrapper]
        traced_sim_blocks = defaultdict(lambda: defaultdict(int)) # Counting how many times a basic block is traced into
        traced_sim_blocks[exit_wrapper.call_stack_suffix()][entry_point_exit.concretize()] = 1

        self._loop_back_edges_set = set()
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
        pending_exits = {}
        # A dict to log edges and the jumpkind between each basic block
        self._edge_map = defaultdict(list)
        exit_targets = self._edge_map
        # A dict to record all blocks that returns to a specific address
        retn_target_sources = defaultdict(list)
        # A dict that collects essential parameters to properly reconstruct initial state for a SimRun
        simrun_info_collection = {}

        pending_possible_targets = set()

        # Iteratively analyze every exit
        while len(remaining_exits) > 0:
            current_exit_wrapper = remaining_exits.pop()
            # Process the popped exit
            self._handle_exit(current_exit_wrapper, remaining_exits,
                              exit_targets, pending_exits,
                              traced_sim_blocks, retn_target_sources,
                              avoid_runs, simrun_info_collection,
                              pending_possible_targets)

            while len(remaining_exits) == 0 and len(pending_exits) > 0:
                # We don't have any exits remaining. Let's pop a fake exit to
                # process
                pending_exit_tuple = pending_exits.keys()[0]
                pending_exit_state, pending_exit_call_stack, pending_exit_bbl_stack = \
                    pending_exits.pop(pending_exit_tuple)
                pending_exit_addr = pending_exit_tuple[len(pending_exit_tuple) - 1]
                # Let's check whether this address has been traced before.
                targets = filter(lambda r: r == pending_exit_tuple,
                                 exit_targets)
                if len(targets) > 0:
                    # That block has been traced before. Let's forget about it
                    l.debug("Target 0x%08x has been traced before." + \
                            "Trying the next one...", pending_exit_addr)
                    continue
                new_exit = self._project.exit_to(addr=pending_exit_addr,
                    state=pending_exit_state,
                    jumpkind="Ijk_Ret")
                new_exit_wrapper = SimExitWrapper(new_exit,
                                                  self._context_sensitivity_level,
                                                  call_stack=pending_exit_call_stack,
                                                  bbl_stack=pending_exit_bbl_stack)
                remaining_exits.append(new_exit_wrapper)
                l.debug("Tracing a missing retn exit 0x%08x, %s", pending_exit_addr, "->".join([hex(i) for i in pending_exit_tuple if i is not None]))
                break

        # Create CFG
        self._graph = self._create_graph(return_target_sources=retn_target_sources)

        # Remove those edges that will never be taken!
        self._remove_non_return_edges()

        # Perform function calling convention analysis
        self._analyze_calling_conventions()

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
                if ex not in self._bbl_dict:
                    pt = simuvex.procedures.SimProcedures["stubs"]["PathTerminator"](self._project.initial_state(), addr=ex[-1])
                    self._bbl_dict[ex] = pt

                    s = "(["
                    for addr in ex[:-1]:
                        s += "0x%x" % addr if addr is not None else "None" + ", "
                    s += "] %s)" % ("0x%x" % ex[-1] if ex[-1] is not None else None)
                    l.warning("Key %s does not exist. Create a PathTerminator instead.", s)

                target_bbl = self._bbl_dict[ex]
                cfg.add_edge(basic_block, target_bbl, jumpkind=jumpkind)

                # Add edges for possibly missing returns
                if basic_block.addr in return_target_sources:
                    for src_irsb_key in \
                            return_target_sources[basic_block.addr]:
                        cfg.add_edge(self._bbl_dict[src_irsb_key],
                                           basic_block, jumpkind="Ijk_Ret")

        return cfg

    def _symbolically_back_traverse(self, current_simrun, simrun_info_collection):

        class register_protector(object):
            def __init__(self, reg_offset, info_collection):
                self._reg_offset = reg_offset
                self._info_collection = info_collection

            def write_persistent_register(self, state):
                if state.inspect.address is None:
                    l.error('state.inspect.address is None. It will be fixed by Yan later.')
                    return

                if state.reg_expr(self._reg_offset).symbolic:
                    current_run = state.inspect.address
                    if current_run in self._info_collection and \
                            not state.se.symbolic(self._info_collection[current_run][self._reg_offset]):
                        l.debug("Overwriting %s with %s", state.reg_expr(self._reg_offset), self._info_collection[current_run][self._reg_offset])
                        state.store_reg(
                            self._reg_offset,
                            self._info_collection[current_run][self._reg_offset]
                        )

        l.debug("Start back traversal from %s", current_simrun)

        # Create a partial CFG first
        temp_cfg = self._create_graph()
        # Reverse it
        temp_cfg.reverse(copy=False)

        path_length = 0
        concrete_exits = []
        if current_simrun not in temp_cfg.nodes():
            # TODO: Figure out why this is happening
            return concrete_exits

        keep_running = True
        while len(concrete_exits) == 0 and path_length < 5 and keep_running:
            path_length += 1
            queue = [current_simrun]
            avoid = set()
            for i in xrange(path_length):
                new_queue = []
                for b in queue:
                    successors = temp_cfg.successors(b)
                    for suc in successors:
                        jk = temp_cfg.get_edge_data(b, suc)['jumpkind']
                        if jk != 'Ijk_Ret':
                            # We don't want to trace into libraries
                            predecessors = temp_cfg.predecessors(suc)
                            avoid |= set([p.addr for p in predecessors if p is not b])
                            new_queue.append(suc)
                queue = new_queue

            for b in queue:
                # Start symbolic exploration from each block
                state = self._project.initial_state(mode='symbolic',
                                                    add_options={simuvex.o.DO_RET_EMULATION} | simuvex.o.resilience_options)
                # Set initial values of persistent regu
                if b.addr in simrun_info_collection:
                    for reg in (state.arch.persistent_regs):
                        state.store_reg(reg, simrun_info_collection[b.addr][reg])
                for reg in (state.arch.persistent_regs):
                    reg_protector = register_protector(reg, simrun_info_collection)
                    state.inspect.add_breakpoint('reg_write',
                                                 simuvex.BP(
                                                     simuvex.BP_AFTER,
                                                     reg_write_offset=state.arch.registers[reg][0],
                                                     action=reg_protector.write_persistent_register
                                                 )
                    )
                result = angr.surveyors.Explorer(self._project,
                                                 start=self._project.exit_to(b.addr, state=state),
                                                 find=(current_simrun.addr, ),
                                                 avoid=avoid,
                                                 max_repeats=10,
                                                 max_depth=path_length).run()
                if result.found:
                    last_run = result.found[0].last_run  # TODO: Access every found path
                    for ex in last_run.exits():
                        if not ex.target.symbolic:
                            concrete_exits.append(ex)
                            keep_running = False
                        else:
                            targets = state.se.any_n_int(ex.target, 512)
                            if len(targets) < 512:
                                keep_running = False
                                for t in targets:
                                    new_ex = ex.copy()
                                    new_ex.target = state.se.BVV(t, ex.target.size())
                                    concrete_exits.append(new_ex)

                if keep_running:
                    l.debug('Step back for one more run...')

        return concrete_exits

    def _get_symbolic_function_initial_state(self, function_addr, fastpath_mode_state=None):
        '''
        Symbolically execute the first basic block of the specified function,
        then returns it. We prepares the state using the already existing
        state in fastpath mode (if avaiable).
        :param function_addr: The function address
        :return: A symbolic state if succeeded, None otherwise
        '''
        if function_addr is None:
            return None

        if function_addr in self._symbolic_function_initial_state:
            return self._symbolic_function_initial_state[function_addr]

        fastpath_state = None
        if fastpath_mode_state is not None:
            fastpath_state = fastpath_mode_state
        else:
            fastpath_irsb = self.get_any_irsb(function_addr)
            if fastpath_irsb is not None:
                fastpath_state = fastpath_irsb.initial_state

        symbolic_initial_state = self._project.initial_state(mode='symbolic')
        if fastpath_state is not None:
            symbolic_initial_state = self._project.arch.prepare_call_state(fastpath_state,
                                                    initial_state=symbolic_initial_state)

        # Create a temporary block
        tmp_block = self._project.block(function_addr)
        num_instr = tmp_block.instructions() - 1

        simexit = self._project.exit_to(function_addr, state=symbolic_initial_state)
        try:
            simrun = self._project.sim_run(simexit, num_inst=num_instr)
        except simuvex.SimError:
            return None

        # We execute all but the last instruction in this basic block, so we have a cleaner
        # state
        # Start execution!
        exits = simrun.flat_exits()

        if exits:
            final_st = None
            for ex in exits:
                if ex.state.satisfiable():
                    final_st = ex.state
                    break
        else:
            final_st = None

        self._symbolic_function_initial_state[function_addr] = final_st

        return final_st

    def _get_simrun(self, addr, current_exit, current_function_addr=None):
        error_occured = False
        state = current_exit.state
        saved_state = current_exit.state  # We don't have to make a copy here
        try:
            if self._project.is_sim_procedure(addr) and \
                    not self._project.sim_procedures[addr][0].ADDS_EXITS and \
                    not self._project.sim_procedures[addr][0].NO_RET:
                # DON'T CREATE USELESS SIMPROCEDURES
                sim_run = simuvex.procedures.SimProcedures["stubs"]["ReturnUnconstrained"](
                    state, addr=addr, name="%s" % self._project.sim_procedures[addr][0])
            else:
                sim_run = self._project.sim_run(current_exit)
        except simuvex.s_irsb.SimFastPathError as ex:
            # Got a SimFastPathError. We wanna switch to symbolic mode for current IRSB.
            l.debug('Switch to symbolic mode for address 0x%x', addr)
            # Make a copy of the current 'fastpath' state
            new_state = None
            if addr != current_function_addr:
                new_state = self._get_symbolic_function_initial_state(current_function_addr)

            if new_state is None:
                new_state = current_exit.state.copy()
                new_state.set_mode('symbolic')
            new_state.options.add(simuvex.o.DO_RET_EMULATION)
            # Swap them
            saved_state, current_exit.state = current_exit.state, new_state
            sim_run, error_occured, _ = self._get_simrun(addr, current_exit)
        except simuvex.s_irsb.SimIRSBError as ex:
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

        return sim_run, error_occured, saved_state

    def _is_address_in_binary(self, address):
        for seg in self._project.main_binary.segments:
            if address >= seg.vaddr and address < seg.vaddr + seg.size:
                return True
        return False

    def _search_for_possible_exits(self, simrun, pending_possible_targets=None):
        '''
        Scan for constants that might be used as exit targets later, and add
        them into pending_exits
        '''

        exits = {}
        if isinstance(simrun, simuvex.SimIRSB):
            for stmt in simrun.irsb.statements():
                if type(stmt) == pyvex.IRStmt.Put and \
                                stmt.offset != self._project.arch.ip_offset:
                    data = stmt.data
                    if type(data) == pyvex.IRExpr.Const:
                        # TODO: Check if there is a proper way to tell whether this const falls in the range of code segments
                        # Now let's live with this big hack...
                        const = data.con.value
                        if self._is_address_in_binary(const):
                            if pending_possible_targets is not None and const in pending_possible_targets:
                                continue
                            pending_possible_targets.add(const)

                            target = const
                            tpl = (None, None, target)
                            #st = self._project.arch.prepare_call_state(self._project.initial_state(mode='fastpath'),
                            #                                           initial_state=saved_state)
                            st = self._project.initial_state(mode='fastpath')
                            exits[tpl] = (st, None, None)

            l.info('Got %d possible exits from %s', len(exits), simrun)

        return exits

    def _create_new_call_stack(self, addr, all_exits, current_exit_wrapper, exit_target, exit_jumpkind):
        if exit_jumpkind == "Ijk_Call":
            new_call_stack = current_exit_wrapper.call_stack_copy()
            # Notice that in ARM, there are some freaking instructions
            # like
            # BLEQ <address>
            # It should give us three exits: Ijk_Call, Ijk_Boring, and
            # Ijk_Ret. The last exit is simulated.
            # Notice: We assume the last exit is the simulated one
            if len(all_exits) > 1 and all_exits[-1].jumpkind == "Ijk_Ret":
                retn_target_addr = all_exits[-1].concretize()
                new_call_stack.call(addr, exit_target,
                                    retn_target=retn_target_addr)
            else:
                # We don't have a fake return exit available, which means
                # this call doesn't return.
                new_call_stack.clear()
                new_call_stack.call(addr, exit_target, retn_target=None)
                retn_target_addr = None
            self._function_manager.call_to(
                function_addr=current_exit_wrapper.current_func_addr(),
                from_addr=addr, to_addr=exit_target,
                retn_addr=retn_target_addr)
        elif exit_jumpkind == "Ijk_Ret":
            # Normal return
            new_call_stack = current_exit_wrapper.call_stack_copy()
            new_call_stack.ret(exit_target)
            self._function_manager.return_from(
                function_addr=current_exit_wrapper.current_func_addr(),
                from_addr=addr, to_addr=exit_target)
        elif exit_jumpkind == 'Ijk_FakeRet':
            # The fake return...
            new_call_stack = current_exit_wrapper.call_stack()
            self._function_manager.return_from_call(
                function_addr=current_exit_wrapper.current_func_addr(),
                first_block_addr=addr,
                to_addr=exit_target)
        else:
            # Normal control flow transition
            new_call_stack = current_exit_wrapper.call_stack()
            self._function_manager.transit_to(
                function_addr=current_exit_wrapper.current_func_addr(),
                from_addr=addr,
                to_addr=exit_target)

        return new_call_stack

    def _handle_exit(self, current_exit_wrapper, remaining_exits, exit_targets,
                     pending_exits, traced_sim_blocks, retn_target_sources,
                     avoid_runs, simrun_info_collection, pending_possible_targets):
        '''
        Handles a SimExit instance.

        In static mode, we create a unique stack region for each function, and
        normalize its stack pointer to the default stack offset.
        '''
        current_exit = current_exit_wrapper.sim_exit()
        call_stack_suffix = current_exit_wrapper.call_stack_suffix()
        addr = current_exit.concretize()
        current_function_addr = current_exit_wrapper.current_func_addr()

        # Get a SimRun out of current SimExit
        simrun, error_occured, saved_state = self._get_simrun(addr, current_exit,
            current_function_addr=current_function_addr)
        if simrun is None:
            return

        if self._treat_constants_as_exits:
            possible_exits = self._search_for_possible_exits(simrun, pending_possible_targets=pending_possible_targets)
            for k, v in possible_exits.items():
                if k not in pending_exits:
                    pending_exits[k] = v

        # Generate key for this SimRun
        simrun_key = call_stack_suffix + (addr,)
        # Adding the new sim_run to our dict
        self._bbl_dict[simrun_key] = simrun

        simrun_info = self._project.arch.gather_info_from_state(simrun.initial_state)
        simrun_info_collection[addr] = simrun_info

        # Get exits
        all_exits = simrun.exits() if addr not in avoid_runs else []

        if not error_occured:
            has_call_exit = any([exit_.jumpkind == 'Ijk_Call' for exit_ in all_exits])
            if has_call_exit:
                concrete_exits = [exit_ for exit_ in all_exits if exit_.jumpkind != 'Ijk_Ret' and not exit_.state.se.symbolic(exit_.target)]
            else:
                concrete_exits = [exit_ for exit_ in all_exits if not exit_.state.se.symbolic(exit_.target)]
            symbolic_exits = [exit_ for exit_ in all_exits if exit_.state.se.symbolic(exit_.target)]

            resolved = False
            if len(symbolic_exits) > 0:
                for s_exit in symbolic_exits:
                    if simuvex.o.SYMBOLIC in s_exit.state.options:
                        targets = s_exit.state.se.any_n_int(s_exit.target, 32)
                        if len(targets) < 32:
                            all_exits = []
                            resolved = True
                            for t in targets:
                                new_ex = s_exit.copy()
                                new_ex.target = s_exit.state.se.BVV(t, s_exit.target.size())
                                all_exits.append(new_ex)
                        else:
                            break

            if not resolved and len(concrete_exits) == 0:
                l.debug("We only got some symbolic exits. Try traversal backwards " + \
                        "in symbolic mode.")

                if isinstance(simrun, simuvex.SimProcedure) and \
                        simrun.ADDS_EXITS:
                    # Skip those SimProcedures that don't create new SimExits
                    l.debug('We got a SimProcedure %s in fastpath mode that creates new exits.', simrun)
                    all_exits = self._symbolically_back_traverse(simrun, simrun_info_collection)
                    l.debug("Got %d concrete exits in symbolic mode.", len(all_exits))
                elif isinstance(simrun, simuvex.SimIRSB) and \
                        any([ex.jumpkind != 'Ijk_Ret' for ex in all_exits]):
                    # We cannot properly handle Return as that requires us start execution from the caller...
                    l.debug('We got a SimIRSB %s', simrun)
                    all_exits = self._symbolically_back_traverse(simrun, simrun_info_collection)
                    l.debug('Got %d concrete exits in symbolic mode', len(all_exits))
                else:
                    l.debug('All exits are returns (Ijk_Ret). It will be handled by pending exits.')

        if len(all_exits) == 0:
            # We cannot resolve the exit of this SimIRSB
            # Log it
            self._push_unresolvable_run(addr)

        if isinstance(simrun, simuvex.SimIRSB) and \
                self._project.is_thumb_state(current_exit):
            self._thumb_addrs.update(simrun.imark_addrs())

        if len(all_exits) == 0:
            if isinstance(simrun,
                simuvex.procedures.SimProcedures["stubs"]["PathTerminator"]):
                # If there is no valid exit in this branch and it's not
                # intentional (e.g. caused by a SimProcedure that does not
                # do_return) , we should make it
                # return to its callsite. However, we don't want to use its
                # state as it might be corrupted. Just create a link in the
                # exit_targets map.
                retn_target = current_exit_wrapper.call_stack().get_ret_target()
                if retn_target is not None:
                    new_call_stack = current_exit_wrapper.call_stack_copy()
                    exit_target_tpl = new_call_stack.stack_suffix(self.context_sensitivity_level) + (retn_target,)
                    exit_targets[simrun_key].append((exit_target_tpl, 'Ijk_Ret'))
            else:
                # This is intentional. We shall remove all the fake
                # returns generated before along this path.

                # Build the tuples that we want to remove from
                # the dict pending_exits
                tpls_to_remove = []
                call_stack_copy = current_exit_wrapper.call_stack_copy()
                while call_stack_copy.get_ret_target() is not None:
                    ret_target = call_stack_copy.get_ret_target()
                    # Remove the current call stack frame
                    call_stack_copy.ret(ret_target)
                    call_stack_suffix = call_stack_copy.stack_suffix(self.context_sensitivity_level)

                    # Type 1: a valid call stack suffix with the return target. They are simulated returns
                    tpl = call_stack_suffix + (ret_target,)
                    tpls_to_remove.append(tpl)
                    # Type 2: no call stack suffix, but only the return target. These are 'possible' exits, like
                    # those exits generated from constants
                    tpl = (None, None, ret_target)
                    tpls_to_remove.append(tpl)

                # Remove those tuples from the dict
                for tpl in tpls_to_remove:
                    if tpl in pending_exits:
                        del pending_exits[tpl]
                        l.debug("Removed (%s) from pending_exits dict.",
                                ",".join([hex(i) if i is not None else 'None' for i in tpl]))

        # If there is a call exit, we shouldn't put the default exit (which
        # is artificial) into the CFG. The exits will be Ijk_Call and
        # Ijk_Ret, and Ijk_Call always goes first
        is_call_exit = False
        last_call_exit_target = None

        # For debugging purposes!
        all_exit_status = {}

        for exit_ in all_exits:
            all_exit_status[exit_] = ""

            new_initial_state = exit_.state.copy()
            exit_jumpkind = exit_.jumpkind

            if exit_jumpkind in {'Ijk_EmWarn', 'Ijk_NoDecode', 'Ijk_MapFail',
                                'Ijk_InvalICache', 'Ijk_NoRedir', 'Ijk_SigTRAP',
                                'Ijk_SigSEGV', 'Ijk_ClientReq'}:
                # Ignore SimExits that are of these jumpkinds
                all_exit_status[exit_] = "Skipped"
                continue

            # Jumpkind post process
            if exit_jumpkind == "Ijk_Call":
                is_call_exit = True
            elif exit_jumpkind == "Ijk_Ret" and is_call_exit:
                exit_jumpkind = "Ijk_FakeRet"

            try:
                exit_target = None
                exit_target = exit_.concretize()
            except simuvex.SimValueError:
                # It cannot be concretized currently. Maybe we could handle
                # it later, maybe it just cannot be concretized
                if exit_jumpkind == "Ijk_Ret":
                    exit_target = current_exit_wrapper.call_stack().get_ret_target()
                else:
                    continue

            if exit_target is None:
                continue

            # Remove pending targets - type 2
            tpl = (None, None, exit_target)
            if tpl in pending_exits:
                l.debug("Removing pending exits (type 2) to %s", hex(exit_target))
                del pending_exits[tpl]

            if exit_jumpkind == "Ijk_Call":
                last_call_exit_target = exit_target
            elif exit_jumpkind == "Ijk_FakeRet":
                if exit_target == last_call_exit_target:
                    l.debug("Skipping a fake return exit that has the same target with its call exit.")
                    all_exit_status[exit_] = "Skipped"
                    continue

            # Create the new call stack of target block
            new_call_stack = self._create_new_call_stack(addr, all_exits,
                                                         current_exit_wrapper,
                                                         exit_target, exit_jumpkind)
            # Create the callstack suffix
            new_call_stack_suffix = new_call_stack.stack_suffix(self._context_sensitivity_level)
            # Tuple that will be used to index this exit
            new_tpl = new_call_stack_suffix + (exit_target,)

            if isinstance(simrun, simuvex.SimIRSB):
                self._detect_loop(simrun, new_tpl,
                                  exit_targets, call_stack_suffix,
                                  simrun_key, exit_target,
                                  exit_jumpkind, current_exit_wrapper)

            # Generate the new BBL stack of target block
            if exit_jumpkind == "Ijk_Call":
                new_bbl_stack = current_exit_wrapper.bbl_stack_copy()
                new_bbl_stack.call(new_call_stack_suffix)
                new_bbl_stack.push(new_call_stack_suffix, exit_target)
            elif exit_jumpkind == "Ijk_Ret" and not is_call_exit:
                new_bbl_stack = current_exit_wrapper.bbl_stack_copy()
                new_bbl_stack.ret(call_stack_suffix)
            else:
                new_bbl_stack = current_exit_wrapper.bbl_stack_copy()
                new_bbl_stack.push(new_call_stack_suffix, exit_target)

            # Generate new exits
            if exit_jumpkind == "Ijk_Ret":
                # This is the real retn exit
                # Remember this retn!
                retn_target_sources[exit_target].append(simrun_key)
                # Check if this retn is inside our pending_exits set
                if new_tpl in pending_exits:
                    del pending_exits[new_tpl]
            if exit_jumpkind == "Ijk_FakeRet":
                # This is the default "fake" retn that generated at each
                # call. Save them first, but don't process them right
                # away
                #st = self._project.arch.prepare_call_state(new_initial_state, initial_state=saved_state)
                st = new_initial_state
                st.mode = 'fastpath'

                pending_exits[new_tpl] = \
                    (st, new_call_stack, new_bbl_stack)
                all_exit_status[exit_] = "Pended"
            elif traced_sim_blocks[new_call_stack_suffix][exit_target] < MAX_TRACING_TIMES:
                traced_sim_blocks[new_call_stack_suffix][exit_target] += 1
                new_exit = self._project.exit_to(addr=exit_target,
                                                state=new_initial_state,
                                                jumpkind=exit_.jumpkind)

                # We might have changed the mode for this basic block
                # before. Make sure it is still running in 'fastpath' mode
                #new_exit.state = self._project.arch.prepare_call_state(new_exit.state, initial_state=saved_state)
                new_exit.state.mode = 'fastpath'

                new_exit_wrapper = SimExitWrapper(new_exit,
                                                  self._context_sensitivity_level,
                                                  call_stack=new_call_stack,
                                                  bbl_stack=new_bbl_stack)
                remaining_exits.append(new_exit_wrapper)
                all_exit_status[exit_] = "Appended"
            elif traced_sim_blocks[new_call_stack_suffix][exit_target] >= MAX_TRACING_TIMES \
                and exit_jumpkind == "Ijk_Ret":
                # This is a corner case for the f****** ARM instruction
                # like
                # BLEQ <address>
                # If we have analyzed the boring exit before returning
                # from that called address, we will lose the link between
                # the last block of the function being called and the
                # basic block it returns to.
                # We cannot reanalyze the basic block as we are not
                # flow-sensitive, but we can still record the connection
                # and make for it afterwards.
                pass

            exit_targets[simrun_key].append((new_tpl, exit_jumpkind))

        # Debugging output
        function_name = self._project.ld.find_symbol_name(simrun.addr)
        module_name = self._project.ld.find_module_name(simrun.addr)

        l.debug("Basic block %s %s", simrun, "->".join([hex(i) for i in call_stack_suffix if i is not None]))
        l.debug("(Function %s of binary %s)" %(function_name, module_name))
        l.debug("|    Has simulated retn: %s", is_call_exit)
        for exit_ in all_exits:
            if exit_.jumpkind == "Ijk_FakeRet":
                exit_type_str = "Simulated Ret"
            else:
                exit_type_str = "-"
            try:
                l.debug("|    target: 0x%08x %s [%s] %s", exit_.concretize(), all_exit_status[exit_], exit_type_str, exit_.jumpkind)
            except simuvex.SimValueError:
                l.debug("|    target cannot be concretized. %s [%s] %s", all_exit_status[exit_], exit_type_str, exit_.jumpkind)
        l.debug("%d exits remaining, %d exits pending.", len(remaining_exits), len(pending_exits))

    def _detect_loop(self, sim_run, new_tpl, exit_targets,
                     simrun_key, new_call_stack_suffix,
                     new_addr, new_jumpkind, current_exit_wrapper):
        # Loop detection
        assert isinstance(sim_run, simuvex.SimIRSB)

        # Loop detection only applies to SimIRSBs
        # The most f****** case: An IRSB branches to itself
        if new_tpl == simrun_key:
            l.debug("%s is branching to itself. That's a loop.", sim_run)
            if (sim_run.addr, sim_run.addr) not in self._loop_back_edges_set:
                self._loop_back_edges_set.add((sim_run.addr, sim_run.addr))
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
                    if (sim_run.addr, next_irsb.addr) not in self._loop_back_edges_set:
                        self._loop_back_edges_set.add((sim_run.addr, next_irsb.addr))
                        self._loop_back_edges.append((sim_run.addr, next_irsb.addr))
                        l.debug("Found a loop, back edge %s --> %s", sim_run, next_irsb)
            else:
                # Case 1, it's not over lapping with any other things
                if (sim_run.addr, next_irsb.addr) not in self._loop_back_edges_set:
                    self._loop_back_edges_set.add((sim_run.addr, next_irsb.addr))
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

    def _analyze_calling_conventions(self):
        '''
        Concretely execute part of the function and watch the changes of sp
        :return:
        '''
        for func in self._function_manager.functions.values():
            graph = func.transition_graph
            startpoint = func.startpoint
            endpoints = func.endpoints

            if not endpoints:
                continue
            if self._project.is_sim_procedure(endpoints[0]):
                # TODO: For now, we assume these SimProcedures doesn't take
                # that many parameters... which is not true, obviously :-(
                continue

            state = self._project.initial_state(mode='concrete', add_options=simuvex.o.resilience_options)
            start_sp = state.reg_expr(state.arch.sp_offset).model.value

            start_run = self._project.sim_run(self._project.exit_to(startpoint,
                                                                 state=state))
            if len(start_run.exits()) == 0:
                continue

            state = start_run.exits()[0].state
            if start_run.exits()[0].jumpkind == 'Ijk_Call':
                # Remove the return address on the stack
                # TODO: Is this the same across platform?
                sp = state.reg_expr(state.arch.sp_offset) + state.arch.bits / 8
                state.store_reg(state.arch.sp_offset, sp)

            end_run = self._project.sim_run(self._project.exit_to(endpoints[0],
                                                                  state=state))
            if len(end_run.exits()) == 0:
                continue

            state = end_run.exits()[0].state
            end_sp_expr = state.reg_expr(state.arch.sp_offset)
            if end_sp_expr.symbolic:
                continue
            end_sp = end_sp_expr.model.value

            difference = end_sp - start_sp

            func.sp_difference = difference

        #for func in self._function_manager.functions.values():
        #    l.info(func)

    def _remove_non_return_edges(self):
        '''
        Remove those return_from_call edges that actually do not return due to
        calling some not-returning functions.
        :return: None
        '''
        function_manager = self._function_manager
        for func in function_manager.functions.values():
            graph = func.transition_graph
            all_return_edges = [(u, v) for (u, v, data) in graph.edges(data=True) if data['type'] == 'return_from_call']
            for return_from_call_edge in all_return_edges:
                callsite_block_addr, return_to_addr = return_from_call_edge
                call_func_addr = func.get_call_target(callsite_block_addr)
                if call_func_addr is None:
                    continue

                call_func = self._function_manager.function(call_func_addr)
                if call_func is None:
                    # Weird...
                    continue

                if not call_func.has_return:
                    # Remove that edge!
                    graph.remove_edge(callsite_block_addr, return_to_addr)
                    # Remove the edge in CFG
                    irsbs = self.get_all_irsbs(callsite_block_addr)
                    for irsb in irsbs:
                        successors = self.get_successors_and_jumpkind(irsb, excluding_fakeret=False)
                        for successor, jumpkind in successors:
                            if jumpkind == 'Ijk_FakeRet' and successor.addr == return_to_addr:
                                self.remove_edge(irsb, successor)

            # Remove all dangling nodes
            wcc = list(networkx.weakly_connected_components(graph))
            for nodes in wcc:
                if func.startpoint not in nodes:
                    graph.remove_nodes_from(nodes)
