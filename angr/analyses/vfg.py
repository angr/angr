from collections import defaultdict
import logging

import networkx
import simuvex
import claripy
import angr

from ..entry_wrapper import EntryWrapper, CallStack
from ..analysis import Analysis, register_analysis
from ..errors import AngrVFGError, AngrVFGRestartAnalysisNotice, AngrError

l = logging.getLogger(name="angr.analyses.vfg")

# The maximum tracing times of a basic block before we widen the results
MAX_ANALYSIS_TIMES_WITHOUT_MERGING = 10
MAX_ANALYSIS_TIMES = 20

class VFGNode(object):
    def __init__(self, addr, key, state=None):
        self.key = key
        self.addr = addr
        self.state = None
        self.widened_state = None
        self.narrowing_times = 0
        self.all_states  = [ ]
        self.events = [ ]
        self.input_variables = [ ]
        self.actions = [ ]
        self.final_states = [ ]

        if state:
            self.all_states.append(state)
            self.state = state

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, o):
        return type(self) == type(o) and \
               self.key == o.key and self.addr == o.addr and \
               self.state == o.state and self.actions == o.actions and \
               self.events == o.events and self.narrowing_times == o.narrowing_times and \
               self.all_states == o.all_states and self.widened_state == o.widened_state and \
               self.input_variables == o.input_variables

    def __repr__(self):
        s = "VFGNode[0x%x] <%s>" % (self.addr, ", ".join([ (("0x%x" % k) if k else "None") for k in self.key ]))
        return s

    def append_state(self, s, is_widened_state=False):
        """
        Appended a new state to this VFGNode.
        :param s: The new state to append
        :param is_widened_state: Whether it is a widened state or not.
        """

        if not is_widened_state:
            self.all_states.append(s)
            self.state = s

        else:
            self.widened_state = s

class VFG(Analysis):
    '''
    This class represents a control-flow graph with static analysis result.
    '''

    def __init__(self, cfg=None,
                 context_sensitivity_level=2,
                 function_start=None,
                 interfunction_level=0,
                 initial_state=None,
                 avoid_runs=None,
                 remove_options=None
                 ):
        '''
        :param project: The project object.
        :param context_sensitivity_level: The level of context-sensitivity of this VFG.
                                        It ranges from 0 to infinity. Default 2.
        :param function_start: The address of the function to analyze. N
        :param interfunction_level: The level of interfunction-ness to be
        :param initial_state: A state to use as the initial one
        :param avoid_runs: A list of runs to avoid
        :param remove_options: State options to remove from the initial state. It only works when `initial_state` is None
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
        self._state_options_to_remove = set() if remove_options is None else remove_options

        # Containers
        self.graph = None # TODO: Maybe we want to remove this line?
        self._nodes = None

        self._normal_states = { } # Last available state for each program point without widening
        self._widened_states = { } # States on which widening has occurred

        # Initial states for start analyzing different functions
        # It maps function key to its states
        self._function_initial_states = defaultdict(dict)

        # All final states are put in this list
        self.final_states = [ ]

        self._uninitialized_access = { }
        self._state_initialization_map = defaultdict(list)

        self._state_ignored_variables = { }

        # Begin VFG construction!
        self._construct(initial_state=initial_state)

    def copy(self):
        new_vfg = VFG(self.project)
        new_vfg._cfg = self._cfg
        new_vfg.graph = networkx.DiGraph(self.graph)
        new_vfg._nodes = self._nodes.copy()
        new_vfg._edge_map = self._edge_map.copy()
        return new_vfg

    def __setstate__(self, s):
        self.__dict__.update(s)
        for n in self._nodes.values():
            n.state.uninitialized_access_handler = self._uninitialized_access_handler
            for state in n.final_states:
                state.uninitialized_access_handler = self._uninitialized_access_handler
        for a in self._function_initial_states.values():
            for state in a.values():
                state.uninitialized_access_handler = self._uninitialized_access_handler

    def __getstate__(self):
        for n in self._nodes.values():
            n.state.uninitialized_access_handler = None
            for state in n.final_states:
                state.uninitialized_access_handler = None
        for a in self._function_initial_states.values():
            for state in a.values():
                state.uninitialized_access_handler = None
        return dict(self.__dict__)

    def _prepare_state(self, function_start, initial_state, function_key):
        # Crawl the binary, create CFG and fill all the refs inside project!
        if initial_state is None:
            if function_start not in self._function_initial_states:
                # We have never saved any initial states for this function
                # Gotta create a fresh state for it
                s = self.project.factory.blank_state(mode="static",
                                              add_options={ simuvex.o.FRESHNESS_ANALYSIS },
                                              remove_options=self._state_options_to_remove,
                )

                if function_start != self.project.loader.main_bin.entry:
                    # This function might have arguments passed on stack, so make
                    # some room for them.
                    # TODO: Decide the number of arguments and their positions
                    #  during CFG analysis
                    sp = s.registers.load('sp')
                    # Set the address mapping
                    sp_val = s.se.any_int(sp) # FIXME: What will happen if we lose track of multiple sp values?
                    s.memory.set_stack_address_mapping(sp_val,
                                                       s.memory.stack_id(function_start) + '_pre',
                                                       0x0)
                    new_sp = sp - 160
                    s.registers.store('sp', new_sp)
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
        initial_sp = s.se.any_int(s.registers.load('sp')) # FIXME: This is bad, as it may lose tracking of multiple sp values
        initial_sp -= s.arch.bits / 8
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

        start = self._start if self._start is not None else self.project.entry

        if not self._cfg:
            # Generate a CFG if no CFG is provided
            l.debug("Generating a CFG starting at 0x%x", start)
            self._cfg = self.project.analyses.CFG(context_sensitivity_level=self._context_sensitivity_level,
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

            # TODO: Remove those lines
            # Initialization
            # self._normal_states = { } # Last available state for each program point without widening
            # self._widened_states = { } # States on which widening has occurred

            self._function_initial_states = defaultdict(dict)

            # Clear the nodes
            self._nodes = { }

            self._events = [ ]

            try:
                self._ai_analyze(initial_state)
            except AngrVFGRestartAnalysisNotice:
                l.info("Restarting analysis.")
                restart_analysis = True

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
            function_start = self.project.loader.main_bin.entry
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
        entry_state = loaded_state.copy()
        entry_state.options.add(simuvex.o.FRESHNESS_ANALYSIS)
        entry_path = self.project.factory.path(entry_state)
        entry_wrapper = EntryWrapper(entry_path, self._context_sensitivity_level)

        # Initialize a worklist
        worklist = [ entry_wrapper ]

        # Counting how many times a basic block has been traced
        tracing_times = defaultdict(int)

        # For each call, we are always getting two exits: an Ijk_Call that
        # stands for the real call exit, and an Ijk_FakeRet which is a simulated exit
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
                              tracing_times, retn_target_sources
                              )

            while len(worklist) == 0 and len(fake_func_return_paths) > 0:
                # We don't have any paths remaining. Let's pop a previously-missing return to
                # process
                fake_exit_tuple = fake_func_return_paths.keys()[0]
                fake_exit_state, fake_exit_call_stack, fake_exit_bbl_stack = \
                    fake_func_return_paths.pop(fake_exit_tuple)
                fake_exit_addr = fake_exit_tuple[len(fake_exit_tuple) - 1]

                # Unlike CFG, we will still trace those blocks that have been traced before. In other words, we don't
                # remove fake returns even if they have been traced - otherwise we cannot come to a fixpoint.

                new_path = self.project.factory.path(fake_exit_state)
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
        if self.graph is None:
            self.graph = new_graph
        else:
            self.graph.add_edges_from(new_graph.edges(data=True))

        # TODO: Determine the last basic block

        for n in self.graph.nodes():
            if self.graph.out_degree(n) == 0:
                # TODO: Fix the issue when n.successors is empty
                if self.graph.successors(n):
                    self.final_states.extend([ i.state for i in self.graph.successors(n) ])
                else:
                    self.final_states.append(n.state)

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

        jumpkind = 'Ijk_Boring'
        if current_path.state.scratch.jumpkind:
            jumpkind = current_path.state.scratch.jumpkind

        try:
            sim_run = self.project.factory.sim_run(current_path.state, jumpkind=jumpkind)
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
            #segment = self.project.loader.main_bin.in_which_segment(addr)
            l.error("AngrError %s when creating SimRun at 0x%x",
                    ex, addr)
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
                     pending_returns, tracing_times, retn_target_sources):
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
        is_narrowing = entry_wrapper.is_narrowing

        addr = current_path.addr
        input_state = current_path.state
        simrun_key = call_stack_suffix + (addr,)

        # Initialize the state with necessary values
        self._initialize_state(input_state)

        if simrun_key not in self._nodes:
            vfg_node = VFGNode(addr, simrun_key, state=input_state)
            self._nodes[simrun_key] = vfg_node

        else:
            # Adding a new VFGNode to our nodes dict
            # TODO:

            vfg_node = self._nodes[simrun_key]

        #if widening_stage != 1:
        #    self._normal_states[simrun_key] = input_state

        if vfg_node.widened_state is None and not is_narrowing:
            # This is where merging happens
            merging_occurred, new_input_state = self._handle_states_merging(vfg_node, addr, input_state, tracing_times)

            if new_input_state is None:
                # This basic block doesn't need to be analyzed anymore...
                return

        else:
            if vfg_node.narrowing_times < 5:
                # However, we do want to narrow it if it's a widened state
                # The way we implement narrowing is quite naive: we just reexecute all reachable blocks with this new state
                # for some times, then take the last result
                if vfg_node.widened_state and vfg_node.narrowing_times == 0:
                    new_input_state = vfg_node.widened_state
                else:
                    new_input_state = input_state
                vfg_node.narrowing_times += 1
                is_narrowing = True

            else:
                return

        input_state = new_input_state
        current_path.state = input_state

        # Execute this basic block with input state, and get a new SimRun object
        simrun, error_occured, restart_analysis = self._get_simrun(input_state, current_path, addr)

        if restart_analysis:
            # We should restart the analysis because of something must be changed in the very initial state
            raise AngrVFGRestartAnalysisNotice()

        if simrun is None:
            # Ouch, we cannot get the simrun for some reason
            return

        if addr not in avoid_runs:
            # Obtain successors
            all_successors = simrun.successors + simrun.unconstrained_successors
        else:
            all_successors = [ ]

        # save those states
        vfg_node.final_states = all_successors[ :: ]

        # Get ignored variables
        # TODO: We should merge it with existing ignored_variable set!

        if isinstance(simrun, simuvex.SimIRSB) and simrun.default_exit is not None:
            if simrun.default_exit.scratch.ignored_variables:
                self._state_ignored_variables[addr] = simrun.default_exit.scratch.ignored_variables.copy()
            else:
                self._state_ignored_variables[addr] = None
        elif all_successors:
            # This is a SimProcedure instance
            self._state_ignored_variables[addr] = all_successors[0].scratch.ignored_variables.copy() \
                if all_successors[0].scratch.ignored_variables is not None else None

        # Update thumb_addrs. TODO: Do we need it in VFG?
        if isinstance(simrun, simuvex.SimIRSB) and current_path.state.thumb:
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
        # Ijk_FakeRet, and Ijk_Call always goes first
        is_call_jump = any([ self._is_call_jump(i.scratch.jumpkind) for i in all_successors ])
        call_targets = [ i.se.exactly_int(i.ip) for i in all_successors if self._is_call_jump(i.scratch.jumpkind) ]
        call_target = None if not call_targets else call_targets[0]

        is_return_jump = len(all_successors) and all_successors[0].scratch.jumpkind == 'Ijk_Ret'

        # For debugging purpose!
        _dbg_exit_status = { }

        for suc_state in all_successors:

            _dbg_exit_status[suc_state] = ""

            self._handle_successor(suc_state, entry_wrapper, all_successors, is_call_jump, is_return_jump, call_target,
                                   current_function_address, call_stack_suffix, retn_target_sources, pending_returns,
                                   tracing_times, remaining_entries, exit_targets, is_narrowing, _dbg_exit_status)

        # Debugging output
        function_name = self.project.loader.find_symbol_name(simrun.addr)
        module_name = self.project.loader.find_module_name(simrun.addr)

        l.debug("Basic block %s %s", simrun, "->".join([hex(i) for i in call_stack_suffix if i is not None]))
        l.debug("(Function %s of binary %s)", function_name, module_name)
        l.debug("|    Has simulated retn: %s", is_call_jump)
        for suc_state in all_successors:
            if is_call_jump and suc_state.scratch.jumpkind == "Ijk_FakeRet":
                exit_type_str = "Simulated Ret"
            else:
                exit_type_str = "-"
            try:
                l.debug("|    target: %s %s [%s] %s", hex(suc_state.se.exactly_int(suc_state.ip)), _dbg_exit_status[suc_state], exit_type_str, suc_state.scratch.jumpkind)
            except simuvex.SimValueError:
                l.debug("|    target cannot be concretized. %s [%s] %s", _dbg_exit_status[suc_state], exit_type_str, suc_state.scratch.jumpkind)
        l.debug("len(remaining_exits) = %d, len(fake_func_retn_exits) = %d", len(remaining_entries), len(pending_returns))

    def _handle_states_merging(self, node, addr, new_state, tracing_times):
        """
        Examine if we have reached to a fix point for the current node, and perform merging/widening if necessary.

        :param node: An instance of VFGNode.
        :param new_state: The new input state that we want to compare against.
        :return: A bool value indicating whether we have reached fix point, and the merge state/original state if possible.
        """
        tracing_times[node] += 1

        tracing_count = tracing_times[node]

        l.debug("Analyzing %s for the %dth time", node, tracing_count)

        if tracing_count == 1:
            node.append_state(new_state)
            return False, new_state

        if tracing_count > MAX_ANALYSIS_TIMES:
            l.debug("%s has been analyzed too many times. Skip.", node)

            return False, None

        # Extract two states
        old_state = node.state

        # The widening flag
        widening_occurred = False

        if addr in self._state_ignored_variables:
            old_state.scratch.ignored_variables = self._state_ignored_variables[addr]
        else:
            old_state.scratch.ignored_variables = simuvex.SimVariableSet()

        if addr in set([dst.addr for (src, dst) in self._widen_points]):
            # We reached a merge point

            if tracing_count >= MAX_ANALYSIS_TIMES_WITHOUT_MERGING:

                if node.widened_state is not None:
                    # We want to narrow the state
                    widened_state = node.widened_state
                    merged_state, narrowing_occurred = self._narrow_states(node, old_state, new_state, widened_state)
                    merging_occurred = narrowing_occurred

                else:
                    # We want to widen the state
                    # ... but, we should merge them first
                    merged_state, merging_occurred = self._merge_states(old_state, new_state)
                    # ... then widen it
                    merged_state, widening_occurred = self._widen_states(old_state, merged_state)

                    merging_occurred = widening_occurred

            else:
                # We want to merge them
                merged_state, merging_occurred = self._merge_states(old_state, new_state)

        else:
            # Not a merge point
            # Always merge the state with existing states
            merged_state, merging_occurred = self._merge_states(old_state, new_state)

        if widening_occurred:
            node.append_state(merged_state, is_widened_state=True)

        else:
            node.append_state(merged_state)

        if merging_occurred:
            l.debug("Merging/widening/narrowing occured for %s. Returning a new state.", node)

            return True, merged_state
        else:
            # if simuvex.s_options.WIDEN_ON_MERGE in merged_state.options:
            #    merged_state.options.remove(simuvex.s_options.WIDEN_ON_MERGE)
            l.debug("%s reached fixpoint.", node)

            return False, None

    def _handle_successor(self, suc_state, entry_wrapper, all_successors, is_call_jump, is_return_jump, call_target,
                          current_function_address, call_stack_suffix, retn_target_sources, pending_returns,
                          tracing_count, remaining_entries, exit_targets, is_narrowing, _dbg_exit_status):

        #
        # Extract initial values
        #
        addr = entry_wrapper.path.addr
        jumpkind = suc_state.scratch.jumpkind
        se = suc_state.se

        self._events.extend([ i for i in suc_state.log.events if not isinstance(i, simuvex.SimAction) ])

        #
        # Get instruction pointer
        #
        try:
            if is_return_jump:
                # FIXME: This is a bad practice...
                ret_target = entry_wrapper.call_stack.get_ret_target()
                if ret_target is None:
                    # We have no where to go according to our call stack
                    # However, we still store the state as it is probably the last available state of the analysis
                    call_stack_suffix = entry_wrapper.call_stack_suffix()
                    simrun_key = call_stack_suffix + (addr, )
                    # self._normal_states[simrun_key] = suc_state
                    return

                suc_state.ip = ret_target

            if len(suc_state.se.any_n_int(suc_state.ip, 2)) > 1:
                if is_return_jump:
                    # It might be caused by state merging
                    # We may retrieve the correct ip from call stack
                    suc_state.ip = entry_wrapper.call_stack.get_ret_target()

                else:
                    # Currently we assume a legit jumping target cannot have more than 256 concrete values
                    MAX_NUMBER_OF_CONCRETE_VALUES = 256

                    all_possible_ips = suc_state.se.any_n_int(suc_state.ip, MAX_NUMBER_OF_CONCRETE_VALUES + 1)

                    if len(all_possible_ips) > MAX_NUMBER_OF_CONCRETE_VALUES:
                        l.warning("IP can be concretized to more than %d values, which means it might be corrupted.",
                                  MAX_NUMBER_OF_CONCRETE_VALUES)

                    else:
                        # Call this function for each possible IP
                        for ip in all_possible_ips:
                            suc_state_ = suc_state.copy()
                            suc_state_.ip = ip

                            self._handle_successor(
                                suc_state_, entry_wrapper, all_successors, is_call_jump, is_return_jump, call_target,
                                current_function_address, call_stack_suffix, retn_target_sources, pending_returns,
                                tracing_count, remaining_entries, exit_targets, is_narrowing, _dbg_exit_status)
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
        if self._is_call_jump(jumpkind):
            fakeret_successor = all_successors[-1]

            # Check if that function is returning
            if self._cfg is not None:
                func = self._cfg.function_manager.function(call_target)
                if func is not None and func.returning is False and len(all_successors) == 2:
                    # Remove the fake return as it is not returning anyway...
                    del all_successors[-1]
                    fakeret_successor = None

        if self._is_call_jump(jumpkind) and \
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

        if jumpkind == "Ijk_FakeRet" and is_call_jump:
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
                reg_sp_expr = successor_state.registers.load(reg_sp_offset) + sp_difference
                successor_state.registers.store(successor_state.arch.sp_offset, reg_sp_expr)

                # Clear the return value with a TOP
                top_si = successor_state.se.TopStridedInterval(successor_state.arch.bits)
                successor_state.registers.store(successor_state.arch.ret_offset, top_si)

                pending_returns[new_tpl] = \
                    (successor_state, new_call_stack, new_bbl_stack)
                _dbg_exit_status[suc_state] = "Appended to fake_func_retn_exits"

        else:
            successor_path = self.project.factory.path(successor_state)
            if simuvex.o.ABSTRACT_MEMORY in suc_state.options:
                if self._is_call_jump(suc_state.scratch.jumpkind):
                    # If this is a call, we create a new stack address mapping
                    reg_sp_si = self._create_stack_region(successor_path.state, successor_path.addr)

                    # Save the new sp register
                    new_reg_sp_expr = successor_path.state.se.ValueSet(bits=suc_state.arch.bits)
                    new_reg_sp_expr.model.set_si('global', reg_sp_si.copy())
                    reg_sp_offset = successor_state.arch.sp_offset
                    successor_path.state.registers.store(reg_sp_offset, new_reg_sp_expr)

                elif suc_state.scratch.jumpkind == "Ijk_Ret":
                    # Remove the existing stack address mapping
                    # FIXME: Now we are assuming the sp is restored to its original value
                    reg_sp_offset = successor_path.state.arch.sp_offset
                    reg_sp_expr = successor_path.state.registers.load(reg_sp_offset)

                    if isinstance(reg_sp_expr.model, claripy.vsa.StridedInterval):
                        reg_sp_si = reg_sp_expr.model
                        reg_sp_val = reg_sp_si.min
                    elif isinstance(reg_sp_expr.model, claripy.vsa.ValueSet):
                        reg_sp_si = reg_sp_expr.model.items()[0][1]
                        reg_sp_val = reg_sp_si.min
                    # TODO: Finish it!

            new_exit_wrapper = EntryWrapper(successor_path,
                                            self._context_sensitivity_level,
                                            call_stack=new_call_stack,
                                            bbl_stack=new_bbl_stack,
                                            is_narrowing=is_narrowing)
            r = self._append_to_remaining_entries(remaining_entries, new_exit_wrapper)
            _dbg_exit_status[suc_state] = r

        if not is_call_jump or jumpkind != "Ijk_FakeRet":
            exit_targets[call_stack_suffix + (addr,)].append((new_tpl, jumpkind))
        else:
            # This is the fake return!
            exit_targets[call_stack_suffix + (addr,)].append((new_tpl, "Ijk_FakeRet"))

    def _is_call_jump(self, jumpkind):
        if jumpkind == 'Ijk_Call' or jumpkind.startswith('Ijk_Sys_'):
            return True
        return False

    def _append_to_remaining_entries(self, remaining_entries, exit_wrapper):
        simrun_key = exit_wrapper.call_stack_suffix() + (exit_wrapper.path.addr, )
        simrun_key = simrun_key[1 : ]

        node = self._cfg.get_node(simrun_key)

        if node is None:
            result = "Appended [not in CFG]"
            remaining_entries.append(exit_wrapper)

        else:
            in_degree = self._cfg.graph.in_degree(node)

            if in_degree <= 1:
                result = "Appended [not a merge point]"
                remaining_entries.append(exit_wrapper)

            else:
                result = "Inserted at front [a merge point]"
                remaining_entries.insert(0, exit_wrapper)

        return result

    def _widen_states(self, old_state, new_state):
        """
        Perform widen operation on the given states, and return a new one.

        :param old_state:
        :param new_state:
        :return: The widened state, and whether widening has occurred
        """

        # print old_state.dbg_print_stack()
        # print new_state.dbg_print_stack()

        l.debug('Widening state at IP %s', old_state.ip)

        if old_state.scratch.ignored_variables is None:
            old_state.scratch.ignored_variables = new_state.scratch.ignored_variables

        widened_state, widening_occurred = old_state.widen(new_state)

        # print "Widened: "
        # print widened_state.dbg_print_stack()

        return widened_state, widening_occurred

    def _narrow_states(self, node, old_state, new_state, previously_widened_state):
        """
        Try to narrow the state!

        :param old_state:
        :param new_state:
        :param previously_widened_state:
        :return: The narrowed state, and whether a narrowing has occurred
        """

        l.debug('Narrowing state at IP %s', previously_widened_state.ip)

        s = previously_widened_state.copy()

        narrowing_occurred = False

        # We will narrow all variables besides those in ignored_variables set

        # Check each fresh variable in new_state, and update them in previously_widened_state if needed.
        # Registers
        ignored_register_vars = self._state_ignored_variables[node.addr].register_variables

        # TODO: Finish the narrowing logic

        return s, narrowing_occurred

    def _merge_states(self, old_state, new_state):
        """
        Merge two given states, and return a new one.

        :param old_state:
        :param new_state:
        :return: The merged state, and whether a merging has occurred
        """

        # print old_state.dbg_print_stack()
        # print new_state.dbg_print_stack()

        if old_state.scratch.ignored_variables is None:
            old_state.scratch.ignored_variables = new_state.scratch.ignored_variables

        merged_state, _, merging_occurred = old_state.merge(new_state)

        # print "Merged: "
        # print merged_state.dbg_print_stack()

        return merged_state, merging_occurred

    def _create_stack_region(self, successor_state, successor_ip):
        reg_sp_offset = successor_state.arch.sp_offset
        reg_sp_expr = successor_state.registers.load(reg_sp_offset)

        if type(reg_sp_expr.model) is claripy.BVV:
            reg_sp_val = successor_state.se.any_int(reg_sp_expr)
            reg_sp_si = successor_state.se.SI(to_conv=reg_sp_expr)
            reg_sp_si = reg_sp_si.model
        elif type(reg_sp_expr.model) in (int, long):
            reg_sp_val = reg_sp_expr.model
            reg_sp_si = successor_state.se.SI(bits=successor_state.arch.bits, to_conv=reg_sp_val)
            reg_sp_si = reg_sp_si.model
        elif type(reg_sp_expr.model) is claripy.vsa.StridedInterval:
            reg_sp_si = reg_sp_expr.model
            reg_sp_val = reg_sp_si.min
        else:
            reg_sp_si = reg_sp_expr.model.items()[0][1]
            reg_sp_val = reg_sp_si.min

        reg_sp_val = reg_sp_val - successor_state.arch.bits / 8  # TODO: Is it OK?
        new_stack_region_id = successor_state.memory.stack_id(successor_ip)
        successor_state.memory.set_stack_address_mapping(reg_sp_val,
                                                        new_stack_region_id,
                                                        successor_ip)

        return reg_sp_si

    def _create_callstack(self, entry_wrapper, successor_ip, jumpkind, is_call_jump, fakeret_successor):
        addr = entry_wrapper.path.addr

        if self._is_call_jump(jumpkind):
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
        if self._is_call_jump(jumpkind):
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

    def _uninitialized_access_handler(self, mem_id, addrs, length, expr, bbl_addr, stmt_idx):
        if type(addrs) is not list:
            addrs = [ addrs ]

        for addr in addrs:
            if expr.model.name not in self._uninitialized_access:
                self._uninitialized_access[expr.model.name] = (bbl_addr, stmt_idx, mem_id, addr, length)

    def _find_innermost_uninitialized_expr(self, expr):
        result = [ ]

        if not expr.args:
            if hasattr(expr.model, 'uninitialized') and expr.model.uninitialized:
                result.append(expr)

        else:
            tmp_result = [ ]

            for a in expr.args:
                if isinstance(a, claripy.Base):
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

        next_expr_type = expr_type

        for ex in expr:
            name = ex.model.name

            if name in self._uninitialized_access:
                bbl_addr, stmt_idx, mem_id, addr, length = self._uninitialized_access[name]
                # FIXME: Here we are reusing expr_type for all uninitialized variables.
                # FIXME: However, it will cause problems for the following case:
                # FIXME: addr(uninit) = addr_a(uninit) + offset_b(uninit)
                # FIXME: In this case, both addr_a and offset_b will be treated as addresses
                # FIXME: We should consider a fix for that
                self._state_initialization_map[bbl_addr].append((mem_id, addr, length, next_expr_type, stmt_idx))
                if next_expr_type == 'addr':
                    next_expr_type = 'value'
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

                elif expr_type == 'value':
                    # Give it a value
                    value = se.SI(bits=length, stride=1, lower_bound=-(2**length-1), upper_bound=2**length)

                else:
                    raise Exception('Not implemented. Please report it to Fish.')

                # Write to the state
                if mem_id == 'reg':
                    state.registers.store(addr, value)
                else:
                    # TODO: This is completely untested!
                    region_id, offset = addr
                    target_addr = se.VS(region=region_id, bits=state.arch.bits, val=offset)

                    state.memory.store(target_addr, value, size=length)

    def _get_block_addr(self, b): #pylint:disable=R0201
        if isinstance(b, simuvex.SimIRSB):
            return b.first_imark.addr
        elif isinstance(b, simuvex.SimProcedure):
            return b.addr
        else:
            raise Exception("Unsupported block type %s" % type(b))

    def get_any_node(self, addr):
        """
        Get any VFG node corresponding to the basic block at @addr.
        Note that depending on the context sensitivity level, there might be
        multiple nodes corresponding to different contexts. This function will
        return the first one it encounters, which might not be what you want.
        """
        for n in self.graph.nodes():
            if n.addr == addr:
                return n

    def irsb_from_node(self, node):
        return self.project.factory.sim_run(node.state, addr=node.addr)

    def _get_nx_paths(self, begin, end):
        """
        Get the possible (networkx) simple paths between two nodes or addresses
        corresponding to nodes.
        Input: addresses or node instances
        Return: a list of lists of nodes representing paths.
        """
        if type(begin) in (int, long) and type(end) in (int, long):
            n_begin = self.get_any_node(begin)
            n_end = self.get_any_node(end)

        elif isinstance(begin, VFGNode) and isinstance(end, VFGNode):
            n_begin = begin
            n_end = end
        else:
            raise AngrVFGError("from and to should be of the same type")

        return networkx.all_simple_paths(self.graph, n_begin, n_end)

    def get_paths(self, begin, end):
        """
        Get all the simple paths between @begin and @end.
        Returns: a list of angr.Path instances.
        """
        paths = self._get_nx_paths(begin, end)
        a_paths = []
        for p in paths:
            runs = map(self.irsb_from_node, p)
            a_paths.append(angr.path.make_path(self.project, runs))
            return a_paths

register_analysis(VFG, 'VFG')
