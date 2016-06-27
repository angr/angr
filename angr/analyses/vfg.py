from collections import defaultdict
import logging

import networkx

import simuvex
import claripy
import angr
import archinfo

from ..entry_wrapper import SimRunKey, EntryWrapper, CallStack
from ..analysis import Analysis, register_analysis
from ..errors import AngrVFGError, AngrVFGRestartAnalysisNotice, AngrError
from .forward_analysis import ForwardAnalysis, AngrForwardAnalysisSkipEntry

l = logging.getLogger(name="angr.analyses.vfg")

# The maximum tracing times of a basic block before we widen the results
MAX_ANALYSIS_TIMES_WITHOUT_MERGING = 5
MAX_ANALYSIS_TIMES = 10

class VFGJob(EntryWrapper):
    """
    An EntryWrapper that contains vfg local variables
    """
    def __init__(self, *args, **kwargs):
        super(VFGJob, self).__init__(*args, **kwargs)

        self.call_stack_suffix = None
        self.simrun = None
        self.vfg_node = None
        self.is_call_jump = None
        self.call_target = None
        self.dbg_exit_status = {}
        self.is_return_jump = None

class VFGNode(object):
    """
    A descriptor of nodes in a Value-Flow Graph
    """
    def __init__(self, addr, key, state=None):
        """
        Constructor.

        :param int addr:
        :param SimRunKey key:
        :param simuvex.SimState state:
        """
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
        s = "VFGNode[%#x] <%s>" % (self.addr, repr(self.key))
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


class VFG(ForwardAnalysis, Analysis):   # pylint:disable=abstract-method
    """
    This class represents a control-flow graph with static analysis result.

    Perform abstract interpretation analysis starting from the given function address. The output is an invariant at
    the beginning (or the end) of each basic block.

    Steps:
    # Generate a CFG first if CFG is not provided.
    # Identify all merge points (denote the set of merge points as Pw) in the CFG.
    # Cut those loop back edges (can be derived from Pw) so that we gain an acyclic CFG.
    # Identify all variables that are 1) from memory loading 2) from initial values, or 3) phi functions. Denote
        the set of those variables as S_{var}.
    # Start real AI analysis and try to compute a fix point of each merge point. Perform widening/narrowing only on
        variables \\in S_{var}.
    """

    # TODO: right now the graph traversal method is not optimal. A new solution is needed to minimize the iteration we
    # TODO: access each node in the graph

    def __init__(self, cfg=None,
                 context_sensitivity_level=2,
                 function_start=None,
                 interfunction_level=0,
                 initial_state=None,
                 avoid_runs=None,
                 remove_options=None,
                 timeout=None,
                 start_at_function=True
                 ):
        """
        :param project: The project object.
        :param context_sensitivity_level: The level of context-sensitivity of this VFG.
                                        It ranges from 0 to infinity. Default 2.
        :param function_start: The address of the function to analyze. N
        :param interfunction_level: The level of interfunction-ness to be
        :param initial_state: A state to use as the initial one
        :param avoid_runs: A list of runs to avoid
        :param remove_options: State options to remove from the initial state. It only works when `initial_state` is
                                None
        :param int timeout:
        :param bool start_at_function:
        """

        ForwardAnalysis.__init__(self, order_entries=True, allow_merging=True)

        # Related CFG.
        # We can still perform analysis if you don't specify a CFG. But providing a CFG may give you better result.
        self._cfg = cfg

        # Where to start the analysis
        self._start = function_start if function_start is not None else self.project.entry

        # Other parameters
        self._avoid_runs = [ ] if avoid_runs is None else avoid_runs
        self._context_sensitivity_level = context_sensitivity_level
        self._interfunction_level = interfunction_level
        self._state_options_to_remove = set() if remove_options is None else remove_options
        self._timeout = timeout
        self._start_at_function = start_at_function

        self._initial_state = initial_state

        self._nodes = {}            # all the vfg nodes, keyed on simrun keys
        self._normal_states = { }   # Last available state for each program point without widening
        self._widened_states = { }  # States on which widening has occurred

        # Initial states for start analyzing different functions
        # It maps function key to its states
        self._function_initial_states = defaultdict(dict)

        # All final states are put in this list
        self.final_states = [ ]

        self._state_initialization_map = defaultdict(list)

        self._exit_targets = defaultdict(list) # A dict to log edges and the jumpkind between each basic block
        # A dict to record all blocks that returns to a specific address
        self._return_target_sources = defaultdict(list)

        self._pending_returns = {}

        self._thumb_addrs = set()   # set of all addresses that are code in thumb mode

        self._final_address = None  # Address of the very last instruction. The analysis is terminated there.

        # local variables

        self._analyze()

    #
    # Public methods
    #

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

    #
    # Operations
    #

    def copy(self):
        new_vfg = VFG(self.project)
        new_vfg._cfg = self._cfg
        new_vfg._graph = networkx.DiGraph(self.graph)
        new_vfg._nodes = self._nodes.copy()
        new_vfg._exit_targets = defaultdict(list, self._exit_targets)
        return new_vfg

    # Pickling helpers
    def __setstate__(self, s):
        self.__dict__.update(s)

    def __getstate__(self):
        return dict(self.__dict__)

    #
    # Main analysis routines, mostly overriding methods of ForwardAnalysis
    #

    def _pre_analysis(self):
        l.debug("Starting from %#x", self._start)

        # Generate a CFG if no CFG is provided
        if not self._cfg:

            l.debug("Generating a CFG, since none was given...")
            self._cfg = self.project.analyses.CFGAccurate(context_sensitivity_level=self._context_sensitivity_level,
                starts=(self._start,)
            )


        # Prepare the state
        initial_state = self._prepare_state(self._start, self._initial_state, function_key=None)
        initial_state.ip = self._start

        initial_state = initial_state.arch.prepare_state(initial_state,
                                                       {'current_function': self._start, }
        )

        # Create the initial path
        entry_state = initial_state.copy()
        entry_path = self.project.factory.path(entry_state)

        if self._start_at_function:
            # set the return address to an address so we can catch it and terminate the VSA analysis
            # TODO: Properly pick an address that will not conflict with any existing code and data in the program
            self._final_address = 0x4fff0000
            self._set_return_address(entry_state, self._final_address)

        job = VFGJob(entry_path.addr, entry_path, self._context_sensitivity_level,
                     jumpkind='Ijk_Boring', final_return_address=self._final_address
                     )
        simrun_key = SimRunKey.new(entry_path.addr, job.get_call_stack_suffix(), job.jumpkind)
        job.simrun_key = simrun_key

        self._insert_entry(job)

    def _entry_sorting_key(self, entry):
        return self._cfg.get_topological_order(self._cfg.get_node(entry.simrun_key))

    def _entry_key(self, entry):
        return entry.simrun_key

    def _pre_entry_handling(self, entry):
        """
        Some code executed before actually processing the entry.

        :param VFGJob entry: the VFGJob object.
        :return: None
        """

        if self._final_address is not None and entry.addr == self._final_address:
            # our analysis should be termianted here
            raise AngrForwardAnalysisSkipEntry()

        entry.call_stack_suffix = entry.get_call_stack_suffix()
        entry.jumpkind = 'Ijk_Boring' if entry.path.state.scratch.jumpkind is None else \
            entry.path.state.scratch.jumpkind

        current_path = entry.path
        src_simrun_key = entry.src_simrun_key
        src_exit_stmt_idx = entry.src_exit_stmt_idx


        addr = current_path.addr
        input_state = current_path.state
        simrun_key = SimRunKey.new(addr, entry.call_stack_suffix, entry.jumpkind)

        if simrun_key not in self._nodes:
            entry.vfg_node = VFGNode(addr, simrun_key, state=input_state)
            self._nodes[simrun_key] = entry.vfg_node

        else:
            entry.vfg_node = self._nodes[simrun_key]

        current_path.state = input_state

        # Execute this basic block with input state, and get a new SimRun object
        # unused result var is `error_occured`
        entry.simrun, _, restart_analysis = self._get_simrun(input_state, current_path, addr)

        if restart_analysis:
            # We should restart the analysis because of something must be changed in the very initial state
            raise AngrVFGRestartAnalysisNotice()

        if entry.simrun is None:
            # Ouch, we cannot get the simrun for some reason
            # Skip this guy
            raise AngrForwardAnalysisSkipEntry()

        self._graph_add_edge(src_simrun_key,
                             simrun_key,
                             jumpkind=entry.jumpkind,
                             src_exit_stmt_idx=src_exit_stmt_idx)

    def _get_successors(self, entry):
        # Extract initial values
        current_path = entry.path
        addr = entry.addr

        # Obtain successors
        if addr not in self._avoid_runs:
            all_successors = entry.simrun.successors + entry.simrun.unconstrained_successors
        else:
            all_successors = []

        # save those states
        entry.vfg_node.final_states = all_successors[:]

        # Update thumb_addrs
        if isinstance(entry.simrun, simuvex.SimIRSB) and current_path.state.thumb:
            self._thumb_addrs.update(entry.simrun.imark_addrs())

        if len(all_successors) == 0:
            if isinstance(entry.simrun,
                          simuvex.procedures.SimProcedures["stubs"]["PathTerminator"]):
                # If there is no valid exit in this branch and it's not
                # intentional (e.g. caused by a SimProcedure that does not
                # do_return) , we should make it return to its callsite.
                # However, we don't want to use its state as it might be
                # corrupted. Just create a link in the exit_targets map.
                retn_target = entry.call_stack.current_return_target
                if retn_target is not None:
                    new_call_stack = entry.call_stack_copy()
                    exit_target_tpl = new_call_stack.stack_suffix(self._context_sensitivity_level) + (retn_target,)
                    self._exit_targets[entry.call_stack_suffix + (addr,)].append(
                        (exit_target_tpl, 'Ijk_Ret'))
            else:
                # This is intentional. We shall remove all the pending returns generated before along this path.
                self._remove_pending_return(entry, self._pending_returns)

        # If this is a call exit, we shouldn't put the default exit (which
        # is artificial) into the CFG. The exits will be Ijk_Call and
        # Ijk_FakeRet, and Ijk_Call always goes first
        entry.is_call_jump = any([self._is_call_jumpkind(i.scratch.jumpkind) for i in all_successors])
        call_targets = [i.se.exactly_int(i.ip) for i in all_successors if self._is_call_jumpkind(i.scratch.jumpkind)]
        entry.call_target = None if not call_targets else call_targets[0]

        entry.is_return_jump = len(all_successors) and all_successors[0].scratch.jumpkind == 'Ijk_Ret'

        return all_successors

    def _handle_successor(self, entry, successor, all_successors):
        # Extract initial values
        addr = entry.path.addr
        jumpkind = successor.scratch.jumpkind
        new_entries = [ ]

        # TODO: handle events
        # self._events.extend([ i for i in successor.log.events if not isinstance(i, simuvex.SimAction) ])

        # Get instruction pointer
        # this try-except block is to handle cases where the instruction pointer is symbolic
        try:
            if entry.is_return_jump:
                ret_target = entry.call_stack.current_return_target
                if ret_target is None:
                    # We have no where to go according to our call stack. However, the callstack might be corrupted
                    l.debug("According to the call stack, we have nowhere to return to.")
                    return

                successor.ip = ret_target

            if len(successor.se.any_n_int(successor.ip, 2)) > 1:
                if entry.is_return_jump:
                    # It might be caused by state merging
                    # We may retrieve the correct ip from call stack
                    successor.ip = entry.call_stack.current_return_target

                else:
                    # Currently we assume a legit jumping target cannot have more than 256 concrete values
                    MAX_NUMBER_OF_CONCRETE_VALUES = 256

                    all_possible_ips = successor.se.any_n_int(successor.ip, MAX_NUMBER_OF_CONCRETE_VALUES + 1)

                    if len(all_possible_ips) > MAX_NUMBER_OF_CONCRETE_VALUES:
                        l.warning("IP can be concretized to more than %d values, which means it might be corrupted.",
                                  MAX_NUMBER_OF_CONCRETE_VALUES)
                        return
                    else:
                        # Call this function for each possible IP
                        for ip in all_possible_ips:
                            concrete_successor = successor.copy()
                            concrete_successor.ip = ip

                            new_entries.extend(self._handle_successor(entry, concrete_successor, all_successors))
                        return new_entries

            successor_ip = successor.se.exactly_int(successor.ip)
        except simuvex.SimValueError:
            # TODO: Should fall back to reading targets from CFG
            # It cannot be concretized currently. Maybe we could handle
            # it later, maybe it just cannot be concretized
            return

        # Make a copy of the state in case we use it later
        successor_state = successor.copy()

        fakeret_successor = None
        if self._is_call_jumpkind(jumpkind):
            # bail out if we hit the interfunction_level cap
            if len(entry.call_stack) > self._interfunction_level:
                l.debug('We are not tracing into a new function %#x because we hit interfunction_level', successor_ip)
                # However, we do want to save out the state here
                self._save_state(entry, successor_ip, successor_state)
                return

            # Get the fakeret successor. If the function we're calling into doesn't return, we should discard it.
            fakeret_successor = all_successors[-1]
            if self._cfg is not None:
                func = self.kb.functions.function(addr=entry.call_target)
                if func is not None and func.returning is False and len(all_successors) == 2:
                    # TODO: do we really want to be deleting elements out of the list we're iterative over??
                    del all_successors[-1]
                    fakeret_successor = None

        # Create a new call stack
        # TODO: why are we creating a new callstack even when we're not doing a call?
        new_call_stack = self._create_callstack(entry, successor_ip, jumpkind, entry.is_call_jump, fakeret_successor)
        if new_call_stack is None:
            l.debug("Cannot create a new callstack for address %#x", successor_ip)
            return
        new_call_stack_suffix = new_call_stack.stack_suffix(self._context_sensitivity_level)
        new_simrun_key = SimRunKey.new(successor_ip, new_call_stack_suffix, jumpkind)

        # Generate the new BBL stack of target block
        new_bbl_stack = self._create_bblstack(entry,
                                              jumpkind,
                                              successor_ip,
                                              entry.is_call_jump,
                                              entry.call_stack_suffix,
                                              new_call_stack_suffix,
                                              entry.func_addr)

        # Generate new exits
        if jumpkind == "Ijk_Ret" and not entry.is_call_jump:
            # This is the real retn exit
            # Remember this retn!
            self._return_target_sources[successor_ip].append(entry.call_stack_suffix + (addr, ))
            # Check if this retn is inside our fake_func_retn_exits set
            if new_simrun_key in self._pending_returns:
                del self._pending_returns[new_simrun_key]

        if jumpkind == "Ijk_FakeRet" and entry.is_call_jump:
            # This is the default "fake" return successor generated at each call. Save them first, but don't process
            # them right away

            # Clear the useless values (like return addresses, parameters) on stack if needed
            if self._cfg is not None:
                current_function = self.kb.functions.function(entry.call_target)
                if current_function is not None:
                    sp_difference = current_function.sp_delta
                else:
                    sp_difference = 0
                reg_sp_offset = successor_state.arch.sp_offset
                reg_sp_expr = successor_state.registers.load(reg_sp_offset) + sp_difference
                successor_state.registers.store(successor_state.arch.sp_offset, reg_sp_expr)

                # Clear the return value with a TOP
                top_si = successor_state.se.TSI(successor_state.arch.bits)
                successor_state.registers.store(successor_state.arch.ret_offset, top_si)

                self._pending_returns[new_simrun_key] = \
                    (successor_state, new_call_stack, new_bbl_stack)
                entry.dbg_exit_status[successor] = "Appended to pending_returns"

        else:
            successor_path = self.project.factory.path(successor_state)
            if simuvex.o.ABSTRACT_MEMORY in successor.options:
                if self._is_call_jumpkind(successor.scratch.jumpkind):
                    # If this is a call, we create a new stack address mapping
                    reg_sp_si = self._create_stack_region(successor_path.state, successor_path.addr)

                    # Save the new sp register
                    new_reg_sp_expr = successor_path.state.se.ValueSet(successor_state.arch.bits,
                                                                       'global',
                                                                       0,
                                                                       reg_sp_si
                                                                       )
                    successor_path.state.regs.sp = new_reg_sp_expr

                elif successor.scratch.jumpkind == "Ijk_Ret":
                    # Remove the existing stack address mapping
                    # FIXME: Now we are assuming the sp is restored to its original value
                    reg_sp_expr = successor_path.state.regs.sp

                    if isinstance(reg_sp_expr._model_vsa, claripy.vsa.StridedInterval):
                        reg_sp_si = reg_sp_expr._model_vsa
                        reg_sp_val = reg_sp_si.min
                    elif isinstance(reg_sp_expr._model_vsa, claripy.vsa.ValueSet):
                        reg_sp_si = reg_sp_expr._model_vsa.items()[0][1]
                        reg_sp_val = reg_sp_si.min
                    # TODO: Finish it!

            new_exit_wrapper = VFGJob(successor_path.addr,
                                      successor_path,
                                      self._context_sensitivity_level,
                                      simrun_key=new_simrun_key,
                                      jumpkind=successor_path.state.scratch.jumpkind,
                                      call_stack=new_call_stack,
                                      bbl_stack=new_bbl_stack,
                                      #is_narrowing=is_narrowing)
                                      )
            #r = self._worklist_append_entry(new_exit_wrapper)
            #_dbg_exit_status[successor] = r

            new_entries.append(new_exit_wrapper)

            entry.dbg_exit_status[successor] = "Appended"

        if not entry.is_call_jump or jumpkind != "Ijk_FakeRet":
            new_target = (new_simrun_key, jumpkind)
        else:
            new_target = (new_simrun_key, "Ijk_FakeRet") # This is the fake return!
        self._exit_targets[entry.call_stack_suffix + (addr,)].append(new_target)

        return new_entries

    def _post_entry_handling(self, entry, successors):
        # Debugging output
        if l.level == logging.DEBUG:

            function_name = self.project.loader.find_symbol_name(entry.addr)
            module_name = self.project.loader.find_module_name(entry.addr)

            l.debug("%#08x %s", entry.addr, "->".join([hex(i) for i in entry.call_stack_suffix if i is not None]))
            l.debug("(Function %s of binary %s)", function_name, module_name)
            l.debug("|    Has simulated retn: %s", entry.is_call_jump)
            for suc in successors:
                if entry.is_call_jump and suc.scratch.jumpkind == "Ijk_FakeRet":
                    exit_type_str = "Simulated Ret"
                else:
                    exit_type_str = "-"

                if suc not in entry.dbg_exit_status:
                    # TODO:
                    l.warning("| %s is not found. FIND OUT WHY.", suc)
                    continue

                try:
                    l.debug("|    target: %s %s [%s] %s", hex(suc.se.exactly_int(suc.ip)),
                            entry.dbg_exit_status[suc], exit_type_str, suc.scratch.jumpkind)
                except simuvex.SimValueError:
                    l.debug("|    target cannot be concretized. %s [%s] %s", entry.dbg_exit_status[suc], exit_type_str,
                            suc.scratch.jumpkind)
            l.debug("%d entries remaining, and %d return entries pending", len(self._entries),
                    len(self._pending_returns))

    def _intra_analysis(self):
        pass

    def _merge_entries(self, *entries):

        assert len(entries) == 2

        path_0 = entries[0].path
        path_1 = entries[1].path

        merged_state, _ = self._merge_states(path_0.state, path_1.state)

        path = self.project.factory.path(merged_state)

        return VFGJob(entries[0].addr, path, self._context_sensitivity_level, jumpkind=entries[0].jumpkind,
                      simrun_key=entries[0].simrun_key
                      )

    def _entry_list_empty(self):

        if self._pending_returns:
            # We don't have any paths remaining. Let's pop a previously-missing return to
            # process
            pending_ret_key = self._pending_returns.keys()[0]
            state, call_stack, bbl_stack = self._pending_returns.pop(pending_ret_key)
            addr = pending_ret_key.addr

            # Unlike CFG, we will still trace those blocks that have been traced before. In other words, we don't
            # remove fake returns even if they have been traced - otherwise we cannot come to a fixpoint.

            new_path = self.project.factory.path(state)
            simrun_key = SimRunKey.new(addr,
                                       call_stack.stack_suffix(self._context_sensitivity_level),
                                       'Ijk_Ret'
                                       )
            job = VFGJob(new_path.addr,
                         new_path,
                         self._context_sensitivity_level,
                         simrun_key=simrun_key,
                         jumpkind=new_path.state.scratch.jumpkind,
                         call_stack=call_stack,
                         bbl_stack=bbl_stack
                         )
            self._insert_entry(job)
            l.debug("Tracing a missing return %#08x, %s", addr, repr(pending_ret_key))

    def _post_analysis(self):
        pass

    def _handle_states_merging(self, node, addr, new_state, tracing_times):
        """
        Examine if we have reached to a fix point for the current node, and perform merging/widening if necessary.

        :param node: An instance of VFGNode.
        :param new_state: The new input state that we want to compare against.
        :returns: A bool value indicating whether we have reached fix point, and the merge state/original state if possible.
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

        # TODO: _widen_points doesn't exist anymore!
        if addr in set(dst.addr for (_, dst) in self._widen_points):
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

    #
    # State widening, merging, and narrowing
    #

    @staticmethod
    def _widen_states(old_state, new_state):
        """
        Perform widen operation on the given states, and return a new one.

        :param old_state:
        :param new_state:
        :returns: The widened state, and whether widening has occurred
        """

        # print old_state.dbg_print_stack()
        # print new_state.dbg_print_stack()

        l.debug('Widening state at IP %s', old_state.ip)

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
        :returns: The narrowed state, and whether a narrowing has occurred
        """

        l.debug('Narrowing state at IP %s', previously_widened_state.ip)

        s = previously_widened_state.copy()

        narrowing_occurred = False

        # TODO: Finish the narrowing logic

        return s, narrowing_occurred

    @staticmethod
    def _merge_states(old_state, new_state):
        """
        Merge two given states, and return a new one.

        :param old_state:
        :param new_state:
        :returns: The merged state, and whether a merging has occurred
        """

        # print old_state.dbg_print_stack()
        # print new_state.dbg_print_stack()

        merged_state, _, merging_occurred = old_state.merge(new_state)

        # print "Merged: "
        # print merged_state.dbg_print_stack()

        return merged_state, merging_occurred


    #
    # Helper methods
    #

    def _prepare_state(self, function_start, initial_state, function_key):
        """
        Generate the state used to begin analysis
        """
        if initial_state is None:
            if function_start not in self._function_initial_states:
                # We have never saved any initial states for this function
                # Gotta create a fresh state for it
                s = self.project.factory.blank_state(mode="static",
                                              remove_options=self._state_options_to_remove,
                )

                if function_start != self.project.entry:
                    # This function might have arguments passed on stack, so make
                    # some room for them.
                    # TODO: Decide the number of arguments and their positions
                    #  during CFG analysis
                    sp = s.regs.sp
                    # Set the address mapping
                    sp_val = s.se.any_int(sp) # FIXME: What will happen if we lose track of multiple sp values?
                    s.memory.set_stack_address_mapping(sp_val,
                                                       s.memory.stack_id(function_start) + '_pre',
                                                       0x0)
                    s.registers.store('sp', sp - 160)
            elif function_key is None:
                l.debug('We should combine all existing states for this function, then analyze it.')
                merged_state = None
                for state in self._function_initial_states[function_start].values():
                    if merged_state is None:
                        merged_state = state
                    else:
                        merged_state, _, _ = merged_state.merge(state)
                s = merged_state
            elif function_key in self._function_initial_states[function_start]:
                l.debug('Loading previously saved state for function %#x %s', function_start,
                        CallStack.stack_suffix_to_string(function_key))
                s = self._function_initial_states[function_start][function_key]
            else:
                raise AngrVFGError('Initial state for function %#x and function key %s is not found.' %
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
        initial_sp -= s.arch.bytes
        s.memory.set_stack_address_mapping(initial_sp,
                                           s.memory.stack_id(function_start),
                                           function_start
                                           )

        return s

    def _set_return_address(self, state, ret_addr):
        """
        Set the return address of the current state to a specific address. We assume we are at the beginning of a
        function, or in other words, we are about to execute the very first instruction of the function.

        :param simuvex.SimState state: The program state
        :param int ret_addr: The return address
        :return: None
        """

        # TODO: the following code is totally untested other than X86 and AMD64. Don't freak out if you find bugs :)
        # TODO: Test it

        ret_bvv = state.se.BVV(ret_addr, self.project.arch.bits)

        if self.project.arch.name in ('X86', 'AMD64'):
            state.stack_push(ret_bvv)
        elif self.project.arch.name in ('ARMEL', 'ARMHF', 'AARCH64'):
            state.regs.lr = ret_bvv
        elif self.project.arch.name in ('MIPS32', 'MIPS64'):
            state.regs.ra = ret_bvv
        elif self.project.arch.name in ('PPC32', 'PPC64'):
            state.regs.lr = ret_bvv
        else:
            l.warning('Return address cannot be set for architecture %s. Please add corresponding logic to '
                      'VFG._set_return_address().', self.project.arch.name
                      )

    def _create_graph(self, return_target_sources=None):
        """
        Create a DiGraph out of the existing edge map.
        :param return_target_sources: Used for making up those missing returns
        :returns: A networkx.DiGraph() object
        """
        if return_target_sources is None:
            # We set it to a defaultdict in order to be consistent with the
            # actual parameter.
            return_target_sources = defaultdict(list)

        cfg = networkx.DiGraph()
        # The corner case: add a node to the graph if there is only one block
        if len(self._nodes) == 1:
            cfg.add_node(self._nodes[self._nodes.keys()[0]])

        # Adding edges
        for tpl, targets in self._exit_targets.items():
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
                            return "%#08x" % addr

                    s = "(["
                    for addr in ex[:-1]:
                        s += addr_formalize(addr) + ", "
                    s += "] %s)" % addr_formalize(ex[-1])
                    l.warning("Key %s does not exist.", s)

        return cfg

    #
    # DiGraph manipulation
    #

    def _graph_get_node(self, node_key, terminator_for_nonexistent_node=False):
        """

        :param node_key:
        :return:
        """

        if node_key not in self._nodes:
            l.error("Trying to look up a node that we don't have yet. is this okay????")
            if not terminator_for_nonexistent_node:
                return None
            # Generate a PathTerminator node
            addr = node_key.addr
            func_addr = node_key.func_addr
            if func_addr is None:
                # We'll have to use the current SimRun address instead
                # TODO: Is it really OK?
                func_addr = addr

            input_state = self.project.factory.entry_state()
            input_state.ip = addr
            pt = VFGNode(addr, node_key, input_state)
            self._nodes[node_key] = pt

            if isinstance(self.project.arch, archinfo.ArchARM) and addr % 2 == 1:
                self._thumb_addrs.add(addr)
                self._thumb_addrs.add(addr - 1)

            l.debug("SimRun key %s does not exist. Create a PathTerminator instead.",
                    repr(node_key))

        return self._nodes[node_key]

    def _graph_add_edge(self, src_node_key, dst_node_key, **kwargs):
        """

        :param src_node_key:
        :param dst_node_key:
        :param jumpkind:
        :param exit_stmt_idx:
        :return:
        """

        dst_node = self._graph_get_node(dst_node_key, terminator_for_nonexistent_node=True)

        if src_node_key is None:
            self.graph.add_node(dst_node)

        else:
            src_node = self._graph_get_node(src_node_key, terminator_for_nonexistent_node=True)
            self.graph.add_edge(src_node, dst_node, **kwargs)

    def _get_simrun(self, state, current_path, addr):
        error_occured = False
        restart_analysis = False

        jumpkind = 'Ijk_Boring'
        if current_path.state.scratch.jumpkind:
            jumpkind = current_path.state.scratch.jumpkind

        try:
            sim_run = self.project.factory.sim_run(current_path.state, jumpkind=jumpkind)
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
            l.error("AngrError %s when creating SimRun at %#x",
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
        while call_stack_copy.current_return_target is not None:
            ret_target = call_stack_copy.current_return_target
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

    @staticmethod
    def _is_call_jumpkind(jumpkind):
        if jumpkind == 'Ijk_Call' or jumpkind.startswith('Ijk_Sys_'):
            return True
        return False

    @staticmethod
    def _create_stack_region(successor_state, successor_ip):
        reg_sp_offset = successor_state.arch.sp_offset
        reg_sp_expr = successor_state.registers.load(reg_sp_offset)

        if type(reg_sp_expr._model_vsa) is claripy.BVV:
            reg_sp_val = successor_state.se.any_int(reg_sp_expr)
            reg_sp_si = successor_state.se.SI(to_conv=reg_sp_expr)
            reg_sp_si = reg_sp_si._model_vsa
        elif type(reg_sp_expr._model_vsa) in (int, long):
            reg_sp_val = reg_sp_expr._model_vsa
            reg_sp_si = successor_state.se.SI(bits=successor_state.arch.bits, to_conv=reg_sp_val)
            reg_sp_si = reg_sp_si._model_vsa
        elif type(reg_sp_expr._model_vsa) is claripy.vsa.StridedInterval:
            reg_sp_si = reg_sp_expr._model_vsa
            reg_sp_val = reg_sp_si.min
        else:
            reg_sp_si = reg_sp_expr._model_vsa.items()[0][1]
            reg_sp_val = reg_sp_si.min

        reg_sp_val = reg_sp_val - successor_state.arch.bytes  # TODO: Is it OK?
        new_stack_region_id = successor_state.memory.stack_id(successor_ip)
        successor_state.memory.set_stack_address_mapping(reg_sp_val,
                                                        new_stack_region_id,
                                                        successor_ip)

        return reg_sp_si

    def _create_callstack(self, entry_wrapper, successor_ip, jumpkind, is_call_jump, fakeret_successor):
        addr = entry_wrapper.path.addr

        if self._is_call_jumpkind(jumpkind):
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
        if self._is_call_jumpkind(jumpkind):
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
        l.debug('Saving out the state for function %#x with function_key %s',
                function_addr,
                CallStack.stack_suffix_to_string(function_key))
        if function_addr in self._function_initial_states and \
                        function_key in self._function_initial_states[function_addr]:
            existing_state = self._function_initial_states[function_addr][function_key]
            merged_state, _, _ = existing_state.merge(successor_state)
            self._function_initial_states[function_addr][function_key] = merged_state
        else:
            self._function_initial_states[function_addr][function_key] = successor_state

    def _get_block_addr(self, b): #pylint:disable=R0201
        if isinstance(b, simuvex.SimIRSB):
            return b.first_imark.addr
        elif isinstance(b, simuvex.SimProcedure):
            return b.addr
        else:
            raise Exception("Unsupported block type %s" % type(b))

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

register_analysis(VFG, 'VFG')
