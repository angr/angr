from collections import defaultdict
import logging

import networkx
import pyvex
import simuvex
import claripy
from archinfo import ArchARM

import angr
from ..entry_wrapper import EntryWrapper
from .cfg_base import CFGBase
from ..analysis import Analysis, register_analysis
from ..errors import AngrCFGError, AngrError, AngrBackwardSlicingError

l = logging.getLogger(name="angr.analyses.cfg")

class CFGNode(object):
    '''
    This class stands for each single node in CFG.
    '''
    def __init__(self, callstack_key, addr, size, cfg, input_state=None, simprocedure_name=None, syscall_name=None,
                 looping_times=0, no_ret=False, is_syscall=False, syscall=None, simrun=None, function_address=None,
                 final_states=None):
        '''
        Note: simprocedure_name is not used to recreate the SimProcedure object. It's only there for better
        __repr__.
        '''

        self.callstack_key = callstack_key
        self.addr = addr
        self.input_state = input_state
        self.simprocedure_name = simprocedure_name
        self.syscall_name = syscall_name
        self.size = size
        self.looping_times = looping_times
        self.no_ret = no_ret
        self.is_syscall = is_syscall
        self.syscall = syscall
        self._cfg = cfg
        self.function_address = function_address
        self.name = simprocedure_name or cfg.project.loader.find_symbol_name(addr)
        if function_address and self.name is None:
            self.name = cfg.project.loader.find_symbol_name(function_address)
            if self.name is not None:
                self.name = "%s+0x%x" % (self.name, (addr - function_address))

        # If this CFG contains an Ijk_Call, `return_target` stores the returning site.
        # Note: this is regardless of whether the call returns or not. You should always check the `no_ret` property if
        # you are using `return_target` to do some serious stuff.
        self.return_target = None

        self.instruction_addrs = [ ]
        if not self.is_simprocedure and simrun is not None:
            # This is a SimIRSB
            # Grab all instruction addresses out!
            irsb = simrun.irsb
            self.instruction_addrs = [ s.addr for s in irsb.statements if type(s) is pyvex.IRStmt.IMark ]  # pylint:disable=unidiomatic-typecheck

        self.final_states = [ ] if final_states is None else final_states

    @property
    def successors(self):
        return self._cfg.get_successors(self)

    @property
    def predecessors(self):
        return self._cfg.get_predecessors(self)

    @property
    def is_simprocedure(self):
        return self.simprocedure_name is not None


    def copy(self):
        c = CFGNode(self.callstack_key,
                    self.addr,
                    self.size,
                    self._cfg,
                    self.input_state,
                    self.simprocedure_name,
                    self.looping_times,
                    self.no_ret,
                    self.is_syscall,
                    self.syscall,
                    self.function_address,
                    final_states=self.final_states[ :: ])
        c.instruction_addrs = self.instruction_addrs[ :: ]
        return c

    def __repr__(self):
        if self.name is not None:
            s = "<CFGNode %s (0x%x) [%d]>" % (self.name, self.addr, self.looping_times)
        else:
            s = "<CFGNode 0x%x (%d) [%d]>" % (self.addr, self.size, self.looping_times)

        return s

    def __eq__(self, other):
        if isinstance(other, simuvex.SimIRSB) or isinstance(other, simuvex.SimProcedure):
            raise ValueError("You do not want to be comparing a SimRun to a CFGNode.")
        if not isinstance(other, CFGNode):
            return False
        return (self.callstack_key == other.callstack_key and
                self.addr == other.addr and
                self.size == other.size and
                self.looping_times == other.looping_times and
                self.simprocedure_name == other.simprocedure_name
                )

    def __hash__(self):
        return hash((self.callstack_key, self.addr, self.looping_times, self.simprocedure_name))

class PendingExit(object):
    def __init__(self, returning_source, state, bbl_stack, call_stack):
        """
        PendingExit is whatever will be put into our pending_exit list. A pending exit is an entry that created by the
        returning of a call or syscall. It is "pending" since we cannot immediately figure out whether this entry will
        be executed or not. If the corresponding call/syscall intentially doesn't return, then the pending exit will be
        removed. If the corresponding call/syscall returns, then the pending exit will be removed as well (since a real
        entry is created from the returning and will be analyzed later). If the corresponding call/syscall might
        return, but for some reason (for example, an unsupported instruction is met during the analysis) our analysis
        does not return properly, then the pending exit will be picked up and put into remaining_entries list.

        :param returning_source: Address of the callee function. It might be None if address of the callee is not
                                resolvable.
        :param state: The state after returning from the callee function. Of course there is no way to get a precise
                    state without emulating the execution of the callee, but at least we can properly adjust the stack
                    and registers to imitate the real returned state.
        :param bbl_stack: Basib block stack
        :param call_stack: Callstack
        """

        self.returning_source = returning_source
        self.state = state
        self.bbl_stack = bbl_stack
        self.call_stack = call_stack

    def __repr__(self):
        return "<PendingExit to %s, from function %s>" % (self.state.ip,
                                      hex(self.returning_source) if self.returning_source is not None else 'Unknown')

class CFG(Analysis, CFGBase):
    '''
    This class represents a control-flow graph.
    '''
    def __init__(self, context_sensitivity_level=1,
                 start=None,
                 avoid_runs=None,
                 enable_function_hints=False,
                 call_depth=None,
                 call_tracing_filter=None,
                 initial_state=None,
                 starts=None,
                 keep_input_state=False,
                 enable_advanced_backward_slicing=False,
                 enable_symbolic_back_traversal=False,
                 additional_edges=None,
                 no_construct=False
                ):
        '''
        All of these parameters are optional.
        :param context_sensitivity_level: The level of context-sensitivity of this CFG.
                                        It ranges from 0 to infinity. Default 1.
        :param avoid_runs: a list of runs to avoid
        :param enable_function_hints: whether to use function hints or now
        :param call_depth: How deep in the call stack to trace
        :param call_tracing_filter: ??? what the hell is this
        :param initial_state: An initial state to use to begin analysis
        :param starts: A list of addresses at which to begin analysis
        :param keep_input_state: Whether to keep the SimStates for each CFGNode
        :param enable_advanced_backward_slicing
        :param enable_symbolic_back_traversal
        :param additional_edges: a dict mapping addresses of basic blocks to addresses of
                            successors to manually include and analyze forward from.
        :param no_construct: Skip the construction procedure. Only used in unit-testing.
        '''
        CFGBase.__init__(self, self.project, context_sensitivity_level)
        self._symbolic_function_initial_state = {}
        self._function_input_states = None
        self._loop_back_edges_set = set()

        self._unresolvable_runs = set()

        if start is not None:
            l.warning("`start` is deprecated. Please consider using `starts` instead in your code.")
            self._starts = (start,)
        else:
            if isinstance(starts, (list, set)):
                self._starts = tuple(starts)
            elif isinstance(starts, tuple) or starts is None:
                self._starts = starts
            else:
                raise AngrCFGError('Unsupported type of the `starts` argument.')

        self._avoid_runs = avoid_runs
        self._enable_function_hints = enable_function_hints
        self._call_depth = call_depth
        self._call_tracing_filter = call_tracing_filter
        self._initial_state = initial_state
        self._keep_input_state = keep_input_state
        self._enable_advanced_backward_slicing = enable_advanced_backward_slicing
        self._enable_symbolic_back_traversal = enable_symbolic_back_traversal
        self._additional_edges = additional_edges if additional_edges else { }

        # Sanity checks

        if isinstance(self._additional_edges, (list, set, tuple)):
            new_dict = defaultdict(list)
            for s, d in self._additional_edges:
                new_dict[s].append(d)
            self._additional_edges = new_dict
        elif isinstance(self._additional_edges, dict):
            pass
        else:
            raise AngrCFGError('Additional edges can only be a list, set, tuple, or a dict.')

        if self._enable_advanced_backward_slicing and self._enable_symbolic_back_traversal:
            raise AngrCFGError('Advanced backward slicing and symbolic back traversal cannot both be enabled.')

        if self._enable_advanced_backward_slicing and not self._keep_input_state:
            raise AngrCFGError('Keep input state must be enabled if advanced backward slicing is enabled.')

        # Addresses of basic blocks who has an indirect jump as their default exit
        self.resolved_indirect_jumps = set()
        self.unresolved_indirect_jumps = set()

        self._executable_address_ranges = [ ]
        self._initialize_executable_ranges()

        if not no_construct:
            self._construct()

    def copy(self):
        # Create a new instance of CFG without calling the __init__ method of CFG class
        new_cfg = CFG.__new__(CFG)
        new_cfg.named_errors = dict(self.named_errors)
        new_cfg.errors = list(self.errors)
        new_cfg.log = list(self.log)
        new_cfg._fail_fast = self._fail_fast
        new_cfg.project = self.project

        # Intelligently (or stupidly... you tell me) fill it up
        new_cfg._graph = networkx.DiGraph(self._graph)
        new_cfg._nodes = self._nodes.copy()
        new_cfg._edge_map = self._edge_map.copy()
        new_cfg._loop_back_edges_set = self._loop_back_edges_set.copy()
        new_cfg._loop_back_edges = self._loop_back_edges[::]
        new_cfg._overlapped_loop_headers = self._overlapped_loop_headers[::]
        new_cfg._function_manager = self._function_manager
        new_cfg._thumb_addrs = self._thumb_addrs.copy()
        new_cfg.project = self.project
        new_cfg.resolved_indirect_jumps = self.resolved_indirect_jumps.copy()
        new_cfg.unresolved_indirect_jumps = self.unresolved_indirect_jumps.copy()

        return new_cfg

    @property
    def unresolvables(self):
        '''
        Get those SimRuns that have non-resolvable exits
        :return:
        '''
        return self._unresolvable_runs

    @property
    def deadends(self):
        """
        Returns all CFGNodes that has an out-degree of 0
        """
        if self.graph is None:
            raise AngrCFGError('CFG hasn\'t been generated yet.')

        deadends = [i for i in self.graph if self.graph.out_degree(i) == 0]

        return deadends

    def _push_unresolvable_run(self, simrun_address):
        self._unresolvable_runs.add(simrun_address)

    def _initialize_executable_ranges(self):
        """
        Collect all executable sections.
        """

        for b in self.project.loader.all_objects:
            for seg in b.segments:
                if seg.is_executable:
                    min_addr = seg.min_addr + b.rebase_addr
                    max_addr = seg.max_addr + b.rebase_addr
                    self._executable_address_ranges.append((min_addr, max_addr))

    def _construct(self):
        '''
        Construct the CFG.

        Fastpath means the CFG generation will work in an IDA-like way, in
        which it will not try to execute every single statement in the emulator,
        but will just do the decoding job. This is much faster than the old
        way.
        '''

        avoid_runs = [ ] if self._avoid_runs is None else self._avoid_runs

        # Create the function manager
        self._function_manager = angr.FunctionManager(self.project, self)

        # Save input states of functions. It will be discarded at the end of this function.
        self._function_input_states = { }

        self._initialize_cfg()

        # Traverse all the IRSBs, and put the corresponding CFGNode objects to a dict
        # It's actually a multi-dict, as we care about contexts.
        self._nodes = { }
        if self._starts is None:
            entry_points = (self.project.entry, )
        else:
            entry_points = self._starts

        l.debug('CFG construction begins')

        remaining_entries = [ ]
        # Counting how many times a basic block is traced into
        traced_sim_blocks = defaultdict(lambda: defaultdict(int))

        # Crawl the binary, create CFG and fill all the refs inside project!
        for ep in entry_points:
            jumpkind = None
            if isinstance(ep, tuple):
                # We support tuples like (addr, jumpkind)
                ep, jumpkind = ep # pylint: disable=unpacking-non-sequence

            if self._initial_state is None:
                loaded_state = self.project.factory.entry_state(mode="fastpath")
            else:
                loaded_state = self._initial_state
                loaded_state.set_mode('fastpath')
            loaded_state.ip = loaded_state.se.BVV(ep, self.project.arch.bits)
            if jumpkind is not None:
                loaded_state.scratch.jumpkind = jumpkind

            new_state_info = None

            # THIS IS A HACK FOR MIPS and ALSO PPC64
            if ep is not None and self.project.arch.name in ('MIPS32', 'MIPS64'):
                # We assume this is a function start
                new_state_info = {'t9': loaded_state.se.BVV(ep, 32)}
            elif ep is not None and self.project.arch.name == 'PPC64':
                # Still assuming this is a function start
                new_state_info = {'r2': loaded_state.registers.load('r2')}

            loaded_state = self.project.arch.prepare_state(loaded_state, new_state_info)
            self._symbolic_function_initial_state[ep] = loaded_state

            entry_point_path = self.project.factory.path(loaded_state.copy())
            path_wrapper = EntryWrapper(entry_point_path, self._context_sensitivity_level)

            remaining_entries.append(path_wrapper)
            # traced_sim_blocks[path_wrapper.call_stack_suffix()][ep] = 1

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
        self.return_target_sources = defaultdict(list)
        # A dict that collects essential parameters to properly reconstruct initial state for a SimRun
        simrun_info_collection = { }

        pending_function_hints = set()

        analyzed_addrs = set()

        non_returning_functions = set()

        # Iteratively analyze every exit
        while len(remaining_entries) > 0:
            entry_wrapper = remaining_entries.pop()
            # Process the popped exit
            self._handle_entry(entry_wrapper, remaining_entries,
                              exit_targets, pending_exits,
                              traced_sim_blocks, self.return_target_sources,
                              avoid_runs, simrun_info_collection,
                              pending_function_hints, analyzed_addrs,
                              non_returning_functions)

            if not len(remaining_entries) and len(pending_exits):
                # There are not remaining entries, but only pending exits left. Each pending exit corresponds to a
                # previous entry that does not return properly.

                # Now it's a good time to analyze each function (that we have so far) and determine if it is a)
                # returning, b) not returning, or c) unknonwn. For those functions that are definitely not returning,
                # remove the corresponding pending exits from `pending_exits` array. Perform this procedure iteratively
                # until no new not-returning functions appear. Then we pick a pending exit based on the following
                # priorities:
                # - Entry pended by a returning function
                # - Entry pended by an unknown function

                while True:
                    new_changes = self._analyze_function_features()
                    if not new_changes['functions_do_not_return']:
                        break

                self._clean_pending_exits(pending_exits)

            while len(remaining_entries) == 0 and len(pending_exits) > 0:
                # We don't have any exits remaining. Let's pop out a pending exit

                pending_exit_tuple = pending_exits.keys()[0]
                pending_exit = pending_exits.pop(pending_exit_tuple)
                pending_exit_state = pending_exit.state
                pending_exit_call_stack = pending_exit.call_stack
                pending_exit_bbl_stack = pending_exit.bbl_stack

                pending_exit_addr = self._simrun_key_addr(pending_exit_tuple)
                # Let's check whether this address has been traced before.
                if any(r == pending_exit_tuple for r in exit_targets):
                    # That block has been traced before. Let's forget about it
                    l.debug("Target 0x%08x has been traced before." + \
                            "Trying the next one...", pending_exit_addr)
                    continue

                # FIXME: Remove these assertions
                assert pending_exit_state.se.exactly_n_int(pending_exit_state.ip, 1)[0] == pending_exit_addr
                assert pending_exit_state.scratch.jumpkind == 'Ijk_FakeRet'

                # pretend it's a Ret jump now
                pending_exit_state.scratch.jumpkind = 'Ijk_Ret'

                new_path = self.project.factory.path(pending_exit_state)
                new_path_wrapper = EntryWrapper(new_path,
                                                  self._context_sensitivity_level,
                                                  call_stack=pending_exit_call_stack,
                                                  bbl_stack=pending_exit_bbl_stack)
                remaining_entries.append(new_path_wrapper)
                l.debug("Tracing a missing retn exit %s", self._simrun_key_repr(pending_exit_tuple))
                break

            if len(remaining_entries) == 0 and len(pending_exits) == 0 and len(pending_function_hints) > 0:
                # Function hints!
                # Now let's look at how many new functions we can get here...
                while pending_function_hints:
                    f = pending_function_hints.pop()
                    if f not in analyzed_addrs:
                        new_state = self.project.factory.entry_state('fastpath')
                        new_state.ip = new_state.se.BVV(f, self.project.arch.bits)

                        # TOOD: Specially for MIPS
                        if new_state.arch.name in ('MIPS32', 'MIPS64'):
                            # Properly set t9
                            new_state.registers.store('t9', f)

                        new_path = self.project.factory.path(new_state)
                        new_path_wrapper = EntryWrapper(new_path,
                                                       self._context_sensitivity_level)
                        remaining_entries.append(new_path_wrapper)
                        l.debug('Picking a function 0x%x from pending function hints.', f)
                        self._function_manager._create_function_if_not_exist(new_path_wrapper.current_function_address)
                        break

        # Create CFG
        self._graph = self._create_graph(return_target_sources=self.return_target_sources)

        # Remove those edges that will never be taken!
        self._remove_non_return_edges()

        # Perform function calling convention analysis
        self._analyze_calling_conventions()

        # Normalize all loop backedges
        self._normalize_loop_backedges()

        # Discard intermediate state dicts
        self._function_input_states = None

    def _create_graph(self, return_target_sources=None):
        """
        Create a DiGraph out of the existing edge map. Meanwhile, update transition map of each function in function
        manager.

        :param return_target_sources: Used for making up those missing returns
        :return: A networkx.DiGraph() object
        """

        exit_targets = self._edge_map

        if return_target_sources is None:
            # We set it to a defaultdict in order to be consistent with the
            # actual parameter.`
            return_target_sources = defaultdict(list)

        cfg = networkx.DiGraph()
        # The corner case: add a node to the graph if there is only one block
        if len(self._nodes) == 1:
            cfg.add_node(self._nodes.values()[0])

        # Clear the transition graph of each function first
        for f in self.function_manager.functions.values():
            f.clear_transition_graph()

        # Adding edges
        for tpl, targets in exit_targets.iteritems():

            src_node = self._nodes[tpl] # Cannot fail :)

            for target in targets:
                node_key, jumpkind, exit_stmt_idx = target
                if node_key not in self._nodes:
                    # Generate a PathTerminator node
                    # pt = simuvex.procedures.SimProcedures["stubs"]["PathTerminator"](self.project.factory.entry_state(), addr=ex[-1])
                    addr = self._simrun_key_addr(node_key)
                    pt = CFGNode(callstack_key=self._simrun_key_callstack_key(node_key),
                                 addr=self._simrun_key_addr(node_key),
                                 size=None,
                                 cfg=self,
                                 input_state=None,
                                 simprocedure_name="PathTerminator",
                                 function_address=self._simrun_key_addr(node_key))
                    if self._keep_input_state:
                        # We don't have an input state available for it (otherwise we won't have to create a
                        # PathTerminator). This is just a trick to make get_any_irsb() happy.
                        pt.input_state = self.project.factory.entry_state()
                        pt.input_state.ip = pt.addr
                    self._nodes[node_key] = pt

                    if isinstance(self.project.arch, ArchARM) and addr % 2 == 1:
                        self._thumb_addrs.add(addr)
                        self._thumb_addrs.add(addr - 1)

                    l.debug("SimRun key %s does not exist. Create a PathTerminator instead.",
                            self._simrun_key_repr(node_key))

                dest_node = self._nodes[node_key]
                cfg.add_edge(src_node, dest_node, jumpkind=jumpkind, exit_stmt_idx=exit_stmt_idx)

                ret_addr = None
                if jumpkind == 'Ijk_Call':
                    target_function = self.function_manager.function(dest_node.addr)
                    if target_function is None or target_function.returning != False:
                        ret_addr = src_node.return_target

                # Update transition graph for functions
                self._update_function_transition_graph(jumpkind,
                                                       src_node.function_address,
                                                       src_node.addr,
                                                       dest_node.function_address,
                                                       dest_node.addr,
                                                       ret_addr=ret_addr
                                                       )

                # Add edges for possibly missing returns
                if not src_node.is_syscall and src_node.addr in return_target_sources:
                    for src_irsb_key in return_target_sources[src_node.addr]:
                        if src_irsb_key in self._nodes:
                            cfg.add_edge(self._nodes[src_irsb_key],
                                           src_node, jumpkind="Ijk_Ret", exit_stmt_idx='default')

        return cfg

    def _update_function_transition_graph(self, jumpkind, src_func_addr, src_addr, dest_func_addr, dest_addr,
                                          ret_addr=None):
        """
        Update transition graphs of functions in function manager based on information passed in.

        :param jumpkind: Jumpkind.
        :param src_func_addr: Function address of source address
        :param src_addr: Source address
        :param dest_func_addr: Function address of destination address
        :param dest_addr: Destination address
        :param ret_addr: The theoretical return address for calls
        """

        # Update the transition graph of current function
        if jumpkind == "Ijk_Call":

            self._function_manager.call_to(
                function_addr=src_func_addr,
                from_addr=src_addr,
                to_addr=dest_addr,
                retn_addr=ret_addr,
                syscall=False
            )

        if jumpkind.startswith('Ijk_Sys'):

            self._function_manager.call_to(
                function_addr=src_func_addr,
                from_addr=src_addr,
                to_addr=dest_addr,
                retn_addr=src_addr, # For syscalls, they are returning to the address of themselves
                syscall=True,
            )

            self._function_manager.function(dest_addr).is_syscall = True

        elif jumpkind == 'Ijk_Ret':

            # Create a return site for current function
            self._function_manager.return_from(
                function_addr=src_func_addr,
                from_addr=src_addr,
                to_addr=dest_addr
            )

            # Create a returning edge in the caller function
            self._function_manager.return_from_call(
                function_addr=dest_func_addr,
                src_function_addr=src_func_addr,
                to_addr=dest_addr
            )

        elif jumpkind == 'Ijk_Boring':

            src_obj = self.project.loader.addr_belongs_to_object(src_addr)
            dest_obj = self.project.loader.addr_belongs_to_object(dest_addr)

            if src_obj is dest_obj:

                # It's a normal transition
                self._function_manager.transit_to(
                    function_addr=src_func_addr,
                    from_addr=src_addr,
                    to_addr=dest_addr
                )

            else:
                self._function_manager.call_to(
                    function_addr=src_func_addr,
                    from_addr=src_addr,
                    to_addr=dest_addr,
                    retn_addr=None, # TODO
                    syscall=False
                )

    def _symbolically_back_traverse(self, current_simrun, simrun_info_collection, cfg_node):

        class register_protector(object):
            def __init__(self, reg_offset, info_collection):
                self._reg_offset = reg_offset
                self._info_collection = info_collection

            def write_persistent_register(self, state):
                if state.inspect.address is None:
                    l.error('state.inspect.address is None. It will be fixed by Yan later.')
                    return

                if state.registers.load(self._reg_offset).symbolic:
                    current_run = state.inspect.address
                    if current_run in self._info_collection and \
                            not state.se.symbolic(self._info_collection[current_run][self._reg_offset]):
                        l.debug("Overwriting %s with %s", state.registers.load(self._reg_offset), self._info_collection[current_run][self._reg_offset])
                        state.registers.store(
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
        if cfg_node not in temp_cfg.nodes():
            # TODO: Figure out why this is happening
            return concrete_exits

        keep_running = True
        while len(concrete_exits) == 0 and path_length < 5 and keep_running:
            path_length += 1
            queue = [cfg_node]
            avoid = set()
            for _ in xrange(path_length):
                new_queue = []
                for n in queue:
                    successors = temp_cfg.successors(n)
                    for suc in successors:
                        jk = temp_cfg.get_edge_data(n, suc)['jumpkind']
                        if jk != 'Ijk_Ret':
                            # We don't want to trace into libraries
                            predecessors = temp_cfg.predecessors(suc)
                            avoid |= set([p.addr for p in predecessors if p is not n])
                            new_queue.append(suc)
                queue = new_queue

            if path_length <= 1:
                continue

            for n in queue:
                # Start symbolic exploration from each block
                state = self.project.factory.blank_state(addr=n.addr,
                                                          mode='symbolic',
                                                          add_options={
                                                              simuvex.o.DO_RET_EMULATION,
                                                              simuvex.o.CONSERVATIVE_READ_STRATEGY,
                                                          } | simuvex.o.resilience_options
                                                         )
                # Avoid concretization of any symbolic read address that is over a certain limit
                # TODO: test case is needed for this option

                # Set initial values of persistent regs
                if n.addr in simrun_info_collection:
                    for reg in state.arch.persistent_regs:
                        state.registers.store(reg, simrun_info_collection[n.addr][reg])
                for reg in state.arch.persistent_regs:
                    reg_protector = register_protector(reg, simrun_info_collection)
                    state.inspect.add_breakpoint('reg_write',
                                                 simuvex.BP(
                                                     simuvex.BP_AFTER,
                                                     reg_write_offset=state.arch.registers[reg][0],
                                                     action=reg_protector.write_persistent_register
                                                 )
                    )
                result = angr.surveyors.Explorer(self.project,
                                                 start=self.project.factory.path(state),
                                                 find=(current_simrun.addr, ),
                                                 avoid=avoid,
                                                 max_repeats=10,
                                                 max_depth=path_length).run()
                if result.found:
                    if not result.found[0].errored and len(result.found[0].step()) > 0:
                        # Make sure we don't throw any exception here by checking the path.errored attribute first
                        keep_running = False
                        concrete_exits.extend([ s for s in result.found[0].next_run.flat_successors ])
                        concrete_exits.extend([ s for s in result.found[0].next_run.unsat_successors ])
                if keep_running:
                    l.debug('Step back for one more run...')

        # Make sure these successors are actually concrete
        # We just use the ip, persistent registers, and jumpkind to initialize the original unsat state
        # TODO: It works for jumptables, but not for calls. We should also handle changes in sp
        new_concrete_successors = [ ]
        for c in concrete_exits:
            unsat_state = current_simrun.unsat_successors[0].copy()
            unsat_state.scratch.jumpkind = c.scratch.jumpkind
            for reg in unsat_state.arch.persistent_regs + ['ip']:
                unsat_state.registers.store(reg, c.registers.load(reg))
            new_concrete_successors.append(unsat_state)

        return new_concrete_successors

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

        if fastpath_mode_state is not None:
            fastpath_state = fastpath_mode_state
        else:
            if function_addr in self._function_input_states:
                fastpath_state = self._function_input_states[function_addr]
            else:
                raise AngrCFGError('The impossible happened. Please report to Fish.')

        symbolic_initial_state = self.project.factory.entry_state(mode='symbolic')
        if fastpath_state is not None:
            symbolic_initial_state = self.project.simos.prepare_call_state(fastpath_state,
                                                    initial_state=symbolic_initial_state)

        # Create a temporary block
        try:
            tmp_block = self.project.block(function_addr)
        except (simuvex.SimError, angr.AngrError):
            return None

        num_instr = tmp_block.instructions - 1

        symbolic_initial_state.ip = function_addr
        path = self.project.factory.path(symbolic_initial_state)
        try:
            simrun = self.project.factory.sim_run(path.state, num_inst=num_instr)
        except (simuvex.SimError, angr.AngrError):
            return None

        # We execute all but the last instruction in this basic block, so we have a cleaner
        # state
        # Start execution!
        exits = simrun.flat_successors + simrun.unsat_successors

        if exits:
            final_st = None
            for ex in exits:
                if ex.satisfiable():
                    final_st = ex
                    break
        else:
            final_st = None

        self._symbolic_function_initial_state[function_addr] = final_st

        return final_st

    def _get_simrun(self, addr, current_entry, current_function_addr=None):
        error_occurred = False
        state = current_entry.state
        saved_state = current_entry.state  # We don't have to make a copy here
        try:
            if self.project.is_hooked(addr) and \
                    not self.project._sim_procedures[addr][0] is simuvex.s_procedure.SimProcedureContinuation and \
                    not self.project._sim_procedures[addr][0].ADDS_EXITS and \
                    not self.project._sim_procedures[addr][0].NO_RET:
                # DON'T CREATE USELESS SIMPROCEDURES
                # When generating CFG, a SimProcedure will not be created as it is but be created as a
                # ReturnUnconstrained stub if it satisfies the following conditions:
                # - It doesn't add any new exits.
                # - It returns as normal.
                # In this way, we can speed up the CFG generation by quite a lot as we avoid simulating
                # those functions like read() and puts(), which has no impact on the overall control flow at all.
                #
                # Special notes about _SimProcedureContinuation_ instances. Any SimProcedure that corresponds to the
                # SimProcedureContinuation we see here adds new exits, otherwise the original SimProcedure wouldn't have
                # been executed anyway. Hence it's reasonable for us to always simulate a SimProcedureContinuation
                # instance.

                old_proc = self.project._sim_procedures[addr][0]
                if old_proc == simuvex.procedures.SimProcedures["stubs"]["ReturnUnconstrained"]:
                    old_name = self.project._sim_procedures[addr][1]['resolves']
                else:
                    old_name = old_proc.__name__.split('.')[-1]

                sim_run = simuvex.procedures.SimProcedures["stubs"]["ReturnUnconstrained"](
                    state,
                    addr=addr,
                    sim_kwargs={ 'resolves': "%s" % old_name }
                )
            else:
                jumpkind = state.scratch.jumpkind
                jumpkind = 'Ijk_Boring' if jumpkind is None else jumpkind
                sim_run = self.project.factory.sim_run(current_entry.state, jumpkind=jumpkind)

        except (simuvex.SimFastPathError, simuvex.SimSolverModeError) as ex:
            # Got a SimFastPathError. We wanna switch to symbolic mode for current IRSB.
            l.debug('Switch to symbolic mode for address 0x%x', addr)
            # Make a copy of the current 'fastpath' state

            l.debug('Symbolic jumps at basic block 0x%x.' % addr)

            new_state = None
            if addr != current_function_addr:
                new_state = self._get_symbolic_function_initial_state(current_function_addr)

            if new_state is None:
                new_state = current_entry.state.copy()
                new_state.set_mode('symbolic')
            new_state.options.add(simuvex.o.DO_RET_EMULATION)
            # Remove bad constraints
            # FIXME: This is so hackish...
            new_state.se._solver.constraints = [ c for c in new_state.se.constraints if c.op != 'I' or c.args[0] is not False ]
            new_state.se._solver._result = None
            # Swap them
            saved_state, current_entry.state = current_entry.state, new_state
            sim_run, error_occurred, _ = self._get_simrun(addr, current_entry)
        except simuvex.SimIRSBError as ex:
            # It's a tragedy that we came across some instructions that VEX
            # does not support. I'll create a terminating stub there
            l.error("SimIRSBError occurred(%s). Creating a PathTerminator.", ex)
            error_occurred = True
            sim_run = \
                simuvex.procedures.SimProcedures["stubs"]["PathTerminator"](
                    state, addr=addr)
        except claripy.ClaripyError as ex:
           l.error("ClaripyError: ", exc_info=True)
           error_occurred = True
           # Generate a PathTerminator to terminate the current path
           sim_run = \
               simuvex.procedures.SimProcedures["stubs"]["PathTerminator"](
                   state, addr=addr)
        except simuvex.SimError as ex:
            l.error("SimError: ", exc_info=True)

            error_occurred = True
            # Generate a PathTerminator to terminate the current path
            sim_run = \
                simuvex.procedures.SimProcedures["stubs"]["PathTerminator"](
                    state, addr=addr)
        except angr.errors.AngrError as ex:
            section = self.project.loader.main_bin.find_section_containing(addr)
            if section is None:
                sec_name = 'No section'
            else:
                sec_name = section.name
            l.error("AngrError %s when creating SimRun at 0x%x (%s)",
                    ex, addr, sec_name)
            # We might be on a wrong branch, and is likely to encounter the
            # "No bytes in memory xxx" exception
            # Just ignore it
            error_occurred = True
            sim_run = None

        return sim_run, error_occurred, saved_state

    def _is_address_executable(self, address):
        for r in self._executable_address_ranges:
            if address >= r[0] and address < r[1]:
                return True
        return False

    def _search_for_function_hints(self, simrun, function_hints_found=None):
        '''
        Scan for constants that might be used as exit targets later, and add
        them into pending_exits
        '''

        function_hints = [ ]
        if isinstance(simrun, simuvex.SimIRSB) and simrun.successors:
            successor = simrun.successors[0]
            for action in successor.log.actions:
                if action.type == 'reg' and action.offset == self.project.arch.ip_offset:
                    # Skip all accesses to IP registers
                    continue
                elif action.type == 'exit':
                    # only consider read/write actions
                    continue

                # Enumerate actions
                data = action.data
                if data is not None:
                    # TODO: Check if there is a proper way to tell whether this const falls in the range of code segments
                    # Now let's live with this big hack...
                    try:
                        const = successor.se.exactly_n_int(data.ast, 1)[0]
                    except: # pylint: disable=bare-except
                        continue

                    if self._is_address_executable(const):
                        if function_hints_found is not None and const in function_hints_found:
                            continue

                        #target = const
                        #tpl = (None, None, target)
                        #st = self.project.simos.prepare_call_state(self.project.initial_state(mode='fastpath'),
                        #                                           initial_state=saved_state)
                        #st = self.project.initial_state(mode='fastpath')
                        #exits[tpl] = (st, None, None)

                        function_hints.append(const)

            l.info('Got %d possible exits from %s, including: %s', len(function_hints), simrun, ", ".join(["0x%x" % f for f in function_hints]))

        return function_hints

    def _create_new_call_stack(self, addr, all_entries, entry_wrapper, exit_target, jumpkind):
        if jumpkind == "Ijk_Call" or jumpkind.startswith('Ijk_Sys'):
            new_call_stack = entry_wrapper.call_stack_copy()
            # Notice that in ARM, there are some freaking instructions
            # like
            # BLEQ <address>
            # It should give us three exits: Ijk_Call, Ijk_Boring, and
            # Ijk_Ret. The last exit is simulated.
            # Notice: We assume the last exit is the simulated one
            if len(all_entries) > 1 and all_entries[-1].scratch.jumpkind == "Ijk_FakeRet":
                se = all_entries[-1].se
                retn_target_addr = se.exactly_int(all_entries[-1].ip, default=0)
                sp = se.exactly_int(all_entries[-1].regs.sp, default=0)

                new_call_stack.call(addr, exit_target,
                                    retn_target=retn_target_addr,
                                    stack_pointer=sp)

            elif jumpkind.startswith('Ijk_Sys') and len(all_entries) == 1:
                # This is a syscall. It returns to the same address as itself (with a different jumpkind)
                retn_target_addr = exit_target
                se = all_entries[0].se
                sp = se.exactly_int(all_entries[0].regs.sp, default=0)
                new_call_stack.call(addr, exit_target,
                                    retn_target=retn_target_addr,
                                    stack_pointer=sp)

            else:
                # We don't have a fake return exit available, which means
                # this call doesn't return.
                new_call_stack.clear()
                se = all_entries[-1].se
                sp = se.exactly_int(all_entries[-1].regs.sp, default=0)

                new_call_stack.call(addr, exit_target, retn_target=None, stack_pointer=sp)

        elif jumpkind == "Ijk_Ret":
            # Normal return
            new_call_stack = entry_wrapper.call_stack_copy()
            new_call_stack.ret(exit_target)

            se = all_entries[-1].se
            sp = se.exactly_int(all_entries[-1].regs.sp, default=0)
            old_sp = entry_wrapper.current_stack_pointer

            # Calculate the delta of stack pointer
            if sp is not None and old_sp is not None:
                delta = sp - old_sp
                func_addr = entry_wrapper.current_function_address

                if self._function_manager.function(func_addr) is None:
                    # Create the function if it doesn't exist
                    # FIXME: But hell, why doesn't it exist in the first place?
                    l.error("Function 0x%x doesn't exist in function manager although it should be there." +
                            "Look into this issue later.",
                            func_addr)
                    self._function_manager._create_function_if_not_exist(func_addr)

                # Set sp_delta of the function
                self._function_manager.function(func_addr).sp_delta = delta

        elif jumpkind == 'Ijk_FakeRet':
            # The fake return...
            new_call_stack = entry_wrapper.call_stack

        else:
            # Normal control flow transition
            new_call_stack = entry_wrapper.call_stack

        return new_call_stack

    @staticmethod
    def _generate_simrun_key(call_stack_suffix, simrun_addr, is_syscall):
        if not is_syscall:
            return call_stack_suffix + (simrun_addr, 'normal' )
        else:
            return call_stack_suffix + (simrun_addr, 'syscall')

    @staticmethod
    def _simrun_key_repr(simrun_key):
        runtype = simrun_key[-1]
        addr = simrun_key[-2]

        callstack = [ ]
        for i in xrange(0, len(simrun_key) - 2, 2):
            from_ = 'None' if simrun_key[i] is None else hex(simrun_key[i])
            to_ = 'None' if simrun_key[i + 1] is None else hex(simrun_key[i + 1])
            callstack.append("%s -> %s" % (from_, to_))

        s = "(%s), %s [%s]" % (", ".join(callstack), hex(addr), runtype)
        return s

    @staticmethod
    def _simrun_key_callstack_key(simrun_key):
        return simrun_key[ : -2]

    @staticmethod
    def _simrun_key_addr(simrun_key):
        return simrun_key[-2]

    def _handle_entry(self, entry_wrapper, remaining_exits, exit_targets,
                     pending_exits, traced_sim_blocks, retn_target_sources,
                     avoid_runs, simrun_info_collection, function_hints_found,
                     analyzed_addrs, non_returning_functions):
        """
        Handles an entry.

        In static mode, we create a unique stack region for each function, and
        normalize its stack pointer to the default stack offset.
        """

        #
        # Extract initial info from entry_wrapper
        #

        current_entry = entry_wrapper.path
        call_stack_suffix = entry_wrapper.call_stack_suffix()
        addr = current_entry.addr
        current_function_addr = entry_wrapper.current_function_address
        current_stack_pointer = entry_wrapper.current_stack_pointer
        accessed_registers_in_function = entry_wrapper.current_function_accessed_registers
        current_function = self._function_manager.function(current_function_addr, create_if_not_exist=True)
        jumpkind = 'Ijk_Boring' if current_entry.state.scratch.jumpkind is None else current_entry.state.scratch.jumpkind

        # Log this address
        if l.level <= logging.DEBUG:
            analyzed_addrs.add(addr)

        if addr == current_function_addr:
            # Store the input state of this function
            self._function_input_states[current_function_addr] = current_entry.state

        #
        # Get a SimRun out of current SimExit
        #

        simrun, error_occured, _ = self._get_simrun(addr, current_entry,
            current_function_addr=current_function_addr)
        if simrun is None:
            # We cannot retrieve the SimRun...
            return

        # We store the function hints first. Function hints will be checked at the end of the analysis to avoid
        # any duplication with existing jumping targets
        if self._enable_function_hints:
            function_hints = self._search_for_function_hints(simrun, function_hints_found=function_hints_found)
            for f in function_hints:
                function_hints_found.add(f)

        # Generate a unique key for this SimRun
        simrun_key = self._generate_simrun_key(call_stack_suffix, addr, jumpkind.startswith('Ijk_Sys'))

        traced_sim_blocks[call_stack_suffix][addr] += 1

        #
        # Create the corresponding CFGNode object
        #

        # Determine whether this is a syscall
        if isinstance(simrun, simuvex.procedures.syscalls.handler.handler):
            is_syscall = True
            if simrun.syscall is not None:
                syscall = simrun.syscall.__class__.__name__
            else:
                # Unsupported syscalls
                syscall = None
        else:
            is_syscall = False
            syscall = None

        if isinstance(simrun, simuvex.SimProcedure):
            simproc_name = simrun.__class__.__name__.split('.')[-1]
            if simproc_name == "ReturnUnconstrained":
                simproc_name = simrun.resolves

            no_ret = False
            if (syscall is None and simrun.NO_RET) or (syscall is not None and simrun.syscall.NO_RET):
                no_ret = True

            cfg_node = CFGNode(call_stack_suffix,
                               simrun.addr,
                               None,
                               self,
                               input_state=None,
                               simprocedure_name=simproc_name,
                               syscall_name=syscall,
                               no_ret=no_ret,
                               is_syscall=is_syscall,
                               syscall=syscall,
                               function_address=simrun.addr)

        else:
            cfg_node = CFGNode(call_stack_suffix,
                               simrun.addr,
                               simrun.irsb.size,
                               self,
                               input_state=None,
                               is_syscall=is_syscall,
                               syscall=syscall,
                               simrun=simrun,
                               function_address=current_function_addr)

        if self._keep_input_state:
            cfg_node.input_state = simrun.initial_state

        node_key = simrun_key
        self._nodes[node_key] = cfg_node

        simrun_info = self.project.arch.gather_info_from_state(simrun.initial_state)
        simrun_info_collection[addr] = simrun_info

        # For ARM THUMB mode
        if isinstance(simrun, simuvex.SimIRSB) and current_entry.state.thumb:
            self._thumb_addrs.update(simrun.imark_addrs())
            self._thumb_addrs.update(map(lambda x: x+1, simrun.imark_addrs()))

        #
        # Get all successors of this SimRun
        #

        all_successors = (simrun.flat_successors + simrun.unsat_successors) if addr not in avoid_runs else [ ]

        if simrun.initial_state.thumb and isinstance(simrun, simuvex.SimIRSB):
            pyvex.set_iropt_level(0)
            it_counter = 0
            conc_temps = {}
            can_produce_exits = set()
            bb = self.project.factory.block(simrun.addr, thumb=True)

            for stmt in bb.vex.statements:
                if stmt.tag == 'Ist_IMark':
                    if it_counter > 0:
                        it_counter -= 1
                        can_produce_exits.add(stmt.addr)
                elif stmt.tag == 'Ist_WrTmp':
                    val = stmt.data
                    if val.tag == 'Iex_Const':
                        conc_temps[stmt.tmp] = val.con.val
                elif stmt.tag == 'Ist_Put':
                    if stmt.offset == self.project.arch.registers['itstate'][0]:
                        val = stmt.data
                        if val.tag == 'Iex_RdTmp':
                            if val.tmp in conc_temps:
                                # We found an IT instruction!!
                                # Determine how many instructions are conditional
                                it_counter = 0
                                itstate = conc_temps[val.tmp]
                                while itstate != 0:
                                    it_counter += 1
                                    itstate >>= 8

            if it_counter != 0:
                l.error('Basic block ends before calculated IT block (%#x)', simrun.addr)

            THUMB_BRANCH_INSTRUCTIONS = ('beq', 'bne', 'bcs', 'bhs', 'bcc', 'blo', 'bmi', 'bpl', 'bvs',
                                         'bvc', 'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble', 'cbz', 'cbnz')
            for cs_insn in bb.capstone.insns:
                if cs_insn.mnemonic in THUMB_BRANCH_INSTRUCTIONS:
                    can_produce_exits.add(cs_insn.address)

            all_successors = filter(lambda state: state.scratch.ins_addr in can_produce_exits or \
                                                  state.scratch.stmt_idx == simrun.num_stmts,
                                    all_successors)

        if self._keep_input_state:
            cfg_node.final_states = all_successors[::]

        # If there is a call exit, we shouldn't put the default exit (which
        # is artificial) into the CFG. The exits will be Ijk_Call and
        # Ijk_FakeRet, and Ijk_Call always goes first
        extra_info = { 'is_call_jump' : False,
                       'call_target': None,
                       'return_target': None,
                       'last_call_exit_target': None,
                       'skip_fakeret': False,
        }

        # Post-process jumpkind before touching all_successors
        for suc in all_successors:
            suc_jumpkind = suc.scratch.jumpkind
            if suc_jumpkind == "Ijk_Call" or suc_jumpkind.startswith('Ijk_Sys'):
                extra_info['is_call_jump'] = True

        #
        # Try to resolve indirect jumps
        #

        # Try to resolve indirect jumps with advanced backward slicing (if enabled)
        if isinstance(simrun, simuvex.SimIRSB) and \
                self._is_indirect_jump(cfg_node, simrun):
            l.debug('IRSB 0x%x has an indirect jump as its default exit', simrun.addr)

            # Throw away all current paths whose target doesn't make sense
            old_successors = all_successors[ :: ]
            all_successors = [ ]
            for i, suc in enumerate(old_successors):

                if suc.se.symbolic(suc.ip):
                    # It's symbolic. Take it, and hopefully we can resolve it later
                    all_successors.append(suc)

                else:
                    # It's concrete. Does it make sense?
                    ip_int = suc.se.exactly_int(suc.ip)

                    if self._is_address_executable(ip_int) or \
                            self.project.is_hooked(ip_int):
                        all_successors.append(suc)

                    else:
                        l.info('%s: an obviously incorrect successor %d/%d (%#x) is ditched',
                                cfg_node,
                                i + 1, len(old_successors),
                                ip_int)

            # We need input states to perform backward slicing
            if self._enable_advanced_backward_slicing and self._keep_input_state:
                # TODO: Handle those successors
                more_successors = self._resolve_indirect_jump(cfg_node, simrun)

                if len(more_successors):
                    # Remove the symbolic successor
                    # TODO: Now we are removing all symbolic successors. Is it possible
                    # TODO: that there is more than one symbolic successor?
                    all_successors = [ suc for suc in all_successors if
                                       not suc.se.symbolic(suc.ip) ]
                    # Insert new successors
                    # We insert new successors in the beginning of all_successors list so that we don't break the
                    # assumption that Ijk_FakeRet is always the last element in the list
                    for suc_addr in more_successors:
                        a = simrun.default_exit.copy()
                        a.ip = suc_addr
                        all_successors.insert(0, a)

                    l.debug('The indirect jump is successfully resolved.')

                    self.resolved_indirect_jumps.add(simrun.addr)

                else:
                    l.debug('We failed to resolve the indirect jump.')
                    self.unresolved_indirect_jumps.add(simrun.addr)

            else:
                if not all_successors:
                    l.debug('We cannot resolve the indirect jump without advanced backward slicing enabled: %s', cfg_node)

        # Try to find more successors if we failed to resolve the indirect jump before
        if not error_occured and (cfg_node.is_simprocedure or self._is_indirect_jump(cfg_node, simrun)):
            has_call_jumps = any([suc_state.scratch.jumpkind == 'Ijk_Call' for suc_state in all_successors])
            if has_call_jumps:
                concrete_successors = [suc_state for suc_state in all_successors if
                                       suc_state.scratch.jumpkind != 'Ijk_FakeRet' and not suc_state.se.symbolic(
                                           suc_state.ip)]
            else:
                concrete_successors = [suc_state for suc_state in all_successors if
                                       not suc_state.se.symbolic(suc_state.ip)]
            symbolic_successors = [suc_state for suc_state in all_successors if suc_state.se.symbolic(suc_state.ip)]

            resolved = len(symbolic_successors) == 0
            if len(symbolic_successors) > 0:
                for suc in symbolic_successors:
                    if simuvex.o.SYMBOLIC in suc.options:
                        targets = suc.se.any_n_int(suc.ip, 32)
                        if len(targets) < 32:
                            all_successors = []
                            resolved = True
                            for t in targets:
                                new_ex = suc.copy()
                                new_ex.ip = suc.se.BVV(t, suc.ip.size())
                                all_successors.append(new_ex)
                        else:
                            break

            if not resolved and (
                        (len(symbolic_successors) > 0 and len(concrete_successors) == 0) or
                        (not cfg_node.is_simprocedure and self._is_indirect_jump(cfg_node, simrun))
            ):
                l.debug("%s has an indirect jump. See what we can do about it.", cfg_node)

                if isinstance(simrun, simuvex.SimProcedure) and \
                        simrun.ADDS_EXITS:
                    # Skip those SimProcedures that don't create new SimExits
                    l.debug('We got a SimProcedure %s in fastpath mode that creates new exits.', simrun)
                    if self._enable_symbolic_back_traversal:
                        all_successors = self._symbolically_back_traverse(simrun, simrun_info_collection, cfg_node)
                        # mark jump as resolved if we got successors
                        if len(all_successors):
                            self.resolved_indirect_jumps.add(simrun.addr)
                        else:
                            self.unresolved_indirect_jumps.add(simrun.addr)
                        l.debug("Got %d concrete exits in symbolic mode.", len(all_successors))
                    else:
                        self.unresolved_indirect_jumps.add(simrun.addr)
                        all_successors = [ ]

                elif isinstance(simrun, simuvex.SimIRSB) and \
                        any([ex.scratch.jumpkind != 'Ijk_Ret' for ex in all_successors]):
                    # We cannot properly handle Return as that requires us start execution from the caller...
                    l.debug("Try traversal backwards in symbolic mode on %s.", cfg_node)
                    if self._enable_symbolic_back_traversal:
                        all_successors = self._symbolically_back_traverse(simrun, simrun_info_collection, cfg_node)

                        # Remove successors whose IP doesn't make sense
                        all_successors = [ suc for suc in all_successors
                                           if self._is_address_executable(suc.se.exactly_int(suc.ip)) ]

                        # mark jump as resolved if we got successors
                        if len(all_successors):
                            self.resolved_indirect_jumps.add(simrun.addr)
                        else:
                            self.unresolved_indirect_jumps.add(simrun.addr)
                        l.debug('Got %d concrete exits in symbolic mode', len(all_successors))
                    else:
                        self.unresolved_indirect_jumps.add(simrun.addr)
                        all_successors = [ ]

                elif len(all_successors) > 0 and all([ex.scratch.jumpkind == 'Ijk_Ret' for ex in all_successors ]):
                    l.debug('All exits are returns (Ijk_Ret). It will be handled by pending exits.')

                else:
                    l.warning('It seems that we cannot resolve this indirect jump: %s', cfg_node)
                    self.unresolved_indirect_jumps.add(simrun.addr)

        # If we have additional edges for this simrun, add them in
        if addr in self._additional_edges:
            dests = self._additional_edges[addr]
            for dst in dests:
                if isinstance(simrun, simuvex.SimIRSB):
                    base_state = simrun.default_exit.copy()
                else:
                    if all_successors:
                        # We try to use the first successor.
                        base_state = all_successors[0].copy()
                    else:
                        # The SimProcedure doesn't have any successor (e.g. it's a PathTerminator)
                        # We'll use its input state instead
                        base_state = simrun.initial_state
                base_state.ip = dst
                # TODO: Allow for sp adjustments
                all_successors.append(base_state)
                l.debug("Additional jump target 0x%x for simrun %s is appended.", dst, simrun)

        if len(all_successors) == 0:
            # There is no way out :-(
            # Log it first
            self._push_unresolvable_run(addr)

            if isinstance(simrun,
                          simuvex.procedures.SimProcedures["stubs"]["PathTerminator"]):
                # If there is no valid exit in this branch and it's not
                # intentional (e.g. caused by a SimProcedure that does not
                # do_return) , we should make it return to its callsite. However,
                # we don't want to use its state anymore as it might be corrupted.
                # Just create a link in the exit_targets map.
                retn_target = entry_wrapper.call_stack.get_ret_target()
                if retn_target is not None:
                    new_call_stack = entry_wrapper.call_stack_copy()
                    exit_target_tpl = self._generate_simrun_key(
                        new_call_stack.stack_suffix(self.context_sensitivity_level),
                        retn_target,
                        False
                    ) # You can never return to a syscall
                    exit_targets[simrun_key].append((exit_target_tpl, 'Ijk_Ret', 'default'))

            else:
                # Well, there is just no successors. What can you expect?
                pass

        #
        # First, handle all actions
        #

        if all_successors:
            self._handle_actions(all_successors[0], simrun, current_function, current_stack_pointer,
                                 accessed_registers_in_function)

        if all_successors:
            # Special case: Add a fakeret successor for Ijk_Sys_*
            if all_successors[0].scratch.jumpkind.startswith('Ijk_Sys'):
                # This is a syscall!
                copied_successor = all_successors[0].copy()
                copied_successor.scratch.jumpkind = 'Ijk_FakeRet'
                all_successors.append(copied_successor)

        # For debugging purposes!
        successor_status = { }

        #
        # Then handles each successor state
        #
        for successor_state in all_successors:
            path_wrapper = self._handle_successor_state(simrun, simrun_key, addr, current_function_addr,
                                                        successor_state, all_successors, entry_wrapper, pending_exits,
                                                        retn_target_sources, traced_sim_blocks, extra_info,
                                                        call_stack_suffix, exit_targets, successor_status)

            if extra_info['is_call_jump'] and extra_info['call_target'] in non_returning_functions:
                extra_info['skip_fakeret'] = True

            if path_wrapper:
                remaining_exits.append(path_wrapper)

        # Post-process CFG Node and log the return target
        if extra_info['is_call_jump'] and extra_info['return_target'] is not None:
            cfg_node.return_target = extra_info['return_target']

        #
        # Debugging output
        #

        if l.level <= logging.DEBUG:
            # Only in DEBUG mode do we process and output all those shit

            function_name = self.project.loader.find_symbol_name(simrun.addr)
            module_name = self.project.loader.find_module_name(simrun.addr)

            l.debug("Basic block %s %s", simrun, "->".join([hex(i) for i in call_stack_suffix if i is not None]))
            l.debug("(Function %s of binary %s)", function_name, module_name)
            l.debug("|    Call jump: %s", extra_info['is_call_jump'])

            for suc in all_successors:
                jumpkind = suc.scratch.jumpkind
                if jumpkind == "Ijk_FakeRet":
                    exit_type_str = "Simulated Ret"
                else:
                    exit_type_str = "-"
                try:
                    l.debug("|    target: 0x%08x %s [%s] %s", suc.se.exactly_int(suc.ip), successor_status[suc], exit_type_str, jumpkind)
                except (simuvex.SimValueError, simuvex.SimSolverModeError):
                    l.debug("|    target cannot be concretized. %s [%s] %s", successor_status[suc], exit_type_str, jumpkind)
            l.debug("%d exits remaining, %d exits pending.", len(remaining_exits), len(pending_exits))
            l.debug("%d unique basic blocks are analyzed so far.", len(analyzed_addrs))

    def _handle_successor_state(self,
                                simrun,
                                simrun_key,
                                addr,
                                current_function_addr,
                                state,
                                all_successor_states,
                                entry_wrapper,
                                pending_exits,
                                retn_target_sources,
                                traced_sim_blocks,
                                extra_info,
                                call_stack_suffix,
                                exit_targets,
                                successor_status):
        """
        Returns a new PathWrapper instance for further analysis, or None if there is no immediate state to perform the
        analysis on.
        """

        # The PathWrapper instance to return
        pw = None

        successor_status[state] = ""

        new_initial_state = state.copy()
        suc_jumpkind = state.scratch.jumpkind
        suc_exit_stmt_idx = state.scratch.exit_stmt_idx

        if suc_jumpkind in {'Ijk_EmWarn', 'Ijk_NoDecode', 'Ijk_MapFail',
                            'Ijk_InvalICache', 'Ijk_NoRedir', 'Ijk_SigTRAP',
                            'Ijk_SigSEGV', 'Ijk_ClientReq'}:
            # Ignore SimExits that are of these jumpkinds
            successor_status[state] = "Skipped"
            return

        if suc_jumpkind == "Ijk_FakeRet" and extra_info['call_target'] is not None:
            # if the call points to a SimProcedure that doesn't return, we don't follow the fakeret anymore
            if self.project.is_hooked(extra_info['call_target']):
                sim_proc = self.project._sim_procedures[extra_info['call_target']][0]
                if sim_proc.NO_RET:
                    return

        exit_target = None
        try:
            exit_target = state.se.exactly_n_int(state.ip, 1)[0]
        except (simuvex.SimValueError, simuvex.SimSolverModeError):
            # It cannot be concretized currently. Maybe we could handle
            # it later, maybe it just cannot be concretized
            if suc_jumpkind == "Ijk_Ret":
                exit_target = entry_wrapper.call_stack.get_ret_target()
                if exit_target is not None:
                    new_initial_state.ip = new_initial_state.BVV(exit_target)
                else:
                    return
            else:
                return

        if exit_target is None:
            return

        if state.thumb:
            # Make sure addresses are always odd. It is important to encode this information in the address for the time being.
            exit_target |= 1

        if (extra_info['is_call_jump'] and
                (suc_jumpkind == 'Ijk_Call' or suc_jumpkind.startswith('Ijk_Sys'))):
            extra_info['call_target'] = exit_target

        if (extra_info['is_call_jump'] and
                suc_jumpkind == 'Ijk_FakeRet'):
            extra_info['return_target'] = exit_target

        # Remove pending targets - type 2
        tpl = self._generate_simrun_key((None, None), exit_target, suc_jumpkind.startswith('Ijk_Suc')) # TODO: Support other context_sensitivity levels other than 2
        if tpl in pending_exits:
            l.debug("Removing pending exits (type 2) to %s", hex(exit_target))
            del pending_exits[tpl]

        if suc_jumpkind == "Ijk_Call":
            extra_info['last_call_exit_target'] = exit_target

        elif suc_jumpkind == "Ijk_FakeRet":
            if exit_target == extra_info['last_call_exit_target']:
                l.debug("... skipping a fake return exit that has the same target with its call exit.")
                successor_status[state] = "Skipped"
                return

            if extra_info['skip_fakeret']:
                l.debug('... skipping a fake return exit since the function it\'s calling doesn\'t return')
                successor_status[state] = "Skipped - non-returning function 0x%x" % extra_info['call_target']
                return

        # TODO: Make it optional
        if (suc_jumpkind == 'Ijk_Ret' and
                self._call_depth is not None and
                len(entry_wrapper.call_stack) <= 1
            ):
                # We cannot continue anymore since this is the end of the function where we started tracing
                l.debug('... reaching the end of the starting function, skip.')
                successor_status[state] = "Skipped - reaching the end of the starting function"
                return

        # Create the new call stack of target block
        new_call_stack = self._create_new_call_stack(addr, all_successor_states,
                                                     entry_wrapper,
                                                     exit_target,
                                                     suc_jumpkind)
        # Create the callstack suffix
        new_call_stack_suffix = new_call_stack.stack_suffix(self._context_sensitivity_level)
        # Tuple that will be used to index this exit
        new_tpl = self._generate_simrun_key(new_call_stack_suffix, exit_target, suc_jumpkind.startswith('Ijk_Sys'))

        if isinstance(simrun, simuvex.SimIRSB):
            self._detect_loop(simrun,
                              new_tpl,
                              exit_targets,
                              simrun_key,
                              new_call_stack_suffix,
                              exit_target,
                              suc_jumpkind,
                              entry_wrapper,
                              current_function_addr)

        # Generate the new BBL stack of target block
        if suc_jumpkind == "Ijk_Call" or suc_jumpkind.startswith('Ijk_Sys'):
            new_bbl_stack = entry_wrapper.bbl_stack_copy()
            new_bbl_stack.call(new_call_stack_suffix, exit_target)
            new_bbl_stack.push(new_call_stack_suffix, exit_target, exit_target)
        elif suc_jumpkind == "Ijk_Ret":
            new_bbl_stack = entry_wrapper.bbl_stack_copy()
            new_bbl_stack.ret(call_stack_suffix, current_function_addr)
        elif suc_jumpkind == "Ijk_FakeRet":
            new_bbl_stack = entry_wrapper.bbl_stack_copy()
        else:
            new_bbl_stack = entry_wrapper.bbl_stack_copy()
            new_bbl_stack.push(new_call_stack_suffix, current_function_addr, exit_target)

        # Generate new exits
        if suc_jumpkind == "Ijk_Ret":

            # This is the real return exit
            # Remember this retn!
            retn_target_sources[exit_target].append(simrun_key)
            # Check if this retn is inside our pending_exits set
            if new_tpl in pending_exits:
                del pending_exits[new_tpl]

            if traced_sim_blocks[new_call_stack_suffix][exit_target] < 1:
                new_path = self.project.factory.path(new_initial_state)
                pw = EntryWrapper(new_path,
                                  self._context_sensitivity_level,
                                  call_stack=new_call_stack,
                                  bbl_stack=new_bbl_stack
                                )
                successor_status[state] = "Appended"

            else:
                # Skip it
                successor_status[state] = "Skipped"

        elif suc_jumpkind == "Ijk_FakeRet":
            # This is the default "fake" retn that generated at each
            # call. Save them first, but don't process them right
            # away
            # st = self.project.simos.prepare_call_state(new_initial_state, initial_state=saved_state)
            st = new_initial_state
            st.set_mode('fastpath')

            pe = PendingExit(extra_info['call_target'], st, new_bbl_stack, new_call_stack)
            pending_exits[new_tpl] = pe
            successor_status[state] = "Pended"

        elif (suc_jumpkind == 'Ijk_Call' or suc_jumpkind.startswith('Ijk_Sys')) and \
               (self._call_depth is not None and
                len(new_call_stack) > self._call_depth and
                     (
                        self._call_tracing_filter is None or
                        self._call_tracing_filter(state, suc_jumpkind)
                     )
                 ):
            # We skip this call
            successor_status[state] = "Skipped"
        elif traced_sim_blocks[new_call_stack_suffix][exit_target] < 1:
            new_path = self.project.factory.path(new_initial_state)

            # We might have changed the mode for this basic block
            # before. Make sure it is still running in 'fastpath' mode
            # new_exit.state = self.project.simos.prepare_call_state(new_exit.state, initial_state=saved_state)
            new_path.state.set_mode('fastpath')

            pw = EntryWrapper(new_path,
                            self._context_sensitivity_level,
                            call_stack=new_call_stack,
                            bbl_stack=new_bbl_stack)
            successor_status[state] = "Appended"
        elif traced_sim_blocks[new_call_stack_suffix][exit_target] >= 1 \
                and suc_jumpkind == "Ijk_Ret":
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

        exit_targets[simrun_key].append((new_tpl, suc_jumpkind, suc_exit_stmt_idx))

        return pw

    def _handle_actions(self, state, current_run, func, sp_addr, accessed_registers):
        se = state.se

        if func is not None and sp_addr is not None:

            # Fix the stack pointer (for example, skip the return address on the stack)
            new_sp_addr = sp_addr + self.project.arch.call_sp_fix

            actions = [ a for a in state.log.actions if a.bbl_addr == current_run.addr ]

            for a in actions:
                if a.type == "mem" and a.action == "read":
                    addr = se.exactly_int(a.addr.ast, default=0)
                    if (self.project.arch.call_pushes_ret and addr >= new_sp_addr) or \
                            (not self.project.arch.call_pushes_ret and addr >= new_sp_addr):
                        # TODO: What if a variable locates higher than the stack is modified as well? We probably want
                        # to make sure the accessing address falls in the range of stack
                        offset = addr - new_sp_addr
                        func.add_argument_stack_variable(offset)
                elif a.type == "reg":
                    offset = a.offset
                    if a.action == "read" and offset not in accessed_registers:
                        func.add_argument_register(offset)
                    elif a.action == "write":
                        accessed_registers.add(offset)
        else:
            l.error("handle_actions: Function not found, or stack pointer is None. It might indicates unbalanced stack.")

    def _detect_loop(self, sim_run, new_tpl, exit_targets,
                     simrun_key, new_call_stack_suffix,
                     new_addr, new_jumpkind, current_exit_wrapper,
                     current_function_addr):
        # Loop detection
        assert isinstance(sim_run, simuvex.SimIRSB)

        if new_jumpkind.startswith("Ijk_Sys"):
            return

        # Loop detection only applies to SimIRSBs
        # The most f****** case: An IRSB branches to itself
        if new_tpl == simrun_key:
            l.debug("%s is branching to itself. That's a loop.", sim_run)
            if (sim_run.addr, sim_run.addr) not in self._loop_back_edges_set:
                self._loop_back_edges_set.add((sim_run.addr, sim_run.addr))
                self._loop_back_edges.append((simrun_key, new_tpl))
        elif new_jumpkind != "Ijk_Call" and new_jumpkind != "Ijk_Ret" and \
                current_exit_wrapper.bbl_in_stack(
                                                new_call_stack_suffix, current_function_addr, new_addr):
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
            next_irsb = self._nodes[new_tpl]
            assert next_irsb is not None
            other_preds = set()
            for k_tpl, v_lst in exit_targets.items():
                a = self._simrun_key_addr(k_tpl)
                for v_tpl in v_lst:
                    b = v_tpl[-2] # The last item is the jumpkind :)
                    if b == next_irsb.addr and a != sim_run.addr:
                        other_preds.add(self._nodes[k_tpl])
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
                        self._loop_back_edges.append((simrun_key, new_tpl))
                        l.debug("Found a loop, back edge %s --> %s", sim_run, next_irsb)
            else:
                # Case 1, it's not over lapping with any other things
                if (sim_run.addr, next_irsb.addr) not in self._loop_back_edges_set:
                    self._loop_back_edges_set.add((sim_run.addr, next_irsb.addr))
                    self._loop_back_edges.append((simrun_key, new_tpl))
                l.debug("Found a loop, back edge %s --> %s", sim_run, next_irsb)

    @staticmethod
    def _is_indirect_jump(_, simirsb):
        """
        Determine if this SimIRSB has an indirect jump as its exit
        """

        if simirsb.irsb.direct_next:
            # It's a direct jump
            return False

        if not (simirsb.irsb.jumpkind == 'Ijk_Call' or simirsb.irsb.jumpkind == 'Ijk_Boring'):
            # It's something else, like a ret of a syscall... we don't care about it
            return False

        return True

    def _resolve_indirect_jump(self, cfgnode, simirsb):
        """
        Try to resolve an indirect jump by slicing backwards
        """

        l.debug("Resolving indirect jump at IRSB %s", simirsb)

        # Let's slice backwards from the end of this exit
        next_tmp = simirsb.irsb.next.tmp

        self._graph = self._create_graph(return_target_sources=self.return_target_sources)
        bc = self.project.analyses.BackwardSlice(self, None, None, cfgnode, -1)
        taint_graph = bc.taint_graph
        # Find the correct taint
        next_nodes = [ n for n in taint_graph.nodes() if n.addr == simirsb.addr and n.type == 'tmp' and n.tmp == next_tmp ]

        if not next_nodes:
            l.error('The target exit is not included in the slice. Something is wrong')
            return [ ]

        next_node = next_nodes[0]

        # Get the weakly-connected subgraph that contains `next_node`
        all_subgraphs = networkx.weakly_connected_component_subgraphs(taint_graph)
        starts = set()
        for subgraph in all_subgraphs:
            if next_node in subgraph:
                # Make sure there is no symbolic read...
                if any([ n.mem_addr.symbolic for n in subgraph.nodes() if n.type == 'mem' ]):
                    continue

                # FIXME: This is an over-approximation. We should try to limit the starts more
                nodes = [ n for n in subgraph.nodes() if subgraph.in_degree(n) == 0]
                for n in nodes:
                    starts.add(n.addr)

        # Execute the slice
        successing_addresses = set()
        annotated_cfg = bc.annotated_cfg()
        for start in starts:
            l.debug('Start symbolic execution at 0x%x on program slice.', start)
            # Get the state from our CFG
            node = self.get_any_node(start)
            if node is None:
                # Well, we have to live with an empty state
                p = self.project.factory.path(self.project.factory.blank_state(addr=start))
            else:
                base_state = node.input_state.copy()
                base_state.set_mode('symbolic')
                base_state.ip = start

                # TODO: Tidy this part of code
                # Clean all taints in the state at this IP
                if node in bc.initial_taints_per_run:
                    initial_taints = bc.initial_taints_per_run[node]

                    to_be_unconstrained = [ ]

                    for taint_set in initial_taints:
                        data_taints = taint_set.data_taints
                        for data_taint in data_taints:
                            try:
                                if bc.is_taint_related_to_ip(data_taint.simrun_addr, data_taint.stmt_idx, 'mem',
                                                          simrun_whitelist=[ simirsb.addr ]):
                                    continue
                                if bc.is_taint_impacting_stack_pointers(data_taint.simrun_addr, data_taint.stmt_idx,
                                                                        'mem'):
                                    continue
                                # Only overwrite it if it's on the stack
                                simrun_addr = data_taint.address.ast.model.value
                                if not (
                                    simrun_addr <= self.project.arch.initial_sp and
                                    simrun_addr > self.project.arch.initial_sp - self.project.arch.stack_size
                                ):
                                    continue
                            except AngrBackwardSlicingError:
                                # The taint is not found
                                # We skip this taint to stay on the safe side
                                continue
                            to_be_unconstrained.append(data_taint)

                    if len(to_be_unconstrained) > 1:
                        # Unconstraining too many values may lead to symbolic execution taking too much time to terminate
                        # For performance concerns, we are only taking the first value here
                        to_be_unconstrained = to_be_unconstrained[ : 1]

                    for data_taint in to_be_unconstrained:
                        unconstrained_value = base_state.se.Unconstrained('unconstrained',
                                                                          data_taint.bits.ast)
                        base_state.memory.store(data_taint.address,
                                                unconstrained_value,
                                                endness=self.project.arch.memory_endness)

                # Clear the constraints!
                base_state.se._solver.constraints = [ ]
                base_state.se._solver._result = None
                p = self.project.factory.path(base_state)

            # For speed concerns, we are limiting the timeout for z3 solver to 5 seconds. It will be restored afterwards
            old_timeout = p.state.se._solver.timeout
            p.state.se._solver.timeout = 5000

            sc = self.project.surveyors.Slicecutor(annotated_cfg, start=p, max_loop_iterations=1).run()

            # Restore the timeout!
            p.state.se._solver.timeout = old_timeout

            if sc.cut or sc.deadended:
                all_deadended_paths = sc.cut + sc.deadended
                for p in all_deadended_paths:
                    if p.addr == simirsb.addr:
                        # We want to get its successors
                        successing_paths = p.step()
                        for sp in successing_paths:
                            successing_addresses.add(sp.addr)

            else:
                l.debug("Cannot determine the exit. You need some better ways to recover the exits :-(")

        l.debug('Resolution is done, and we have %d new successors.', len(successing_addresses))

        return list(successing_addresses)

    def _normalize_loop_backedges(self):
        """
        Convert loop_backedges from tuples of simrun keys to real edges in self.graph.
        """

        loop_backedges = [ ]

        for src_key, dst_key in self._loop_back_edges:
            src = self._nodes[src_key]
            dst = self._nodes[dst_key]

            loop_backedges.append((src, dst))

        self._loop_back_edges = loop_backedges

    def get_lbe_exits(self):
        """
        -> Generator
        Returns a generator of exits of the loops
        based on the back egdes
        """
        for lirsb, _ in self._loop_back_edges:
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

    def normalize(self):
        """
        Normalize the CFG, making sure there are no overlapping basic blocks.
        """

        # FIXME: Currently after normalization, CFG._nodes will not be updated, which will lead to some interesting
        # FIXME: bugs.
        # FIXME: Currently any information inside FunctionManager (including those functions) is not updated.

        graph = self.graph

        end_addresses = defaultdict(list)

        for n in graph.nodes():
            if n.is_simprocedure:
                continue
            end_addr = n.addr + n.size
            end_addresses[(end_addr, n.callstack_key)].append(n)

        while any([ len(x) > 1 for x in end_addresses.itervalues() ]):
            tpl_to_find = (None, None)
            for tpl, x in end_addresses.iteritems():
                if len(x) > 1:
                    tpl_to_find = tpl
                    break

            end_addr, callstack_key = tpl_to_find
            all_nodes = end_addresses[tpl_to_find]

            all_nodes = sorted(all_nodes, key=lambda n: n.size)
            smallest_node = all_nodes[0]
            other_nodes = all_nodes[ 1 : ]

            # Break other nodes
            for n in other_nodes:
                new_size = smallest_node.addr - n.addr
                if new_size == 0:
                    # This is the node that has the same size as the smallest one
                    continue

                new_end_addr = n.addr + new_size

                # Does it already exist?
                new_node = None
                tpl = (new_end_addr, n.callstack_key)
                if tpl in end_addresses:
                    nodes = [ i for i in end_addresses[tpl] if i.addr == n.addr ]
                    if len(nodes) > 0:
                        new_node = nodes[0]

                if new_node is None:
                    # Create a new one
                    new_node = CFGNode(callstack_key, n.addr, new_size, self, function_address=n.function_address)
                    # Copy instruction addresses
                    new_node.instruction_addrs = [ ins_addr for ins_addr in n.instruction_addrs
                                                   if ins_addr < n.addr + new_size]
                    # Put the newnode into end_addresses
                    end_addresses[tpl].append(new_node)

                # Modify the CFG
                original_predecessors = list(graph.in_edges_iter([n], data=True))
                for p, _, _ in original_predecessors:
                    graph.remove_edge(p, n)
                graph.remove_node(n)

                for p, _, data in original_predecessors:
                    graph.add_edge(p, new_node, data)

                # We should find the correct successor
                new_successors = [ i for i in all_nodes
                                  if i.addr == smallest_node.addr ]
                if new_successors:
                    new_successor = new_successors[0]
                    graph.add_edge(new_node, new_successor, jumpkind='Ijk_Boring')
                else:
                    # We gotta create a new one
                    l.error('normalize(): Please report it to Fish.')

            end_addresses[tpl_to_find] = [ smallest_node ]

    def unroll_loops(self, max_loop_unrolling_times):
        if not isinstance(max_loop_unrolling_times, (int, long)) or \
                         max_loop_unrolling_times < 0:
            raise AngrCFGError('Max loop unrolling times must be set to an integer greater than or equal to 0 if ' +
                               'loop unrolling is enabled.')

        # Traverse the CFG and try to find the beginning of loops
        loop_backedges = [ ]

        start = self._starts[0]
        if isinstance(start, tuple):
            start, _ = start # pylint: disable=unpacking-non-sequence
        start_node = self.get_any_node(start)
        if start_node is None:
            raise AngrCFGError('Cannot find start node when trying to unroll loops. The CFG might be empty.')

        graph_copy = networkx.DiGraph(self.graph)

        while True:
            cycles_iter = networkx.simple_cycles(graph_copy)
            try:
                cycle = cycles_iter.next()
            except StopIteration:
                break

            loop_backedge = (None, None)

            for n in networkx.dfs_preorder_nodes(graph_copy, source=start_node):
                if n in cycle:
                    idx = cycle.index(n)
                    if idx == 0:
                        loop_backedge = (cycle[-1], cycle[idx])
                    else:
                        loop_backedge = (cycle[idx - 1], cycle[idx])
                    break

            if loop_backedge not in loop_backedges:
                loop_backedges.append(loop_backedge)

            # Create a common end node for all nodes whose out_degree is 0
            end_nodes = [ n for n in graph_copy.nodes_iter() if graph_copy.out_degree(n) == 0 ]
            new_end_node = "end_node"

            if len(end_nodes) == 0:
                # We gotta randomly break a loop
                cycles = sorted(networkx.simple_cycles(graph_copy), key=len)
                first_cycle = cycles[0]
                if len(first_cycle) == 1:
                    graph_copy.remove_edge(first_cycle[0], first_cycle[0])
                else:
                    graph_copy.remove_edge(first_cycle[0], first_cycle[1])
                end_nodes = [n for n in graph_copy.nodes_iter() if graph_copy.out_degree(n) == 0]

            for en in end_nodes:
                graph_copy.add_edge(en, new_end_node)

            #postdoms = self.immediate_postdominators(new_end_node, target_graph=graph_copy)
            #reverse_postdoms = defaultdict(list)
            #for k, v in postdoms.iteritems():
            #    reverse_postdoms[v].append(k)

            # Find all loop bodies
            #for src, dst in loop_backedges:
            #    nodes_in_loop = { src, dst }

            #    while True:
            #        new_nodes = set()

            #        for n in nodes_in_loop:
            #            if n in reverse_postdoms:
            #                for node in reverse_postdoms[n]:
            #                    if node not in nodes_in_loop:
            #                        new_nodes.add(node)

            #        if not new_nodes:
            #            break

            #        nodes_in_loop |= new_nodes

            # Unroll the loop body
            # TODO: Finish the implementation

            graph_copy.remove_node(new_end_node)
            src, dst = loop_backedge
            if graph_copy.has_edge(src, dst): # It might have been removed before
                # Duplicate the dst node
                new_dst = dst.copy()
                new_dst.looping_times = dst.looping_times + 1
                if (new_dst not in graph_copy # If the new_dst is already in the graph, we don't want to keep unrolling
                                              # the this loop anymore since it may *create* a new loop. Of course we
                                              # will lose some edges in this way, but in general it is acceptable.
                        and new_dst.looping_times <= max_loop_unrolling_times):
                    # Log all successors of the dst node
                    dst_successors = graph_copy.successors(dst)
                    # Add new_dst to the graph
                    edge_data = graph_copy.get_edge_data(src, dst)
                    graph_copy.add_edge(src, new_dst, **edge_data)
                    for ds in dst_successors:
                        if ds.looping_times == 0 and ds not in cycle:
                            edge_data = graph_copy.get_edge_data(dst, ds)
                            graph_copy.add_edge(new_dst, ds, **edge_data)
                # Remove the original edge
                graph_copy.remove_edge(src, dst)

        # Update loop backedges
        self._loop_back_edges = loop_backedges

        self._graph = graph_copy

    def _clean_pending_exits(self, pending_exits):
        """
        Remove those pending exits if:
        a) they are the return exits of non-returning SimProcedures
        b) they are the return exits of non-returning Syscalls
        b) they are the return exits of non-returning functions

        :param pending_exits: A dict of all pending exits
        """

        pending_exits_to_remove = [ ]

        for simrun_key, pe in pending_exits.iteritems():

            if pe.returning_source is None:
                # The original call failed. This pending exit must be followed.
                continue

            func = self.function_manager.function(pe.returning_source)
            if func is None:
                # Why does it happen?
                l.warning("An expected function at %s is not found. Please report it to Fish.",
                          hex(pe.returning_source) if pe.returning_source is not None else 'None')
                continue

            if func.returning == False:
                # Oops, it's not returning
                # Remove this pending exit
                pending_exits_to_remove.append(simrun_key)

        for simrun_key in pending_exits_to_remove:

            l.debug('Removing a pending exit to 0x%x since the target function 0x%x does not return',
                    self._simrun_key_addr(simrun_key),
                    pending_exits[simrun_key].returning_source,
                    )

            del pending_exits[simrun_key]

    def _analyze_calling_conventions(self):
        '''
        Concretely execute part of the function and watch the changes of sp
        :return:
        '''

        l.debug("Analyzing calling conventions of each function.")

        for func in self._function_manager.functions.values():
            startpoint = func.startpoint

            #
            # Refining arguments of a function by analyzing its call-sites
            #
            callsites = self._get_callsites(func.startpoint)
            self._refine_function_arguments(func, callsites)

            cc = simuvex.SimCC.match(self.project, startpoint, self)

            # Set the calling convention
            func.cc = cc

        #for func in self._function_manager.functions.values():
        #    l.info(func)

    def _analyze_function_features(self):
        """
        For each function in self.function_manager, try to determine if it returns or not. A function does not return if
        it calls another function that is known to be not returning, and this functiond does not have other exits.

        We might as well analyze other features of functions in the future.
        """

        changes = {
            'functions_return': [ ],
            'functions_do_not_return': [ ]
        }

        self._graph = self._create_graph()

        for func_addr, func in self.function_manager.functions.iteritems():
            if func.returning is not None:
                # It has been determined before. Skip it
                continue

            # If there is at least one endpoint, then this function is definitely returning
            if func.endpoints:
                changes['functions_return'].append(func)
                func.returning = True
                continue

            # This function does not have endpoints. It's either because it does not return, or we haven't analyzed all
            # blocks of it. We check all its current nodes in transition graph whose out degree is 0 (call them
            # temporary endpoints)

            func_transition_graph = func.local_transition_graph

            temporary_local_endpoints = [ a for a in func_transition_graph.nodes()
                                    if func_transition_graph.out_degree(a) == 0 ]

            if not temporary_local_endpoints:
                # It might be empty if our transition graph is fucked up (for example, the freaking
                # SimProcedureContinuation can be used in any SimProcedures and almost always creates loops in its
                # transition graph). Just ignore it.
                continue

            all_endpoints_returning = [ ]
            temporary_endpoints = [ ]

            for local_endpoint in temporary_local_endpoints:

                if local_endpoint in func.transition_graph.nodes():
                    out_edges = func.transition_graph.out_edges([ local_endpoint ], data=True)

                    if not out_edges:
                        temporary_endpoints.append(local_endpoint)

                    else:
                        for src, dst, data in out_edges:
                            t = data['type']

                            if t != 'fake_return':
                                temporary_endpoints.append(dst)

            for endpoint in temporary_endpoints:
                if endpoint in func.blocks:
                    # Somehow analysis terminated here (e.g. an unsupported instruction, or it doesn't generate an exit)

                    n = self.get_any_node(endpoint, is_syscall=func.is_syscall)
                    if n:
                        # It might be a SimProcedure or a syscall, or even a normal block
                        all_endpoints_returning.append(not n.no_ret)

                    else:
                        all_endpoints_returning.append(None)

                else:
                    # This block is not a member of the current function
                    call_target = endpoint

                    call_target_func = self.function_manager.function(call_target)
                    if call_target_func is None:
                        all_endpoints_returning.append(None)
                        continue

                    all_endpoints_returning.append(call_target_func.returning)

            if all([ i == False for i in all_endpoints_returning ]):
                # All target functions that this function calls is not returning
                func.returning = False
                changes['functions_do_not_return'].append(func)

        return changes

    def _get_callsites(self, function_address):
        '''
        Get where a specific function is called.
        :param function_address:    Address of the target function
        :return:                    A list of CFGNodes whose exits include a call/jump to the given function
        '''

        all_predecessors = [ ]

        nodes = self.get_all_nodes(function_address)
        for n in nodes:
            predecessors = self.get_predecessors(n)
            all_predecessors.extend(predecessors)

        return all_predecessors

    def _refine_function_arguments(self, func, callsites):
        '''

        :param func:
        :param callsites:
        :return:
        '''

        for i, c in enumerate(callsites):
            # Execute one block ahead of the callsite, and execute one basic block after the callsite
            # In this process, the following tasks are performed:
            # - Record registers/stack variables that are modified
            # - Record the change of the stack pointer
            # - Check if the return value is used immediately
            # We assume that the stack is balanced before and after the call (you can have caller clean-up of course).
            # Any abnormal behaviors will be logged.
            # Hopefully this approach will allow us to have a better understanding of parameters of those function
            # stubs and function proxies.

            if c.simprocedure_name is not None:
                # Skip all SimProcedures
                continue

            l.debug("Refining %s at 0x%x (%d/%d).", repr(func), c.addr, i, len(callsites))

            # Get a basic block ahead of the callsite
            blocks_ahead = [ c ]

            # the block after
            blocks_after = [ ]
            successors = self.get_successors_and_jumpkind(c, excluding_fakeret=False)
            for s, jk in successors:
                if jk == 'Ijk_FakeRet':
                    blocks_after = [ s ]
                    break

            regs_overwritten = set()
            stack_overwritten = set()
            regs_read = set()
            regs_written = set()

            try:
                # Execute the predecessor
                path = self.project.factory.path(self.project.factory.blank_state(mode="fastpath", addr=blocks_ahead[0].addr))
                all_successors = path.next_run.successors + path.next_run.unsat_successors
                if len(all_successors) == 0:
                    continue

                suc = all_successors[0]
                se = suc.se
                # Examine the path log
                actions = suc.log.actions
                sp = se.exactly_int(suc.regs.sp, default=0) + self.project.arch.call_sp_fix
                for ac in actions:
                    if ac.type == "reg" and ac.action == "write":
                        regs_overwritten.add(ac.offset)
                    elif ac.type == "mem" and ac.action == "write":
                        addr = se.exactly_int(ac.addr.ast, default=0)
                        if (self.project.arch.call_pushes_ret and addr >= sp + self.project.arch.bits / 8) or \
                                (not self.project.arch.call_pushes_ret and addr >= sp):
                            offset = addr - sp
                            stack_overwritten.add(offset)

                func.prepared_registers.add(tuple(regs_overwritten))
                func.prepared_stack_variables.add(tuple(stack_overwritten))

            except (simuvex.SimError, AngrError):
                pass

            try:
                if len(blocks_after):
                    path = self.project.factory.path(self.project.factory.blank_state(mode="fastpath", addr=blocks_after[0].addr))
                    all_successors = path.next_run.successors + path.next_run.unsat_successors
                    if len(all_successors) == 0:
                        continue

                    suc = all_successors[0]
                    actions = suc.log.actions
                    for ac in actions:
                        if ac.type == "reg" and ac.action == "read" and ac.offset not in regs_written:
                            regs_read.add(ac.offset)
                        elif ac.type == "reg" and ac.action == "write":
                            regs_written.add(ac.offset)

                    # Filter registers, remove unnecessary registers from the set
                    regs_overwritten = self.project.arch.argument_registers.intersection(regs_overwritten)
                    regs_read = self.project.arch.argument_registers.intersection(regs_read)

                    func.registers_read_afterwards.add(tuple(regs_read))

            except (simuvex.SimError, AngrError):
                pass

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

                if call_func.returning == False:
                    # Remove that edge!
                    graph.remove_edge(call_func_addr, return_to_addr)
                    # Remove the edge in CFG
                    nodes = self.get_all_nodes(callsite_block_addr)
                    for n in nodes:
                        successors = self.get_successors_and_jumpkind(n, excluding_fakeret=False)
                        for successor, jumpkind in successors:
                            if jumpkind == 'Ijk_FakeRet' and successor.addr == return_to_addr:
                                self.remove_edge(n, successor)

            # Remove all dangling nodes
            #wcc = list(networkx.weakly_connected_components(graph))
            #for nodes in wcc:
            #    if func.startpoint not in nodes:
            #        graph.remove_nodes_from(nodes)

    def _immediate_dominators(self, node, target_graph=None, reverse_graph=False):
        if target_graph is None:
            target_graph = self.graph

        if node not in target_graph:
            raise AngrCFGError('Target node %s is not in graph.' % node)

        graph = networkx.DiGraph(target_graph)
        if reverse_graph:
            # Reverse the graph without deepcopy
            for n in target_graph.nodes():
                graph.add_node(n)
            for src, dst in target_graph.edges():
                graph.add_edge(dst, src)

        idom = {node: node}

        order = list(networkx.dfs_postorder_nodes(graph, node))
        dfn = {u: i for i, u in enumerate(order)}
        order.pop()
        order.reverse()

        def intersect(u, v):
            while u != v:
                while dfn[u] < dfn[v]:
                    u = idom[u]
                while dfn[u] > dfn[v]:
                    v = idom[v]
            return u

        changed = True
        while changed:
            changed = False
            for u in order:
                new_idom = reduce(intersect, (v for v in graph.pred[u] if v in idom))
                if u not in idom or idom[u] != new_idom:
                    idom[u] = new_idom
                    changed = True

        return idom

    def immediate_dominators(self, start, target_graph=None):
        return self._immediate_dominators(start, target_graph=target_graph, reverse_graph=False)

    def immediate_postdominators(self, end, target_graph=None):
        return self._immediate_dominators(end, target_graph=target_graph, reverse_graph=True)

    def __setstate__(self, s):
        self._graph = s['graph']
        self._function_manager = s['function_manager']
        self._loop_back_edges = s['_loop_back_edges']
        self._nodes = s['_nodes']
        self.unresolved_indirect_jumps = s['unresolved_indirect_jumps']
        self.resolved_indirect_jumps = s['resolved_indirect_jumps']
        self._thumb_addrs = s['_thumb_addrs']
        self._unresolvable_runs = s['_unresolvable_runs']
        self._executable_address_ranges = s['_executable_address_ranges']

    def __getstate__(self):
        s = { }
        s['graph'] = self._graph
        s['function_manager'] = self._function_manager
        s['_loop_back_edges'] = self._loop_back_edges
        s['_nodes'] = self._nodes
        s['unresolved_indirect_jumps'] = self.unresolved_indirect_jumps
        s['resolved_indirect_jumps'] = self.resolved_indirect_jumps
        s['_thumb_addrs'] = self._thumb_addrs
        s['_unresolvable_runs'] = self._unresolvable_runs
        s['_executable_address_ranges'] = self._executable_address_ranges

        return s

    def _get_nx_paths(self, begin,  end):
        """
        Get the possible (networkx) simple paths between two nodes or addresses
        corresponding to nodes.
        Input: addresses or node instances
        Return: a list of lists of nodes representing paths.
        """
        if isinstance(begin, int) and isinstance(end, int):
            n_begin = self.get_any_node(begin)
            n_end = self.get_any_node(end)

        elif isinstance(begin, CFGNode) and isinstance(end, CFGNode):
            n_begin = begin
            n_end = end
        else:
            raise AngrCFGError("from and to should be of the same type")

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

register_analysis(CFG, 'CFG')
