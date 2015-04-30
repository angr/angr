from collections import defaultdict
import logging

import networkx
import simuvex
import claripy

import angr
from ..entry_wrapper import EntryWrapper
from .cfg_base import CFGBase
from ..analysis import Analysis
from ..errors import AngrCFGError, AngrError


l = logging.getLogger(name="angr.analyses.cfg")

# The maximum tracing times of a basic block
MAX_TRACING_TIMES = 1

class CFGNode(object):
    '''
    This guy stands for each single node in CFG.
    '''
    def __init__(self, callstack_key, addr, size, cfg, input_state=None, simprocedure_name=None):
        '''
        Note: simprocedure_name is not used to recreate the SimProcedure object. It's only there for better
        __repr__.
        '''

        self.callstack_key = callstack_key
        self.addr = addr
        self.input_state = input_state
        self.simprocedure_name = simprocedure_name
        self.size = size
        self._cfg = cfg

    @property
    def successors(self):
        return self._cfg.get_successors(self)

    @property
    def predecessors(self):
        return self._cfg.get_predecessors(self)

    def __repr__(self):
        if self.simprocedure_name is not None:
            s = "<CFGNode %s (0x%x)>" % (self.simprocedure_name, self.addr)
        else:
            s = "<CFGNode 0x%x (%d)>" % (self.addr, self.size)

        return s

    def __eq__(self, other):
        if isinstance(other, simuvex.SimIRSB) or isinstance(other, simuvex.SimProcedure):
            raise ValueError("You do not want to be comparing a SimRun to a CFGNode.")
        if not isinstance(other, CFGNode):
            return False
        return self.callstack_key == other.callstack_key and self.addr == other.addr and self.size == other.size

    def __hash__(self):
        return hash((self.callstack_key, self.addr))

class CFG(Analysis, CFGBase):
    '''
    This class represents a control-flow graph.
    '''
    def __init__(self, context_sensitivity_level=1,
                 start=None,
                 avoid_runs=None,
                 enable_function_hints=False,
                 call_depth=None,
                 initial_state=None,
                 starts=None,
                 keep_input_state=False
                ):
        '''

        :param project: The project object.
        :param context_sensitivity_level: The level of context-sensitivity of this CFG.
                                        It ranges from 0 to infinity.
        :return:
        '''
        CFGBase.__init__(self, self._p, context_sensitivity_level)
        self._symbolic_function_initial_state = {}

        self._unconstrained_states = []
        self._unresolvable_runs = set()

        if start is not None:
            l.warning("`start` is deprecated. Please consider using `starts` instead in your code.")
            self._starts = (start,)
        else:
            if type(starts) in (list, set):
                self._starts = tuple(starts)
            elif type(starts) is tuple or starts is None:
                self._starts = starts
            else:
                raise AngrCFGError('Unsupported type of the `starts` argument.')

        self._avoid_runs = avoid_runs
        self._enable_function_hints = enable_function_hints
        self._call_depth = call_depth
        self._initial_state = initial_state
        self._keep_input_state = keep_input_state

        if self._enable_function_hints:
            # FIXME: As we don't have section info, we have to hardcode where executable sections are.
            # FIXME: PLEASE MANUALLY MODIFY THE FOLLOWING CHECK BEFORE YOU RUN CFG GENERATION TO YOUR BINARY
            # FIXME: IF YOU DON'T DO IT, DON'T COMPLAIN TO ME - GO FUCK YOURSELF IN THE CORNER
            
            self.text_base = []
            self.text_size = []
            for b in self._p.ld.shared_objects + [self._p.ld.main_bin,]:
                text_sec = b.sections['.text']
                self.text_base.append(b.rebase_addr + text_sec['addr'])
                self.text_size.append(text_sec['size'])


        self._construct()

        self.result = {"functions": self._function_manager.functions.keys(), "graph": self.graph}

    def copy(self):
        # Create a new instance of CFG without calling the __init__ method of CFG class
        new_cfg = Analysis.copy(self)

        # Intelligently (or stupidly... you tell me) fill it up
        new_cfg._graph = networkx.DiGraph(self._graph)
        new_cfg._nodes = self._nodes.copy()
        new_cfg._edge_map = self._edge_map.copy()
        new_cfg._loop_back_edges_set = self._loop_back_edges_set.copy()
        new_cfg._loop_back_edges = self._loop_back_edges[::]
        new_cfg._overlapped_loop_headers = self._overlapped_loop_headers[::]
        new_cfg._function_manager = self._function_manager
        new_cfg._thumb_addrs = self._thumb_addrs.copy()

        return new_cfg

    @property
    def unresolvables(self):
        '''
        Get those SimRuns that have non-resolvable exits
        :return:
        '''
        return self._unresolvable_runs

    @property
    def unconstrained(self):
	return self._unconstrained_states

    def _push_unresolvable_run(self, simrun_address):
        self._unresolvable_runs.add(simrun_address)

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
        self._function_manager = angr.FunctionManager(self._project, self)

        # Save input states of functions. It will be discarded at the end of this function.
        self._function_input_states = { }

        self._initialize_cfg()

        # Traverse all the IRSBs, and put the corresponding CFGNode objects to a dict
        # It's actually a multi-dict, as we care about contexts.
        self._nodes = { }
        if self._starts is None:
            entry_points = (self._project.entry, )
        else:
            entry_points = self._starts
        l.debug("We start analysis from the following points: %s",
                ", ".join([hex(i) for i in entry_points])
        )

        remaining_entries = [ ]
        # Counting how many times a basic block is traced into
        traced_sim_blocks = defaultdict(lambda: defaultdict(int))

        # Crawl the binary, create CFG and fill all the refs inside project!
        for ep in entry_points:
            if self._initial_state is None:
                loaded_state = self._project.state_generator.entry_point(mode="fastpath")
            else:
                loaded_state = self._initial_state
                loaded_state.set_mode('fastpath')
            loaded_state.ip = loaded_state.se.BVV(ep, self._project.arch.bits)

            new_state_info = None

            # THIS IS A HACK FOR MIPS and ALSO PPC64
            if ep is not None and isinstance(self._project.arch, simuvex.SimMIPS32):
                # We assume this is a function start
                new_state_info = {'current_function': loaded_state.se.BVV(ep, 32)}
            elif ep is  not None and isinstance(self._project.arch, simuvex.SimPPC64):
                # Still assuming this is a function start
                new_state_info = {'toc': loaded_state.reg_expr('r2')}

            loaded_state = self._project.arch.prepare_state(loaded_state, new_state_info)
            self._symbolic_function_initial_state[ep] = loaded_state

            entry_point_path = self._project.path_generator.blank_path(state=loaded_state.copy())
            path_wrapper = EntryWrapper(entry_point_path, self._context_sensitivity_level)

            remaining_entries.append(path_wrapper)
            traced_sim_blocks[path_wrapper.call_stack_suffix()][ep] = 1

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
        simrun_info_collection = { }

        pending_function_hints = set()

        analyzed_addrs = set()

        # Iteratively analyze every exit
        while len(remaining_entries) > 0:
            entry_wrapper = remaining_entries.pop()
            # Process the popped exit
            self._handle_entry(entry_wrapper, remaining_entries,
                              exit_targets, pending_exits,
                              traced_sim_blocks, retn_target_sources,
                              avoid_runs, simrun_info_collection,
                              pending_function_hints, analyzed_addrs)

            while len(remaining_entries) == 0 and len(pending_exits) > 0:
                # We don't have any exits remaining. Let's pop a fake exit to
                # process
                pending_exit_tuple = pending_exits.keys()[0]
                pending_exit_state, pending_exit_call_stack, pending_exit_bbl_stack = \
                    pending_exits.pop(pending_exit_tuple)
                pending_exit_addr = pending_exit_tuple[-1]
                # Let's check whether this address has been traced before.
                if any(r == pending_exit_tuple for r in exit_targets):
                    # That block has been traced before. Let's forget about it
                    l.debug("Target 0x%08x has been traced before." + \
                            "Trying the next one...", pending_exit_addr)
                    continue

                # FIXME: Remove these assertions
                assert pending_exit_state.se.exactly_n_int(pending_exit_state.ip, 1)[0] == pending_exit_addr
                assert pending_exit_state.scratch.jumpkind == 'Ijk_Ret'

                new_path = self._project.path_generator.blank_path(state=pending_exit_state)
                new_path_wrapper = EntryWrapper(new_path,
                                                  self._context_sensitivity_level,
                                                  call_stack=pending_exit_call_stack,
                                                  bbl_stack=pending_exit_bbl_stack)
                remaining_entries.append(new_path_wrapper)
                l.debug("Tracing a missing retn exit 0x%08x, %s", pending_exit_addr, "->".join([hex(i) for i in pending_exit_tuple if i is not None]))
                break

            if len(remaining_entries) == 0 and len(pending_exits) == 0 and len(pending_function_hints) > 0:
                # Now let's look at how many new functions we can get here...
                while pending_function_hints:
                    f = pending_function_hints.pop()
                    if f not in analyzed_addrs:
                        new_state = self._project.state_generator.entry_point('fastpath')
                        new_state.ip = new_state.se.BVV(f, self._project.arch.bits)

                        # TOOD: Specially for MIPS
                        if new_state.arch.name == 'MIPS32':
                            # Properly set t9
                            new_state.store_reg('t9', f)

                        new_path = self._project.path_generator.blank_path(state=new_state)
                        new_path_wrapper = EntryWrapper(new_path,
                                                       self._context_sensitivity_level)
                        remaining_entries.append(new_path_wrapper)
                        l.debug('Picking a function 0x%x from pending function hints.', f)
                        self._function_manager._create_function_if_not_exist(new_path_wrapper.current_function_address)
                        break
        # Create CFG
        self._graph = self._create_graph(return_target_sources=retn_target_sources)

        # Remove those edges that will never be taken!
        self._remove_non_return_edges()

        # Perform function calling convention analysis
        self._analyze_calling_conventions()

        # Normalize all loop backedges
        self._normalize_loop_backedges()

        # Discard intermediate state dicts
        self._function_input_states = None

    def _create_graph(self, return_target_sources=None):
        '''
        Create a DiGraph out of the existing edge map.
        :param return_target_sources: Used for making up those missing returns
        :return: A networkx.DiGraph() object
        '''
        exit_targets = self._edge_map

        if return_target_sources is None:
            # We set it to a defaultdict in order to be consistent with the
            # actual parameter.`
            return_target_sources = defaultdict(list)

        cfg = networkx.DiGraph()
        # The corner case: add a node to the graph if there is only one block
        if len(self._nodes) == 1:
            cfg.add_node(self._nodes.values()[0])

        # Adding edges
        for tpl, targets in exit_targets.iteritems():
            basic_block = self._nodes[tpl] # Cannot fail :)
            for ex, jumpkind in targets:
                if ex not in self._nodes:
                    # Generate a PathTerminator node
                    # pt = simuvex.procedures.SimProcedures["stubs"]["PathTerminator"](self._project.state_generator.entry_point(), addr=ex[-1])
                    pt = CFGNode(callstack_key=ex[:-1],
                                 addr=ex[-1],
                                 size=None,
                                 cfg=self,
                                 input_state=None,
                                 simprocedure_name="PathTerminator")
                    if self._keep_input_state:
                        # We don't have an input state available for it (otherwise we won't have to create a
                        # PathTerminator). This is just a trick to make get_any_irsb() happy.
                        pt.input_state = self._project.state_generator.entry_point()
                        pt.input_state.ip = pt.addr
                    self._nodes[ex] = pt

                    l.debug("Key ([%s], %s) does not exist. Create a PathTerminator instead.", 
                            ', '.join(hex(addr) for addr in ex[:-1] if addr is not None),
                            hex(ex[-1]) if ex[-1] is not None else 'None')

                target_bbl = self._nodes[ex]
                cfg.add_edge(basic_block, target_bbl, jumpkind=jumpkind)

                # Add edges for possibly missing returns
                if basic_block.addr in return_target_sources:
                    for src_irsb_key in \
                            return_target_sources[basic_block.addr]:
                        cfg.add_edge(self._nodes[src_irsb_key],
                                           basic_block, jumpkind="Ijk_Ret")

        return cfg

    def _symbolically_back_traverse(self, current_simrun, simrun_info_collection, cfg_node):

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
        if cfg_node not in temp_cfg.nodes():
            # TODO: Figure out why this is happening
            return concrete_exits

        keep_running = True
        while len(concrete_exits) == 0 and path_length < 5 and keep_running:
            path_length += 1
            queue = [cfg_node]
            avoid = set()
            for i in xrange(path_length):
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

            for n in queue:
                # Start symbolic exploration from each block
                state = self._project.state_generator.blank_state(address=n.addr, mode='symbolic', add_options={simuvex.o.DO_RET_EMULATION} | simuvex.o.resilience_options)
                # Set initial values of persistent regs
                if n.addr in simrun_info_collection:
                    for reg in state.arch.persistent_regs:
                        state.store_reg(reg, simrun_info_collection[n.addr][reg])
                for reg in state.arch.persistent_regs:
                    reg_protector = register_protector(reg, simrun_info_collection)
                    state.inspect.add_breakpoint('reg_write',
                                                 simuvex.BP(
                                                     simuvex.BP_AFTER,
                                                     reg_write_offset=state.arch.registers[reg][0],
                                                     action=reg_protector.write_persistent_register
                                                 )
                    )
                result = angr.surveyors.Explorer(self._project,
                                                 start=self._project.path_generator.blank_path(state=state),
                                                 find=(current_simrun.addr, ),
                                                 avoid=avoid,
                                                 max_repeats=10,
                                                 max_depth=path_length).run()
                if result.found:
                    if len(result.found[0].successors) > 0:
                        keep_running = False
                        concrete_exits.extend([ s for s in result.found[0].next_run.flat_successors ])
                        concrete_exits.extend([ s for s in result.found[0].next_run.unsat_successors ])
                    self._unconstrained_states += result.found[0].unconstrained_successor_states
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
                unsat_state.store_reg(reg, c.reg_expr(reg))
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

        fastpath_state = None
        if fastpath_mode_state is not None:
            fastpath_state = fastpath_mode_state
        else:
            if function_addr in self._function_input_states:
                fastpath_state = self._function_input_states[function_addr]
            else:
                raise AngrCFGError('The impossible happened. Please report to Fish.')

        symbolic_initial_state = self._project.state_generator.entry_point(mode='symbolic')
        if fastpath_state is not None:
            symbolic_initial_state = self._project.simos.prepare_call_state(fastpath_state,
                                                    initial_state=symbolic_initial_state)

        # Create a temporary block
        try:
            tmp_block = self._project.block(function_addr)
        except (simuvex.SimError, angr.AngrError):
            return None

        num_instr = tmp_block.instructions - 1

        symbolic_initial_state.ip = function_addr
        path = self._project.path_generator.blank_path(state=symbolic_initial_state)
        try:
            simrun = self._project.sim_run(path.state, num_inst=num_instr)
            self._unconstrained_states += simrun.unconstrained_successors
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
        error_occured = False
        state = current_entry.state
        saved_state = current_entry.state  # We don't have to make a copy here
        try:
            if self._project.is_sim_procedure(addr) and \
                    not self._project.sim_procedures[addr][0].ADDS_EXITS and \
                    not self._project.sim_procedures[addr][0].NO_RET:
                # DON'T CREATE USELESS SIMPROCEDURES
                # When generating CFG, a SimProcedure will not be created as it is but be created as a
                # ReturnUnconstrained stub if it satisfies the following conditions:
                # - It doesn't add any new exits.
                # - It returns as normal.
                # In this way, we can speed up the CFG generation by quite a lot as we avoid simulating
                # those functions like read() and puts(), which has no impact on the overall control flow at all.

                old_proc = self._project.sim_procedures[addr][0]
                if old_proc == simuvex.procedures.SimProcedures["stubs"]["ReturnUnconstrained"]:
                    old_name = self._project.sim_procedures[addr][1]['resolves']
                else:
                    old_name = old_proc.__name__.split('.')[-1]

                sim_run = simuvex.procedures.SimProcedures["stubs"]["ReturnUnconstrained"](
                    state,
                    addr=addr,
                    sim_kwargs={ 'resolves': "%s" % old_name }
                )
            else:
                sim_run = self._project.sim_run(current_entry.state)
                self._unconstrained_states += sim_run.unconstrained_successors
        except (simuvex.SimFastPathError, simuvex.SimSolverModeError) as ex:
            # Got a SimFastPathError. We wanna switch to symbolic mode for current IRSB.
            l.debug('Switch to symbolic mode for address 0x%x', addr)
            # Make a copy of the current 'fastpath' state
            self._log('Symbolic jumps at basic block 0x%x.' % addr)

            new_state = None
            if addr != current_function_addr:
                new_state = self._get_symbolic_function_initial_state(current_function_addr)

            if new_state is None:
                new_state = current_entry.state.copy()
                new_state.set_mode('symbolic')
            new_state.options.add(simuvex.o.DO_RET_EMULATION)
            # Swap them
            saved_state, current_entry.state = current_entry.state, new_state
            sim_run, error_occured, _ = self._get_simrun(addr, current_entry)
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

        return sim_run, error_occured, saved_state

    def _is_address_executable(self, address):
        for i in xrange(len(self.text_base)):
            text_base = self.text_base[i]
            text_size = self.text_size[i]
            if address >= text_base and address < text_base + text_size:
                return True
        return False

        #allowed_segments = {'text'}
        #seg = self._project.main_binary.in_which_segment(address)
        #return seg in allowed_segments

    def _search_for_function_hints(self, simrun, function_hints_found=None):
        '''
        Scan for constants that might be used as exit targets later, and add
        them into pending_exits
        '''

        function_hints = [ ]
        if isinstance(simrun, simuvex.SimIRSB) and simrun.successors:
            successor = simrun.successors[0]
            for action in successor.log.actions:
                if action.type == 'reg' and action.offset == self._project.arch.ip_offset:
                    # Skip all accesses to IP registers
                    continue
                elif action.type == 'exit':
                    # only consider read/write actions
                    continue

                # Enumerate actions
                try:
                    data = action.data
                except Exception as x:                   
                    print x.message
                    continue 
                if data is not None:
                    # TODO: Check if there is a proper way to tell whether this const falls in the range of code segments
                    # Now let's live with this big hack...
                    try:
                        const = successor.se.exactly_n_int(data.ast, 1)[0]
                    except:
                        continue

                    if self._is_address_executable(const):
                        if function_hints_found is not None and const in function_hints_found:
                            continue

                        #target = const
                        #tpl = (None, None, target)
                        #st = self._project.simos.prepare_call_state(self._project.initial_state(mode='fastpath'),
                        #                                           initial_state=saved_state)
                        #st = self._project.initial_state(mode='fastpath')
                        #exits[tpl] = (st, None, None)

                        function_hints.append(const)

            l.info('Got %d possible exits from %s, including: %s', len(function_hints), simrun, ", ".join(["0x%x" % f for f in function_hints]))

        return function_hints

    def _create_new_call_stack(self, addr, all_entries, entry_wrapper, exit_target, jumpkind):
        if jumpkind == "Ijk_Call":
            new_call_stack = entry_wrapper.call_stack_copy()
            # Notice that in ARM, there are some freaking instructions
            # like
            # BLEQ <address>
            # It should give us three exits: Ijk_Call, Ijk_Boring, and
            # Ijk_Ret. The last exit is simulated.
            # Notice: We assume the last exit is the simulated one
            if len(all_entries) > 1 and all_entries[-1].scratch.jumpkind == "Ijk_Ret":
                se = all_entries[-1].se
                retn_target_addr = se.exactly_int(all_entries[-1].ip, default=0)
                sp = se.exactly_int(all_entries[-1].sp_expr(), default=0)

                new_call_stack.call(addr, exit_target,
                                    retn_target=retn_target_addr,
                                    stack_pointer=sp)
            else:
                # We don't have a fake return exit available, which means
                # this call doesn't return.
                new_call_stack.clear()
                se = all_entries[-1].se
                sp = se.exactly_int(all_entries[-1].sp_expr(), default=0)

                new_call_stack.call(addr, exit_target, retn_target=None, stack_pointer=sp)
                retn_target_addr = None

            self._function_manager.call_to(
                function_addr=entry_wrapper.current_function_address,
                from_addr=addr,
                to_addr=exit_target,
                retn_addr=retn_target_addr)
        elif jumpkind == "Ijk_Ret":
            # Normal return

            se = all_entries[-1].se
            sp = se.exactly_int(all_entries[-1].sp_expr(), default=0)

            new_call_stack = entry_wrapper.call_stack_copy()
            old_sp = entry_wrapper.current_stack_pointer
            new_call_stack.ret(exit_target)

            # Calculate the delta of stack pointer
            if sp is not None and old_sp is not None:
                delta = sp - old_sp
                # Set sp_delta of the function
                self._function_manager.function(entry_wrapper.current_function_address).sp_delta = delta

            self._function_manager.return_from(
                function_addr=entry_wrapper.current_function_address,
                from_addr=addr,
                to_addr=exit_target)
        elif jumpkind == 'Ijk_FakeRet':
            # The fake return...
            new_call_stack = entry_wrapper.call_stack
            self._function_manager.return_from_call(
                function_addr=entry_wrapper.current_function_address,
                first_block_addr=addr,
                to_addr=exit_target)
        else:
            # Normal control flow transition
            new_call_stack = entry_wrapper.call_stack
            self._function_manager.transit_to(
                function_addr=entry_wrapper.current_function_address,
                from_addr=addr,
                to_addr=exit_target)

        return new_call_stack

    def _handle_entry(self, entry_wrapper, remaining_exits, exit_targets,
                     pending_exits, traced_sim_blocks, retn_target_sources,
                     avoid_runs, simrun_info_collection, function_hints_found,
                     analyzed_addrs):
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
        current_function = self._function_manager.function(current_function_addr)

        # Log this address
        analyzed_addrs.add(addr)

        if addr == current_function_addr:
            # Store the input state of this function
            self._function_input_states[current_function_addr] = current_entry.state

        # Get a SimRun out of current SimExit
        simrun, error_occured, saved_state = self._get_simrun(addr, current_entry,
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
        simrun_key = call_stack_suffix + (addr, )

        # Create the corresponding CFGNode object
        if isinstance(simrun, simuvex.SimProcedure):
            simproc_name = simrun.__class__.__name__.split('.')[-1]
            if simproc_name == "ReturnUnconstrained":
                simproc_name = simrun.resolves

            cfg_node = CFGNode(simrun_key[:-1],
                               simrun.addr,
                               None,
                               self,
                               input_state=None,
                               simprocedure_name=simproc_name)
        else:
            cfg_node = CFGNode(simrun_key[:-1],
                               simrun.addr,
                               simrun.irsb.size,
                               self,
                               input_state=None)
        if self._keep_input_state:
            cfg_node.input_state = simrun.initial_state
        self._nodes[simrun_key] = cfg_node

        simrun_info = self._project.arch.gather_info_from_state(simrun.initial_state)
        simrun_info_collection[addr] = simrun_info

        # For ARM THUMB mode
        if isinstance(simrun, simuvex.SimIRSB) and current_entry.state.thumb:
            self._thumb_addrs.update(simrun.imark_addrs())

        #
        # Get all successors of this SimRun
        #

        all_successors = (simrun.flat_successors + simrun.unsat_successors) if addr not in avoid_runs else []

        #
        # First, handle all actions
        #

        if all_successors:
            self._handle_actions(all_successors[0], simrun, current_function, current_stack_pointer,
                                 accessed_registers_in_function)

        #
        # Then handle all successors
        #

        if not error_occured:
            has_call_jumps = any([suc_state.scratch.jumpkind == 'Ijk_Call' for suc_state in all_successors])
            if has_call_jumps:
                concrete_successors = [suc_state for suc_state in all_successors if suc_state.scratch.jumpkind != 'Ijk_Ret' and not suc_state.se.symbolic(suc_state.ip)]
            else:
                concrete_successors = [suc_state for suc_state in all_successors if not suc_state.se.symbolic(suc_state.ip)]
            symbolic_successors = [suc_state for suc_state in all_successors if suc_state.se.symbolic(suc_state.ip)]

            resolved = False
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

            if not resolved and len(symbolic_successors) > 0 and len(concrete_successors) == 0:
                l.debug("We only got some symbolic exits. Try traversal backwards " +
                        "in symbolic mode.")

                if isinstance(simrun, simuvex.SimProcedure) and \
                        simrun.ADDS_EXITS:
                    # Skip those SimProcedures that don't create new SimExits
                    l.debug('We got a SimProcedure %s in fastpath mode that creates new exits.', simrun)
                    all_successors = self._symbolically_back_traverse(simrun, simrun_info_collection, cfg_node)
                    l.debug("Got %d concrete exits in symbolic mode.", len(all_successors))
                elif isinstance(simrun, simuvex.SimIRSB) and \
                        any([ex.scratch.jumpkind != 'Ijk_Ret' for ex in all_successors]):
                    # We cannot properly handle Return as that requires us start execution from the caller...
                    l.debug('We got a SimIRSB %s', simrun)
                    all_successors = self._symbolically_back_traverse(simrun, simrun_info_collection, cfg_node)
                    l.debug('Got %d concrete exits in symbolic mode', len(all_successors))
                else:
                    l.debug('All exits are returns (Ijk_Ret). It will be handled by pending exits.')

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
                    exit_target_tpl = new_call_stack.stack_suffix(self.context_sensitivity_level) + (retn_target,)
                    exit_targets[simrun_key].append((exit_target_tpl, 'Ijk_Ret'))
            else:
                # This is intentional. We shall remove all the fake
                # returns generated before along this path.

                # Build the tuples that we want to remove from
                # the dict pending_exits
                tpls_to_remove = [ ]
                call_stack_copy = entry_wrapper.call_stack_copy()
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
                        l.debug("Removed ([%s], %s) from pending_exits dict.",
                                ", ".join(hex(i) for i in tpl[:-1] if i is not None),
                                hex(tpl[-1] if tpl[-1] is not None else 'None'))

        # If there is a call exit, we shouldn't put the default exit (which
        # is artificial) into the CFG. The exits will be Ijk_Call and
        # Ijk_Ret, and Ijk_Call always goes first
        info_block = { 'is_call_jump' : False,
                       'call_target': None,
                       'last_call_exit_target': None
        }

        # For debugging purposes!
        successor_status = { }

        #
        # In the end, handles each successor state
        #
        for successor_state in all_successors:
            path_wrapper = self._handle_successor_state(simrun, simrun_key, addr, current_function_addr,
                                                        successor_state, all_successors, entry_wrapper, pending_exits,
                                                        retn_target_sources, traced_sim_blocks, info_block,
                                                        call_stack_suffix, exit_targets, successor_status)
            if path_wrapper:
                remaining_exits.append(path_wrapper)

        #
        # Debugging output
        #

        if l.level == logging.DEBUG:
            # Only in DEBUG mode do we process and output all those shit

            function_name = self._project.ld.find_symbol_name(simrun.addr)
            module_name = self._project.ld.find_module_name(simrun.addr)

            l.debug("Basic block %s %s", simrun, "->".join([hex(i) for i in call_stack_suffix if i is not None]))
            l.debug("(Function %s of binary %s)" %(function_name, module_name))
            l.debug("|    Has simulated retn: %s", info_block['is_call_jump'])

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
                                info_block,
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

        if suc_jumpkind in {'Ijk_EmWarn', 'Ijk_NoDecode', 'Ijk_MapFail',
                            'Ijk_InvalICache', 'Ijk_NoRedir', 'Ijk_SigTRAP',
                            'Ijk_SigSEGV', 'Ijk_ClientReq'}:
            # Ignore SimExits that are of these jumpkinds
            successor_status[state] = "Skipped"
            return

        # Jumpkind post process
        if suc_jumpkind == "Ijk_Call":
            info_block['is_call_jump'] = True
        elif suc_jumpkind == "Ijk_Ret" and info_block['is_call_jump']:
            suc_jumpkind = "Ijk_FakeRet"

        if suc_jumpkind == "Ijk_FakeRet" and info_block['call_target'] is not None:
            # if the call points to a SimProcedure that doesn't return, we don't follow the fakeret anymore
            if self._p.is_sim_procedure(info_block['call_target']):
                sim_proc = self._p.sim_procedures[info_block['call_target']][0]
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

        if info_block['is_call_jump']:
            info_block['call_target'] = exit_target

        # Remove pending targets - type 2
        tpl = (None, None, exit_target)
        if tpl in pending_exits:
            l.debug("Removing pending exits (type 2) to %s", hex(exit_target))
            del pending_exits[tpl]

        if suc_jumpkind == "Ijk_Call":
            info_block['last_call_exit_target'] = exit_target
        elif suc_jumpkind == "Ijk_FakeRet":
            if exit_target == info_block['last_call_exit_target']:
                l.debug("Skipping a fake return exit that has the same target with its call exit.")
                successor_status[state] = "Skipped"
                return

        # Create the new call stack of target block
        new_call_stack = self._create_new_call_stack(addr, all_successor_states,
                                                     entry_wrapper,
                                                     exit_target, suc_jumpkind)
        # Create the callstack suffix
        new_call_stack_suffix = new_call_stack.stack_suffix(self._context_sensitivity_level)
        # Tuple that will be used to index this exit
        new_tpl = new_call_stack_suffix + (exit_target,)

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
        if suc_jumpkind == "Ijk_Call":
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
            # This is the real retn exit
            # Remember this retn!
            retn_target_sources[exit_target].append(simrun_key)
            # Check if this retn is inside our pending_exits set
            if new_tpl in pending_exits:
                del pending_exits[new_tpl]
        if suc_jumpkind == "Ijk_FakeRet":
            # This is the default "fake" retn that generated at each
            # call. Save them first, but don't process them right
            # away
            # st = self._project.simos.prepare_call_state(new_initial_state, initial_state=saved_state)
            st = new_initial_state
            st.mode = 'fastpath'

            pending_exits[new_tpl] = \
                (st, new_call_stack, new_bbl_stack)
            successor_status[state] = "Pended"
        elif suc_jumpkind == 'Ijk_Call' and self._call_depth is not None and len(new_call_stack) > self._call_depth:
            # We skip this call
            successor_status[state] = "Skipped as it reaches maximum call depth"
        elif traced_sim_blocks[new_call_stack_suffix][exit_target] < MAX_TRACING_TIMES:
            traced_sim_blocks[new_call_stack_suffix][exit_target] += 1
            new_path = self._project.path_generator.blank_path(state=new_initial_state)

            # We might have changed the mode for this basic block
            # before. Make sure it is still running in 'fastpath' mode
            # new_exit.state = self._project.simos.prepare_call_state(new_exit.state, initial_state=saved_state)
            new_path.state.set_mode('fastpath')

            pw = EntryWrapper(new_path,
                                            self._context_sensitivity_level,
                                            call_stack=new_call_stack,
                                            bbl_stack=new_bbl_stack)
            successor_status[state] = "Appended"
        elif traced_sim_blocks[new_call_stack_suffix][exit_target] >= MAX_TRACING_TIMES \
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

        exit_targets[simrun_key].append((new_tpl, suc_jumpkind))

        return pw

    def _handle_actions(self, state, current_run, func, sp_addr, accessed_registers):
        se = state.se

        if func is not None and sp_addr is not None:

            # Fix the stack pointer (for example, skip the return address on the stack)
            new_sp_addr = sp_addr + self._p.arch.call_sp_fix

            actions = [ a for a in state.log.actions if a.bbl_addr == current_run.addr ]

            for a in actions:
                if a.type == "mem" and a.action == "read":
                    addr = se.exactly_int(a.addr.ast, default=0)
                    if (self._p.arch.call_pushes_ret and addr >= new_sp_addr) or \
                            (not self._p.arch.call_pushes_ret and addr >= new_sp_addr):
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
            l.error("sp is None")

    def _detect_loop(self, sim_run, new_tpl, exit_targets,
                     simrun_key, new_call_stack_suffix,
                     new_addr, new_jumpkind, current_exit_wrapper,
                     current_function_addr):
        # Loop detection
        assert isinstance(sim_run, simuvex.SimIRSB)

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
                a = k_tpl[-1]
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

    def normalize(self):
        """
        Normalize the CFG, making sure there are no overlapping basic blocks.
        """

        graph = self.graph

        end_addresses = defaultdict(list)

        for n in graph.nodes():
            if n.simprocedure_name is not None:
                continue
            end_addr = n.addr + n.size
            end_addresses[(end_addr, n.callstack_key)].append(n)

        while any([ len(l) > 1 for l in end_addresses.itervalues() ]):
            tpl_to_find = None
            for tpl, l in end_addresses.iteritems():
                if len(l) > 1:
                    tpl_to_find = tpl
                    break

            end_addr, callstack_key = tpl_to_find
            all_nodes = end_addresses[tpl_to_find]

            all_nodes = sorted(all_nodes, key=lambda n: n.size)
            smallest_node = all_nodes[0]
            print "Smallest from endaddr %x: " % end_addr, smallest_node
            other_nodes = all_nodes[ 1 : ]

            # Break other nodes
            for n in other_nodes:
                new_size = smallest_node.addr - n.addr
                print "New size for node %s is %d" % (n, new_size)
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
                    new_node = CFGNode(callstack_key, n.addr, new_size, self)
                    # Put the newnode into end_addresses
                    end_addresses[tpl].append(new_node)

                # Modify the CFG
                original_predecessors = list(graph.in_edges_iter([n], data=True))
                for p, _, _ in original_predecessors:
                    graph.remove_edge(p, n)
                graph.remove_node(n)

                for p, _, data in original_predecessors:
                    graph.add_edge(p, new_node, data)

                graph.add_edge(new_node, smallest_node, jumpkind='Ijk_Boring')

            end_addresses[tpl_to_find] = [ smallest_node ]

    def _analyze_calling_conventions(self):
        '''
        Concretely execute part of the function and watch the changes of sp
        :return:
        '''

        l.debug("Analyzing calling conventions of each function.")

        for func in self._function_manager.functions.values():
            graph = func.transition_graph
            startpoint = func.startpoint
            endpoints = func.endpoints

            #
            # Refining arguments of a function by analyzing its call-sites
            #
            callsites = self._get_callsites(func.startpoint)
            self._refine_function_arguments(func, callsites)

            cc = simuvex.SimCC.match(self._p, startpoint, self)

            # Set the calling convention
            func.cc = cc

        #for func in self._function_manager.functions.values():
        #    l.info(func)

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
                path = self._p.path_generator.blank_path(mode="fastpath", address=blocks_ahead[0].addr)
                all_successors = path.next_run.successors + path.next_run.unsat_successors
                if len(all_successors) == 0:
                    continue

                suc = all_successors[0]
                se = suc.se
                # Examine the path log
                actions = suc.log.actions
                sp = se.exactly_int(suc.sp_expr(), default=0) + self._p.arch.call_sp_fix
                for ac in actions:
                    if ac.type == "reg" and ac.action == "write":
                        regs_overwritten.add(ac.offset)
                    elif ac.type == "mem" and ac.action == "write":
                        addr = se.exactly_int(ac.addr.ast, default=0)
                        if (self._p.arch.call_pushes_ret and addr >= sp + self._p.arch.bits / 8) or \
                                (not self._p.arch.call_pushes_ret and addr >= sp):
                            offset = addr - sp
                            stack_overwritten.add(offset)

                func.prepared_registers.add(tuple(regs_overwritten))
                func.prepared_stack_variables.add(tuple(stack_overwritten))

            except (simuvex.SimError, AngrError):
                pass

            try:
                if len(blocks_after):
                    path = self._p.path_generator.blank_path(mode="fastpath", address=blocks_after[0].addr)
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
                    regs_overwritten = self._p.arch.filter_argument_registers(regs_overwritten)
                    regs_read = self._p.arch.filter_argument_registers(regs_read)

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

                if not call_func.has_return:
                    # Remove that edge!
                    graph.remove_edge(callsite_block_addr, return_to_addr)
                    # Remove the edge in CFG
                    nodes = self.get_all_nodes(callsite_block_addr)
                    for n in nodes:
                        successors = self.get_successors_and_jumpkind(n, excluding_fakeret=False)
                        for successor, jumpkind in successors:
                            if jumpkind == 'Ijk_FakeRet' and successor.addr == return_to_addr:
                                self.remove_edge(n, successor)

            # Remove all dangling nodes
            wcc = list(networkx.weakly_connected_components(graph))
            for nodes in wcc:
                if func.startpoint not in nodes:
                    graph.remove_nodes_from(nodes)

    def __setstate__(self, s):
        self._graph = s['graph']
        self._function_manager = s['function_manager']
        self._loop_back_edges = s['_loop_back_edges']
        self._nodes = s['_nodes']

    def __getstate__(self):
        s = { }
        s['graph'] = self._graph
        s['function_manager'] = self._function_manager
        s['_loop_back_edges'] = self._loop_back_edges
        s['_nodes'] = self._nodes

        return s
