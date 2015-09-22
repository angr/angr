import logging
from itertools import count
from collections import defaultdict

import networkx

from simuvex import SimProcedures, o
from simuvex.procedures.syscalls import handler

from ..errors import AngrError, AngrCFGError
from ..analysis import Analysis, register_analysis
from ..path_group import PathGroup
from ..path import Path, AngrPathError

l = logging.getLogger('angr.analyses.veritesting')

class VeritestingError(Exception):
    pass

class CallTracingFilter(object):
    whitelist = {
        SimProcedures['cgc']['receive'],
        SimProcedures['cgc']['transmit'],
        SimProcedures['libc.so.6']['read'],
        }

    cfg_cache = { }

    def __init__(self, project, depth, blacklist=None):
        self.project = project
        self.blacklist = [ ] if blacklist is None else blacklist
        self._skipped_targets = set()
        self.depth = depth

    def filter(self, call_target_state, jumpkind):
        """
            The call will be skipped if it returns True.

            :param call_target_state: The new state of the call target
            :param jumpkind: Jumpkind of this call
            :return: True if we want to skip this call, False otherwise
            """

        ACCEPT = False
        REJECT = True

        l.debug('Filtering calling target %s', call_target_state.ip)

        # Currently we always skip the call, unless the target function satisfies one of the following conditions:
        # 1) It's a SimProcedure that are in the whitelist
        # 2) It's a function that has no loops, and no calls/syscalls,
        # 3) It's a function that has no loops, and only has calls to another function that will not be filtered out by
        #    this filter

        # Generate a CFG
        ip = call_target_state.ip

        if self.depth >= 5:
            l.debug('Rejecting target %s - too deep, depth is %d', ip, self.depth)
            return REJECT

        try:
            addr = call_target_state.se.exactly_int(ip)
        except (SimValueError, SimSolverModeError):
            self._skipped_targets.add(-1)
            l.debug('Rejecting target %s - cannot be concretized', ip)
            return REJECT

        # Is it in our blacklist?
        if addr in self.blacklist:
            self._skipped_targets.add(addr)
            l.debug('Rejecting target 0x%x - blacklisted', addr)
            return REJECT

        # If the target is a SimProcedure, is it on our whitelist?
        if self.project.is_hooked(addr) and type(self.project._sim_procedures[addr][0]) in CallTracingFilter.whitelist:
            # accept!
            l.debug('Accepting target 0x%x, jumpkind %s', addr, jumpkind)
            return ACCEPT

        # If it's a syscall, let's see if the real syscall is inside our whitelist
        if jumpkind.startswith('Ijk_Sys'):
            call_target_state.scratch.jumpkind = jumpkind
            tmp_path = self.project.factory.path(call_target_state)
            next_run = tmp_path.next_run
            if isinstance(next_run, handler.handler):
                syscall = next_run.syscall
                if type(syscall) in CallTracingFilter.whitelist:
                    # accept!
                    l.debug('Accepting target 0x%x, jumpkind %s', addr, jumpkind)
                    return ACCEPT
                else:
                    # reject
                    l.debug('Rejecting target 0x%x - syscall %s not in whitelist', addr, syscall)
                    return REJECT
            else:
                # The syscall is not handled?
                # reject
                l.debug('Rejecting target 0x%x - Unsupported syscall handler %s', addr, next_run)
                return REJECT

        cfg_key = (addr, jumpkind)
        if cfg_key not in self.cfg_cache:
            new_blacklist = self.blacklist[ :: ]
            new_blacklist.append(addr)
            tracing_filter = CallTracingFilter(self.project, depth=self.depth + 1, blacklist=new_blacklist)
            cfg = self.project.analyses.CFG(starts=((addr, jumpkind),),
                                               initial_state=call_target_state,
                                               context_sensitivity_level=0,
                                               call_depth=0,
                                               call_tracing_filter=tracing_filter.filter
                                               )
            self.cfg_cache[cfg_key] = (cfg, tracing_filter)

            try:
                cfg.unroll_loops(1)
            except AngrCFGError:
                # Exceptions occurred during loop unrolling
                # reject
                l.debug('Rejecting target 0x%x - loop unrolling failed', addr)
                return REJECT

        else:
            l.debug('Loading CFG from CFG cache')
            cfg, tracing_filter = self.cfg_cache[cfg_key]

        if cfg._loop_back_edges:
            # It has loops!
            self._skipped_targets.add(addr)
            l.debug('Rejecting target 0x%x - it has loops', addr)
            return REJECT

        sim_procedures = [ n for n in cfg.graph.nodes() if n.simprocedure_name is not None ]
        for sp_node in sim_procedures:
            if not self.project.is_hooked(sp_node.addr):
                # This is probably a PathTerminator
                # Just skip it for now
                continue

            if self.project._sim_procedures[sp_node.addr][0] not in CallTracingFilter.whitelist:
                self._skipped_targets.add(addr)
                l.debug('Rejecting target 0x%x - contains SimProcedures outside whitelist', addr)
                return REJECT

        if len(tracing_filter._skipped_targets):
            # Bummer
            self._skipped_targets.add(addr)
            l.debug('Rejecting target 0x%x - should be skipped', addr)
            return REJECT

        # accept!
        l.debug('Accepting target 0x%x, jumpkind %s', addr, jumpkind)
        return ACCEPT

class Ref(object):
    def __init__(self, type, addr, actual_addrs, bits, value, action):
        """
        This is a reference object that is used internally in Veritesting. It holds less information than SimActions, but it
        has a little bit better interface, and saves a lot more keystrokes.
        """

        self.type = type
        self.addr = addr
        self.actual_addrs = set(actual_addrs)
        self.bits = bits
        self.value = value
        self.action = action

    @property
    def actual_offsets(self):
        if self.type == 'reg':
            return self.actual_addrs
        else:
            raise VeritestingError('Unsupported Ref type %s' % self.type)

    @property
    def offset(self):
        if self.type == 'reg':
            return self.addr
        else:
            raise VeritestingError('Unsupported Ref type %s' % self.type)

    def __eq__(self, other):
        if type(self.bits) in (int, long) and type(other.bits) in (int, long):
            return self.type == other.type and self.actual_addrs == other.actual_addrs and \
                   self.bits == other.bits
        else:
            return self.type == other.type and self.actual_addrs == other.actual_addrs and \
                   hash(self.bits) == hash(other.bits)

    def __hash__(self):
        return hash("%s_%s_%s" % (self.type, hash(tuple(self.actual_addrs)), self.bits))

class ITETreeNode(object):
    def __init__(self, guard=None, true_expr=None, false_expr=None):
        self.guard = guard
        self.true_expr = true_expr
        self.false_expr = false_expr

    def _encode(self, se, expr):
        if type(expr) is ITETreeNode:
            return expr.encode(se)
        else:
            return expr

    def encode(self, se):
        if self.true_expr is None and self.false_expr is None:
            raise VeritestingError('Unable to encode an empty ITETree.')
        elif self.true_expr is None:
            # Ignore the guard, and just encode the other expr
            return self._encode(se, self.false_expr)
        elif self.false_expr is None:
            # Ignore the guard, and just encode the other expr
            return self._encode(se, self.true_expr)


        true_branch_expr = self._encode(se, self.true_expr)
        false_branch_expr = self._encode(se, self.false_expr)

        return se.If(self.guard, true_branch_expr, false_branch_expr)

class ActionQueue(object):
    def __init__(self, id, actions, parent_key=None):
        self.id = id
        self.actions = actions
        self.parent_key = parent_key

class Veritesting(Analysis):
    # A cache for CFG we generated before
    cfg_cache = { }
    # Names of all stashes we will return from Veritesting
    all_stashes = ('successful', 'errored', 'deadended', 'deviated', 'unconstrained')

    def __init__(self, input_path, boundaries=None, loop_unrolling_limit=10, enable_function_inlining=False,
                 terminator=None, deviation_filter=None, path_callback=None):
        """
        SSE stands for Static Symbolic Execution, and we also implemented an extended version of Veritesting (Avgerinos,
        Thanassis, et al, ICSE 2014).

        :param input_path: The initial path to begin the execution with
        :param boundaries: Addresses where execution should stop
        :param loop_unrolling_limit: The maximum times that Veritesting should unroll a loop for
        :param enable_function_inlining: Whether we should enable function inlining and syscall inlining
        :param terminator: A callback function that takes a path as parameter. Veritesting will terminate if this function
                            returns True
        :param deviation_filter: A callback function that takes a path as parameter. Veritesting will put the path into
                                "deviated" stash if this function returns True
        :param path_callback: A callback function that takes a path as parameter. Veritesting will call this function on every
                            single path after their next_run is created.
        """
        self._input_path = input_path
        self._boundaries = boundaries if boundaries is not None else [ ]
        self._loop_unrolling_limit = loop_unrolling_limit
        self._enable_function_inlining = enable_function_inlining
        self._terminator = terminator
        self._deviation_filter = deviation_filter
        self._path_callback = path_callback

        self.actionqueue_ctr = count()

        l.info("Static symbolic execution starts at 0x%x", self._input_path.addr)
        l.debug("The execution will terminate at the following addresses: [ %s ]",
                ", ".join([ hex(i) for i in self._boundaries ]))
        l.debug("A loop will be unrolled by a maximum of %d times.", self._loop_unrolling_limit)
        if self._enable_function_inlining:
            l.debug("Function inlining is enabled.")
        else:
            l.debug("Function inlining is disabled.")

        self._input_path.state.options.add(o.TRACK_ACTION_HISTORY)
        result, final_path_group = self._veritesting()
        self._input_path.state.options.discard(o.TRACK_ACTION_HISTORY)
        for a in final_path_group.stashes:
            final_path_group.apply(stash=a, path_func=lambda p: p.state.options.discard(o.TRACK_ACTION_HISTORY))

        self.result = result
        self.final_path_group = final_path_group

    def _veritesting(self):
        """
        Perform static symbolic execution starting from the given point
        """

        p = self._input_path.copy()

        try:
            new_path_group = self._execute_and_merge(p)

        except (ClaripyError, SimError, AngrError):
            if not BYPASS_VERITESTING_EXCEPTIONS in p.state.options:
                raise
            else:
                l.warning("Veritesting caught an exception.", exc_info=True)
            return False, PathGroup(self.project, stashes={'deviated', p})

        except VeritestingError as ex:
            l.warning("Exception occurred: %s", str(ex))
            return False, PathGroup(self.project, stashes={'deviated', p})

        l.info('Returning a set of new paths: %s (successful: %s, deadended: %s, errored: %s, deviated: %s)',
                new_path_group,
                new_path_group.successful,
                new_path_group.deadended,
                new_path_group.errored,
                new_path_group.deviated
              )

        return True, new_path_group

    def _execute_and_merge(self, path):
        """
        Symbolically execute the program in a static manner. The basic idea is that, we look ahead by creating a CFG,
        then perform a _controlled symbolic exploration_ based on the CFG, one path at a time. The controlled symbolic
        exploration stops when it sees a branch whose both directions are all feasible, or it shall wait for a merge
        from another path.

        A basic block will not be executed for more than *loop_unrolling_limit* times. If that is the case, a new state
        will be returned.

        :param path: The initial path to start the execution
        :return: A list of new states
        """

        state = path.state
        se = state.se
        ip_int = path.addr

        # Remove path._run
        path._run = None

        # Build a CFG out of the current function

        cfg_key = (ip_int, path.jumpkind)
        if cfg_key in self.cfg_cache:
            cfg, cfg_graph_with_loops = self.cfg_cache[cfg_key]

        else:
            if self._enable_function_inlining:
                call_tracing_filter = CallTracingFilter(self.project, depth=0)
                filter = call_tracing_filter.filter
            else:
                filter = None
            # To better handle syscalls, we make a copy of all registers if they are not symbolic
            cfg_initial_state = self.project.factory.blank_state(mode='fastpath')
            # FIXME: This is very hackish
            # FIXME: And now only Linux-like syscalls are supported
            if self.project.arch.name == 'X86':
                if not state.se.symbolic(state.regs.eax):
                    cfg_initial_state.regs.eax = state.regs.eax
            elif self.project.arch.name == 'AMD64':
                if not state.se.symbolic(state.regs.rax):
                    cfg_initial_state.regs.rax = state.regs.rax

            cfg = self.project.analyses.CFG(starts=((ip_int, path.jumpkind),),
                                               context_sensitivity_level=0,
                                               call_depth=0,
                                               call_tracing_filter=filter,
                                               initial_state=cfg_initial_state
                                               )
            cfg.normalize()
            cfg_graph_with_loops = networkx.DiGraph(cfg.graph)
            cfg.unroll_loops(self._loop_unrolling_limit)

            self.cfg_cache[cfg_key] = (cfg, cfg_graph_with_loops)

        loop_backedges = cfg._loop_back_edges
        loop_heads = set([ dst.addr for _, dst in loop_backedges ])

        # Find all merge points
        merge_points = self._get_all_merge_points(cfg, cfg_graph_with_loops)
        l.debug('Merge points: %s', [ hex(i[0]) for i in merge_points ])

        #
        # Controlled symbolic exploration
        #

        # Initialize the beginning path
        initial_path = path
        initial_path.info['loop_ctrs'] = defaultdict(int)
        initial_path.info['actionqueue_list'] = [ self._new_actionqueue() ]

        # This is a special hack for CGC stuff, since the CGCAnalysis relies on correct conditions of file actions
        # Otherwise we may just save out those actions, and then copy them back when returning those paths
        initial_path.actions = [ a for a in initial_path.actions if a.type.startswith('file') ]

        path_group = PathGroup(self.project,
                               active_paths=[ initial_path ],
                               immutable=False,
                               resilience=o.BYPASS_VERITESTING_EXCEPTIONS in initial_path.state.options)
        # Initialize all stashes
        for stash in self.all_stashes:
            path_group.stashes[stash] = [ ]
        # immediate_dominators = cfg.immediate_dominators(cfg.get_any_node(ip_int))

        saved_paths = { }

        def is_path_errored(path):
            if path.errored:
                return True
            elif len(path.jumpkinds) > 0 and path.jumpkinds[-1] in Path._jk_all_bad:
                l.debug("Errored jumpkind %s", path.jumpkinds[-1])
                path._error = AngrPathError('path has a failure jumpkind of %s' % path.jumpkinds[-1])
            else:
                try:
                    if path._run is None:
                        ip = path.addr
                        # FIXME: cfg._nodes should also be updated when calling cfg.normalize()
                        size_of_next_irsb = [n for n in cfg.graph.nodes() if n.addr == ip][0].size
                        path.step(max_size=size_of_next_irsb)
                except (AngrError, SimError, ClaripyError) as ex:
                    l.debug('is_path_errored(): caxtching exception %s', ex)
                    path._error = ex
                except (TypeError, ValueError, ArithmeticError, MemoryError) as ex:
                    l.debug("is_path_errored(): catching exception %s", ex)
                    path._error = ex

            return False

        def is_path_overbound(path):
            """
            Filter out all paths that run out of boundaries or loop too many times
            """

            ip = path.addr

            if ip in self._boundaries:
                l.debug("... terminating Veritesting due to overbound")
                return True

            if (ip in loop_heads # This is the beginning of the loop
                    or path.jumpkind == 'Ijk_Call' # We also wanna catch recursive function calls
                    ):
                path.info['loop_ctrs'][ip] += 1

                if path.info['loop_ctrs'][ip] >= self._loop_unrolling_limit + 1:
                    l.debug('... terminating Veritesting due to overlooping')
                    return True

            l.debug('... accepted')
            return False


        def generate_successors(path):
            ip = path.addr

            l.debug("Pushing 0x%x one step forward...", ip)

            # FIXME: cfg._nodes should also be updated when calling cfg.normalize()
            size_of_next_irsb = [ n for n in cfg.graph.nodes() if n.addr == ip ][0].size
            # It has been called by is_path_errored before, but I'm doing it here anyways. Who knows how the logic in
            # PathGroup will change in the future...
            path.step(max_size=size_of_next_irsb)

            # Now it's safe to call anything that may access Path.next_run
            if self._path_callback:
                copied_path = path.copy()
                self._unfuck(copied_path)
                self._path_callback(copied_path)

            successors = path.successors

            # Get all unconstrained successors, and save them out
            if path.next_run:
                for s in path.next_run.unconstrained_successors:
                    u_path = Path(self.project, s, path=path)
                    path_group.stashes['unconstrained'].append(u_path)

            # Record their guards :-)
            for successing_path in successors:
                if 'guards' not in successing_path.info:
                    successing_path.info['guards'] = [ ]
                last_guard = successing_path.guards[-1]
                if not successing_path.state.se.is_true(last_guard):
                    successing_path.info['guards'].append(last_guard)

            # Fill the ActionQueue list
            if len(successors) == 1:
                # Expand the last ActionQueue
                if not successors[0].info['actionqueue_list']:
                    successors[0].info['actionqueue_list'].append(self._new_actionqueue())
                self._get_last_actionqueue(successors[0]).actions.extend(successors[0].last_actions)

            elif len(successors) > 1:
                # Save this current path, since we might need it in the future
                path_key = (path.addr, self._get_last_actionqueue(path).id)
                saved_paths[path_key] = path

                # Generate a new ActionQueue for each successor
                for successing_path in successors:
                    successing_path.info['actionqueue_list'].append(self._new_actionqueue(parent_key=path_key))
                    self._get_last_actionqueue(successing_path).actions.extend(successing_path.last_actions)

            l.debug("... new successors: %s", successors)
            return successors

        def _path_not_in_cfg(p):
            """
            Returns if p.addr is not a proper node in our CFG

            :param p: The Path instance to test.
            :return: False if our CFG contains p.addr, True otherwise
            """

            n = cfg.get_any_node(p.addr, is_syscall=p.jumpkinds[-1].startswith('Ijk_Sys'))
            if n is None:
                return True

            if n.simprocedure_name == 'PathTerminator':
                return True

            return False

        while path_group.active:
            # Step one step forward
            l.debug('Steps %s with %d active paths: [ %s ]',
                    path_group,
                    len(path_group.active),
                    path_group.active)

            # Apply self.deviation_func on every single active path, and move them to deviated stash if needed
            if self._deviation_filter is not None:
                path_group.stash(filter_func=self._deviation_filter, from_stash='active', to_stash='deviated')

            # Mark all those paths that are out of boundaries as successful
            path_group.stash(filter_func=is_path_overbound, from_stash='active', to_stash='successful')

            path_group.step(successor_func=generate_successors, check_func=is_path_errored)
            if self._terminator is not None and self._terminator(path_group):
                for p in path_group.unfuck:
                    self._unfuck(p)
                break

            # Stash all paths that we do not see in our CFG
            path_group.stash(filter_func=_path_not_in_cfg,
                             to_stash="deviated"
                             )

            # Stash all paths that we do not care about
            path_group.stash(filter_func=
                             lambda p: (p.state.scratch.jumpkind not in
                                            ('Ijk_Boring', 'Ijk_Call', 'Ijk_Ret', 'Ijk_NoHook')
                                        and not p.state.scratch.jumpkind.startswith('Ijk_Sys')
                             ),
                             to_stash="deadended"
                             )
            if path_group.deadended:
                l.debug('Now we have some deadended paths: %s', path_group.deadended)

            # Stash all possible paths that we should merge later
            for merge_point_addr, merge_point_looping_times in merge_points:
                path_group.stash_addr(merge_point_addr,
                                 to_stash="_merge_%x_%d" % (merge_point_addr, merge_point_looping_times)
                                 )

            # Try to merge a set of previously stashed paths, and then unstash them
            if not path_group.active:
                merged_anything = False

                for merge_point_addr, merge_point_looping_times in merge_points:
                    if merged_anything:
                        break

                    stash_name = "_merge_%x_%d" % (merge_point_addr, merge_point_looping_times)

                    if stash_name in path_group.stashes:
                        # Try to prune the stash, so unsatisfiable paths will be thrown away
                        path_group.prune(from_stash=stash_name, to_stash='pruned')
                        if 'pruned' in path_group.stashes and len(path_group.pruned):
                            l.info('... pruned %d paths from stash %s', len(path_group.pruned), stash_name)
                        # Remove the pruned stash to save memory
                        path_group.drop(stash='pruned')

                        stash = path_group.stashes[stash_name]
                        if not len(stash):
                            continue

                        # Group all those paths based on their callstacks
                        groups = defaultdict(list)
                        for p in stash:
                            groups[p.callstack].append(p)

                        l.debug('Trying to merge and activate stash %s', stash_name)
                        l.debug('%d paths are grouped into %d groups based on their callstacks',
                               len(stash),
                               len(groups)
                               )

                        for g in groups.itervalues():
                            if len(g) == 1:
                                # Just unstash it
                                p = g[0]
                                path_group.stashes[stash_name].remove(p)

                                if any([loop_ctr >= self._loop_unrolling_limit + 1 for loop_ctr in p.info['loop_ctrs'].itervalues()]):
                                    l.debug("%s is overlooping", p)
                                    path_group.deadended.append(p)
                                else:
                                    l.debug('Put %s into active stash', p)
                                    path_group.active.append(p)
                                merged_anything = True

                            elif len(g) > 1:
                                for p in g:
                                    path_group.stashes[stash_name].remove(p)

                                # Merge them first

                                # Find the previous dominator for all those
                                # Determine their common ancestor
                                ancestor_key = self._determine_ancestor(g)
                                initial_path = saved_paths[ancestor_key]
                                merged_path = self._merge_path_list(se, initial_path, g)

                                if any([ loop_ctr >= self._loop_unrolling_limit + 1 for loop_ctr in merged_path.info['loop_ctrs'].itervalues() ]):
                                    l.debug("%s is overlooping", merged_path)
                                    path_group.deadended.append(merged_path)
                                else:
                                    l.debug('Put %s into active stash', p)
                                    path_group.active.append(merged_path)

                                merged_anything = True

        if any([ len(path_group.stashes[stash_name]) for stash_name in self.all_stashes]):
            # Remove all stashes other than errored or deadended
            path_group.stashes = { name: stash for name, stash in path_group.stashes.items()
                                   if name in self.all_stashes }

            for stash in path_group.stashes:
                path_group.apply(lambda p: self._unfuck(p), stash=stash)

        return path_group

    @staticmethod
    def _unfuck(p):
        del p.info['actionqueue_list']
        del p.info['loop_ctrs']

        if 'guards' in p.info:
            del p.info['guards']
        if 'loop_ctrs' in p.info:
            del p.info['loop_ctrs']
        if 'actions' in p.info:
            #p.actions = p.actions + p.info['actions']
            #p.last_actions = p.last_actions + p.info['actions']
            del p.info['actions']
        else:
            pass

        return p

    def _merge_path_list(self, se, base_path, path_list):
        merge_info = [ ]
        for path_to_merge in path_list:
            inputs, outputs = self._io_interface(se, path_to_merge.actions, base_path.actions)
            merge_info.append((path_to_merge, inputs, outputs))
        l.info('Merging %d paths: [ %s ].',
               len(merge_info),
               ", ".join([str(p) for p, _, _ in merge_info])
               )
        merged_path = self._merge_paths(base_path, merge_info)
        l.info('... merged.')

        return merged_path

    def _merge_paths(self, base_path, merge_info_list):

        def find_real_ref(ref, ref_list):
            """
            Returns the last element r in ref_list that satisfies r == ref
            """
            for r in reversed(ref_list):
                if r == ref:
                    return r
            return None

        # Perform merging
        all_outputs = [ ]
        # Merge all outputs together into all_outputs
        # The order must be kept since actions should be applied one by one in order
        # Complexity of the current implementation sucks...
        # TODO: Optimize the complexity of the following loop
        for _, _, outputs in merge_info_list:
            for ref in reversed(outputs):
                if ref not in all_outputs:
                    all_outputs.append(ref)

        all_outputs = reversed(all_outputs)
        merged_path = base_path.copy()  # We make a copy first
        # merged_path.actions = [ ]
        merged_path.last_actions = [ ]
        # merged_path.events = [ ]
        merged_state = merged_path.state
        merged_path.info['actionqueue_list'].append(self._new_actionqueue((merged_path.addr, self._get_last_actionqueue(merged_path).id)))

        for ref in all_outputs:
            last_ip = None

            all_values = [ ]
            all_guards = [ ]

            for i, merge_info in enumerate(merge_info_list):
                final_path, _, outputs = merge_info

                # First we should build the value
                if ref in outputs:
                    # Find the real ref
                    real_ref = find_real_ref(ref, outputs)

                    # Read the final value
                    if real_ref.type == 'mem':
                        v = real_ref.value

                    elif real_ref.type == 'reg':
                        v = real_ref.value

                    elif real_ref.type.startswith('file'):
                        v = real_ref.value

                    else:
                        raise VeritestingError('FINISH ME')

                    if real_ref.type == 'reg' and real_ref.offset == self.project.arch.ip_offset:
                        # Sanity check!
                        if last_ip is None:
                            last_ip = v
                        else:
                            if merged_state.se.is_true(last_ip != v):
                                raise VeritestingError("We don't want to merge IP - something is seriously wrong")

                    # Then we build one more layer of our ITETree
                    guards = final_path.info['guards']
                    guard = merged_state.se.And(*guards) if guards else merged_state.se.true

                    all_values.append(v)
                    all_guards.append(guard)

            max_value_size = max([ v.size() for v in all_values ])

            # Optimization: if all values are of the same size, we can remove one to reduce the number of ITEs
            # FIXME: this optimization doesn't make sense at all.
            #sizes_of_value = set([ v.size() for v in all_values ])
            #if len(sizes_of_value) == 1 and len(all_values) == len(merge_info_list):
            #    all_values = all_values[ 1 : ]
            #    all_guards = all_guards[ 1 : ]

            # Write the output to merged_state

            merged_actions = [ ]
            if real_ref.type == 'mem':
                for actual_addr in real_ref.actual_addrs:
                    # Create the merged_action, and memory.store_cases will fill it up
                    merged_action = SimActionData(merged_state, 'mem', 'write',
                                                  addr=merged_state.se.BVV(actual_addr, self.project.arch.bits),
                                                  size=max_value_size)
                    merged_state.memory.store_cases(actual_addr, all_values, all_guards, endness='Iend_BE', action=merged_action)

                    merged_actions.append(merged_action)

            elif real_ref.type == 'reg':
                if real_ref.offset != self.project.arch.ip_offset:
                    # Create the merged_action, and memory.store_cases will fill it up
                    merged_action = SimActionData(merged_state, 'reg', 'write', addr=real_ref.offset, size=max_value_size)
                    merged_state.registers.store_cases(real_ref.offset, all_values, all_guards, endness='Iend_BE', action=merged_action)
                else:
                    # Create the merged_action, and memory.store_cases will fill it up
                    merged_action = SimActionData(merged_state, 'reg', 'write', addr=real_ref.offset, size=max_value_size)
                    merged_state.registers.store(real_ref.offset, last_ip, action=merged_action)
                merged_actions.append(merged_action)

            elif real_ref.type.startswith('file'):
                # No matter it's a read or a write, we should always write it at the desired place
                # However, we don't have to create the SimAction here
                for actual_addr in real_ref.actual_addrs:
                    # FIXME: We assume no new files were opened
                    file_id = real_ref.type[ real_ref.type.index('_') + 1 : ]
                    file_id = merged_state.posix.filename_to_fd(file_id[ : file_id.index('_') ])
                    merged_action = SimActionData(merged_state, real_ref.type, real_ref.action, addr=actual_addr, size=max_value_size)
                    merged_state.posix.files[file_id].content.store_cases(actual_addr, all_values, all_guards, endness='Iend_BE', action=merged_action)

                    merged_actions.append(merged_action)

            else:
                 l.error('Unsupported Ref type %s in path merging', real_ref.type)

            if merged_actions:
                for merged_action in merged_actions:
                    merged_path.actions.append(merged_action)
                    merged_path.last_actions.append(merged_action)
                    self._get_last_actionqueue(merged_path).actions.append(merged_action)

        # Merge *all* actions
        '''
        for i, merge_info in enumerate(merge_info_list):
            final_path, _, _ = merge_info

            guards = final_path.info['guards']
            guard = merged_state.se.And(*guards) if guards else None

            for action in final_path.actions:
                if action.type == 'tmp':
                    continue
                # Encode the constraint into action.condition
                action = action.copy()
                if guard is not None:
                    if action.condition is None:
                        action.condition = action._make_object(guard)
                    else:
                        action.condition.ast = merged_state.se.And(action.condition.ast, guard)
                if 'actions' not in merged_path.info:
                    merged_path.info['actions'] = [ ]

                merged_path.info['actions'].append(action)
        '''

        # Fix backtrace of the merged path
        merged_path.addr_backtrace.append(-1)
        merged_path.backtrace.append('Veritesting')

        # Add extra constraints from original paths to the merged path
        # It's really important to not lose them. Yan has a lot to say about it.
        all_constraints = [ ]
        for final_path, _, _ in merge_info_list:
            if final_path.info['guards']:
                se = final_path.state.se
                guards = final_path.info['guards']

                # There are also some extra constraints that are encoded in SimActionConstraint objects
                # We don't want to lose them for sure.
                #
                # constraints = [ ]
                #for a in [ b for b in final_path.actions if b.type == 'constraint' ]:
                #    if not final_path.state.se.is_true(a.constraint.ast):
                #        print "CONSTRAINT: ", a.constraint.ast, "CONDITION: ", a.condition
                #        __import__('ipdb').set_trace()
                constraints = [ (a.constraint if a.condition is None
                                     else se.And(a.constraint, a.condition))
                                    for a in final_path.actions if a.type == 'constraint'
                                ]
                all_constraints.append(se.And(*(guards + constraints)))
        if all_constraints:
            merged_state.add_constraints(merged_state.se.Or(*all_constraints))

        # Fixing the callstack of the merged path
        merged_path.callstack = merge_info_list[0][0].callstack

        # Fix the loop_ctrs
        new_loop_ctrs = defaultdict(int)
        for final_path, _, _ in merge_info_list:
            for loop_head_addr, looping_times in final_path.info['loop_ctrs'].iteritems():
                if looping_times > new_loop_ctrs[loop_head_addr]:
                    new_loop_ctrs[loop_head_addr] = looping_times
        merged_path.info['loop_ctrs'] = new_loop_ctrs

        #
        # Clean the stage
        #

        if 'guards' in merged_path.info:
            del merged_path.info['guards']

        # Clear the Path._run, otherwise Path.successors will not generate a new run
        merged_path._run = None

        return merged_path

    def _unpack_action_obj(self, action_obj):
        return action_obj.ast

    def _io_interface(self, se, actions, base_actions):
        """
        Get inputs and outputs by parsing the action list.

        :param se:
        :param actions:
        :param base_actions:
        :return:
        """

        outputs = [ ]

        # TODO: More optimization could be done. For example, we should grab actions out of ActionQueue lists, instead
        # TODO: of comparing them one by one

        start_pos = 0
        for i in xrange(min(len(actions), len(base_actions))):
            a = actions[i]
            b = base_actions[i]

            if a.type == b.type:
                if a.type == 'constraint':
                    # We don't care about constraint actions
                    pass
                elif a.type == 'exit':
                    if a.exit_type == b.exit_type and hash(a.target.ast) == hash(b.target.ast) :
                        pass
                    else:
                        break
                else:
                    if (
                        (a.addr is None and b.addr is None) or
                        (hash(a.addr.ast) == hash(b.addr.ast))
                    ) and (
                        (hash(a.size.ast) == hash(b.size.ast))
                    ):
                        pass
                    else:
                        break
            else:
                break

            start_pos = i + 1

        written_reg_offsets = set()
        written_mem_addrs = set()
        for a in reversed(actions[start_pos : ]):
            if a.type == 'reg':
                size = self._unpack_action_obj(a.size)
                value = self._unpack_action_obj(a.actual_value) if a.actual_value is not None else None
                offset = self._unpack_action_obj(a.addr)
                actual_offsets = a.actual_addrs if a.actual_addrs else [ offset ]
                # Neither offset nor size can be symbolic
                ref = Ref('reg', offset, actual_offsets, size, value, a)

                #if a.action == 'read':
                #    for actual_offset in actual_offsets:
                #        if actual_offset not in written_reg_offsets:
                #            inputs.append(ref)

                if a.action == 'write':
                    # FIXME: Consider different sizes
                    if all([ o in written_reg_offsets for o in actual_offsets ]):
                        continue

                    outputs.append(ref)
                    for actual_offset in actual_offsets:
                        written_reg_offsets.add(actual_offset)

            elif a.type == 'mem':
                addr = self._unpack_action_obj(a.addr)
                actual_addrs = a.actual_addrs if a.actual_addrs else [ addr ]
                size = self._unpack_action_obj(a.size)
                value = self._unpack_action_obj(a.actual_value) if a.actual_value is not None else None
                ref = Ref('mem', addr, actual_addrs, size, value, a)

                #if a.action == 'read':
                #    for actual_addr in actual_addrs:
                #        if actual_addr not in written_mem_addrs:
                #            inputs.append(ref)
                #            break

                if a.action == 'write':
                    # FIXME: Consider different sizes
                    if all([ o in written_mem_addrs for o in actual_addrs ]):
                        continue

                    outputs.append(ref)
                    for actual_addr in actual_addrs:
                        written_mem_addrs.add(actual_addr)

            elif a.type == 'exit':
                target = self._unpack_action_obj(a.target)

                ref = Ref('reg', self.project.arch.ip_offset, [ self.project.arch.ip_offset ], target.size(), target, a)
                outputs.append(ref)

            elif a.type.startswith('file'):
                addr = self._unpack_action_obj(a.addr)
                actual_addrs = a.actual_addrs if a.actual_addrs else [ addr ]
                size = self._unpack_action_obj(a.size)
                value = self._unpack_action_obj(a.actual_value) if a.actual_value is not None else \
                    self._unpack_action_obj(a.data)
                ref = Ref(a.type, addr, actual_addrs, size, value, a)

                outputs.append(ref)
                # TODO: Write it to a dict

            elif a.type != 'tmp':
                # l.warning('Unsupported action type %s in _io_interface', a.type)
                pass

        inputs = [ ] #list(reversed(inputs))
        outputs = list(reversed(outputs))

        return inputs, outputs

    def _post_dominate(self, reversed_graph, n1, n2):
        """
        Checks whether n1 post-dominates n2 in the *original* (not reversed) graph
        :param reversed_graph: The reversed networkx.DiGraph instance
        :param n1: Node 1
        :param n2: Node 2
        :return: True/False
        """

        ds = networkx.dominating_set(reversed_graph, n1)
        return n2 in ds

    def _get_all_merge_points(self, cfg, graph_with_loops):
        """
        Return all possible merge points in this CFG.
        :param cfg: The control flow graph, which must be acyclic
        :return: a list of merge points
        """

        graph = networkx.DiGraph(cfg.graph)
        reversed_cyclic_graph = networkx.reverse(graph_with_loops, copy=False)

        # Remove all "FakeRet" edges
        fakeret_edges = [ (src, dst) for src, dst, data in graph.edges_iter(data=True)
                          if data['jumpkind'] == 'Ijk_FakeRet' ]
        graph.remove_edges_from(fakeret_edges)

        # Remove all "FakeRet" edges from cyclic_graph as well
        fakeret_edges = [(src, dst) for src, dst, data in reversed_cyclic_graph.edges_iter(data=True)
                         if data['jumpkind'] == 'Ijk_FakeRet']
        reversed_cyclic_graph.remove_edges_from(fakeret_edges)

        # Perform a topological sort
        sorted_nodes = networkx.topological_sort(graph)

        nodes = [ n for n in sorted_nodes if graph.in_degree(n) > 1 and n.looping_times == 0 ]

        # Reorder nodes based on post-dominance relations
        nodes = sorted(nodes,
                       cmp=lambda n1, n2: 1 if self._post_dominate(reversed_cyclic_graph, n1, n2)
                       else (-1 if self._post_dominate(reversed_cyclic_graph, n2, n1)
                        else 0)
                       )

        return list([ (n.addr, n.looping_times) for n in nodes ])

    def _new_actionqueue(self, parent_key=None):
        return ActionQueue(self.actionqueue_ctr.next(), [ ], parent_key=parent_key)

    def _get_last_actionqueue(self, path):
        if not path.info['actionqueue_list']:
            return None
        return path.info['actionqueue_list'][-1]

    def _determine_ancestor(self, path_list):
        # Scan through their ActionQueueList, and return the last common ancestor key
        min_actionqueue_list_size = min(len(p.info['actionqueue_list']) for p in path_list)
        ancestor_key = None
        for i in xrange(0, min_actionqueue_list_size):
            all_keys_set = set()
            for p in path_list:
                all_keys_set.add(p.info['actionqueue_list'][i].parent_key)

            if len(all_keys_set) > 1:
                break

            ancestor_key = list(all_keys_set)[0]

        return ancestor_key

register_analysis(Veritesting, 'Veritesting')

from simuvex import SimValueError, SimSolverModeError, SimError, SimActionData
from simuvex.s_options import BYPASS_VERITESTING_EXCEPTIONS
from claripy import ClaripyError
