import logging
from collections import defaultdict

import networkx

from simuvex import SimProcedures, o

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

        :param call_target_state:   The new state of the call target.
        :param jumpkind:            The Jumpkind of this call.
        :returns:                   True if we want to skip this call, False otherwise.
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
            tmp_path.step()
            next_run = tmp_path.next_run
            if type(next_run) in CallTracingFilter.whitelist:
                # accept!
                l.debug('Accepting target 0x%x, jumpkind %s', addr, jumpkind)
                return ACCEPT
            else:
                # reject
                l.debug('Rejecting target 0x%x - syscall %s not in whitelist', addr, type(next_run))
                return REJECT

        cfg_key = (addr, jumpkind)
        if cfg_key not in self.cfg_cache:
            new_blacklist = self.blacklist[ :: ]
            new_blacklist.append(addr)
            tracing_filter = CallTracingFilter(self.project, depth=self.depth + 1, blacklist=new_blacklist)
            cfg = self.project.analyses.CFGAccurate(starts=((addr, jumpkind),),
                                                    initial_state=call_target_state,
                                                    context_sensitivity_level=0,
                                                    call_depth=1,
                                                    call_tracing_filter=tracing_filter.filter,
                                                    normalize=True
                                                    )
            self.cfg_cache[cfg_key] = (cfg, tracing_filter)

            try:
                cfg.force_unroll_loops(1)
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


class Veritesting(Analysis):
    # A cache for CFG we generated before
    cfg_cache = { }
    # Names of all stashes we will return from Veritesting
    all_stashes = ('successful', 'errored', 'deadended', 'deviated', 'unconstrained')

    def __init__(
        self, input_path, boundaries=None, loop_unrolling_limit=10, enable_function_inlining=False,
        terminator=None, deviation_filter=None, path_callback=None
    ):
        """
        SSE stands for Static Symbolic Execution, and we also implemented an extended version of Veritesting (Avgerinos,
        Thanassis, et al, ICSE 2014).

        :param input_path:               The initial path to begin the execution with.
        :param boundaries:               Addresses where execution should stop.
        :param loop_unrolling_limit:     The maximum times that Veritesting should unroll a loop for.
        :param enable_function_inlining: Whether we should enable function inlining and syscall inlining.
        :param terminator:               A callback function that takes a path as parameter. Veritesting will terminate
                                         if this function returns True.
        :param deviation_filter:         A callback function that takes a path as parameter. Veritesting will put the
                                         path into "deviated" stash if this function returns True.
        :param path_callback:            A callback function that takes a path as parameter. Veritesting will call this
                                         function on every single path after their next_run is created.
        """
        self._input_path = input_path.copy()
        self._boundaries = boundaries if boundaries is not None else [ ]
        self._loop_unrolling_limit = loop_unrolling_limit
        self._enable_function_inlining = enable_function_inlining
        self._terminator = terminator
        self._deviation_filter = deviation_filter
        self._path_callback = path_callback

        # set up the cfg stuff
        self._cfg, self._loop_graph = self._make_cfg()
        self._loop_backedges = self._cfg._loop_back_edges
        self._loop_heads = set([ dst.addr for _, dst in self._loop_backedges ])

        l.info("Static symbolic execution starts at 0x%x", self._input_path.addr)
        l.debug(
            "The execution will terminate at the following addresses: [ %s ]",
            ", ".join([ hex(i) for i in self._boundaries ])
        )

        l.debug("A loop will be unrolled by a maximum of %d times.", self._loop_unrolling_limit)
        if self._enable_function_inlining:
            l.debug("Function inlining is enabled.")
        else:
            l.debug("Function inlining is disabled.")

        self.result, self.final_path_group = self._veritesting()

    def _veritesting(self):
        """
        Perform static symbolic execution starting from the given point.
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

        l.info(
            'Returning new paths: (successful: %s, deadended: %s, errored: %s, deviated: %s)',
            len(new_path_group.successful), len(new_path_group.deadended),
            len(new_path_group.errored), len(new_path_group.deviated)
        )

        return True, new_path_group

    def _execute_and_merge(self, path):
        """
        Symbolically execute the program in a static manner. The basic idea is that we look ahead by creating a CFG,
        then perform a _controlled symbolic exploration_ based on the CFG, one path at a time. The controlled symbolic
        exploration stops when it sees a branch whose both directions are all feasible, or it shall wait for a merge
        from another path.

        A basic block will not be executed for more than *loop_unrolling_limit* times. If that is the case, a new state
        will be returned.

        :param path: The initial path to start the execution.
        :returns:    A list of new states.
        """

        # Remove path._run
        path._run = None

        # Find all merge points
        merge_points = self._get_all_merge_points(self._cfg, self._loop_graph)
        l.debug('Merge points: %s', [ hex(i[0]) for i in merge_points ])

        #
        # Controlled symbolic exploration
        #

        # Initialize the beginning path
        initial_path = path
        initial_path.info['loop_ctrs'] = defaultdict(int)

        path_group = PathGroup(
            self.project,
            active_paths=[ initial_path ],
            immutable=False,
            resilience=o.BYPASS_VERITESTING_EXCEPTIONS in initial_path.state.options
        )

        # Initialize all stashes
        for stash in self.all_stashes:
            path_group.stashes[stash] = [ ]
        # immediate_dominators = cfg.immediate_dominators(cfg.get_any_node(ip_int))

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
            path_group.stash(
                filter_func=self.is_path_overbound,
                from_stash='active', to_stash='successful'
            )

            path_group.step(
                successor_func=lambda p: self.generate_successors(p, path_group),
                check_func=self.is_path_errored
            )
            if self._terminator is not None and self._terminator(path_group):
                for p in path_group.unfuck:
                    self._unfuck(p)
                break

            # Stash all paths that we do not see in our CFG
            path_group.stash(
                filter_func=self._path_not_in_cfg,
                to_stash="deviated"
            )

            # Stash all paths that we do not care about
            path_group.stash(
                filter_func= lambda p: (
                    p.state.scratch.jumpkind not in
                    ('Ijk_Boring', 'Ijk_Call', 'Ijk_Ret', 'Ijk_NoHook')
                    and not p.state.scratch.jumpkind.startswith('Ijk_Sys')
                ),
                to_stash="deadended"
            )

            if path_group.deadended:
                l.debug('Now we have some deadended paths: %s', path_group.deadended)

            # Stash all possible paths that we should merge later
            for merge_point_addr, merge_point_looping_times in merge_points:
                path_group.stash_addr(
                    merge_point_addr,
                    to_stash="_merge_%x_%d" % (merge_point_addr, merge_point_looping_times)
                )

            # Try to merge a set of previously stashed paths, and then unstash them
            if not path_group.active:
                merged_anything = False

                for merge_point_addr, merge_point_looping_times in merge_points:
                    if merged_anything:
                        break

                    stash_name = "_merge_%x_%d" % (merge_point_addr, merge_point_looping_times)
                    if stash_name not in path_group.stashes:
                        continue

                    stash_size = len(path_group.stashes[stash_name])
                    if stash_size == 0:
                        continue
                    if stash_size == 1:
                        l.info("Skipping merge of 1 path in stash %s.", stash_size)
                        path_group.move(stash_name, 'active')
                        continue

                    # let everyone know of the impending disaster
                    l.info("Merging %d paths in stash %s", stash_size, stash_name)

                    # Try to prune the stash, so unsatisfiable paths will be thrown away
                    path_group.prune(from_stash=stash_name, to_stash='pruned')
                    if 'pruned' in path_group.stashes and len(path_group.pruned):
                        l.debug('... pruned %d paths from stash %s', len(path_group.pruned), stash_name)
                    # Remove the pruned stash to save memory
                    path_group.drop(stash='pruned')

                    # merge things callstack by callstack
                    while len(path_group.stashes[stash_name]):
                        r = path_group.stashes[stash_name][0]
                        path_group.move(
                            stash_name, 'merge_tmp',
                            lambda p: p.callstack == r.callstack #pylint:disable=cell-var-from-loop
                        )

                        old_count = len(path_group.merge_tmp)
                        l.debug("... trying to merge %d paths.", old_count)

                        # merge the loop_ctrs
                        new_loop_ctrs = defaultdict(int)
                        for m in path_group.merge_tmp:
                            for head_addr, looping_times in m.info['loop_ctrs'].iteritems():
                                new_loop_ctrs[head_addr] = max(
                                    looping_times,
                                    m.info['loop_ctrs'][head_addr]
                                )

                        path_group.merge(stash='merge_tmp')
                        for m in path_group.merge_tmp:
                            m.info['loop_ctrs'] = new_loop_ctrs

                        new_count = len(path_group.stashes['merge_tmp'])
                        l.debug("... after merge: %d paths.", new_count)

                        merged_anything |= new_count != old_count

                        if len(path_group.merge_tmp) > 1:
                            l.warning("More than 1 path after Veritesting merge.")
                            path_group.move('merge_tmp', 'active')
                        elif any(
                            loop_ctr >= self._loop_unrolling_limit + 1 for loop_ctr in
                            path_group.one_merge_tmp.info['loop_ctrs'].itervalues()
                        ):
                            l.debug("... merged path is overlooping")
                            path_group.move('merge_tmp', 'deadended')
                        else:
                            l.debug('... merged path going to active stash')
                            path_group.move('merge_tmp', 'active')

        if any(len(path_group.stashes[stash_name]) for stash_name in self.all_stashes):
            # Remove all stashes other than errored or deadended
            path_group.stashes = {
                name: stash for name, stash in path_group.stashes.items()
                if name in self.all_stashes
            }

            for stash in path_group.stashes:
                path_group.apply(self._unfuck, stash=stash)

        return path_group

    #
    # Path management
    #

    def is_path_errored(self, path):
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
                    size_of_next_irsb = [ n for n in self._cfg.graph.nodes() if n.addr == ip ][0].size
                    path.step(max_size=size_of_next_irsb)
            except (AngrError, SimError, ClaripyError) as ex:
                l.debug('is_path_errored(): caxtching exception %s', ex)
                path._error = ex
            except (TypeError, ValueError, ArithmeticError, MemoryError) as ex:
                l.debug("is_path_errored(): catching exception %s", ex)
                path._error = ex

        return False

    def _path_not_in_cfg(self, p):
        """
        Returns if p.addr is not a proper node in our CFG.

        :param p: The Path instance to test.
        :returns: False if our CFG contains p.addr, True otherwise.
        """

        n = self._cfg.get_any_node(p.addr, is_syscall=p.jumpkinds[-1].startswith('Ijk_Sys'))
        if n is None:
            return True

        if n.simprocedure_name == 'PathTerminator':
            return True

        return False

    def generate_successors(self, path, path_group):
        ip = path.addr

        l.debug("Pushing 0x%x one step forward...", ip)

        # FIXME: cfg._nodes should also be updated when calling cfg.normalize()
        size_of_next_irsb = [ n for n in self._cfg.graph.nodes() if n.addr == ip ][0].size
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

        l.debug("... new successors: %s", successors)
        return successors

    def is_path_overbound(self, path):
        """
        Filter out all paths that run out of boundaries or loop too many times.
        """

        ip = path.addr

        if ip in self._boundaries:
            l.debug("... terminating Veritesting due to overbound")
            return True

        if (
            ip in self._loop_heads # This is the beginning of the loop
            or path.jumpkind == 'Ijk_Call' # We also wanna catch recursive function calls
        ):
            path.info['loop_ctrs'][ip] += 1
            if path.info['loop_ctrs'][ip] >= self._loop_unrolling_limit + 1:
                l.debug('... terminating Veritesting due to overlooping')
                return True

        l.debug('... accepted')
        return False

    @staticmethod
    def _unfuck(p):
        del p.info['loop_ctrs']
        return p

    #
    # Merge point determination
    #

    def _make_cfg(self):
        """
        Builds a CFG from the current function.
        """

        path = self._input_path
        state = path.state
        ip_int = path.addr

        cfg_key = (ip_int, path.jumpkind)
        if cfg_key in self.cfg_cache:
            cfg, cfg_graph_with_loops = self.cfg_cache[cfg_key]
        else:
            if self._enable_function_inlining:
                call_tracing_filter = CallTracingFilter(self.project, depth=0)
                filter = call_tracing_filter.filter #pylint:disable=redefined-builtin
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

            cfg = self.project.analyses.CFGAccurate(
                starts=((ip_int, path.jumpkind),),
                context_sensitivity_level=0,
                call_depth=1,
                call_tracing_filter=filter,
                initial_state=cfg_initial_state,
                normalize=True,
            )
            cfg_graph_with_loops = networkx.DiGraph(cfg.graph)
            cfg.force_unroll_loops(self._loop_unrolling_limit)
            self.cfg_cache[cfg_key] = (cfg, cfg_graph_with_loops)

        return cfg, cfg_graph_with_loops

    @staticmethod
    def _post_dominate(reversed_graph, n1, n2):
        """
        Checks whether `n1` post-dominates `n2` in the *original* (not reversed) graph.

        :param reversed_graph:  The reversed networkx.DiGraph instance.
        :param n1:              Node 1.
        :param n2:              Node 2.
        :returns:               True/False.
        """

        ds = networkx.dominating_set(reversed_graph, n1)
        return n2 in ds

    def _get_all_merge_points(self, cfg, graph_with_loops):
        """
        Return all possible merge points in this CFG.

        :param cfg: The control flow graph, which must be acyclic.
        :returns:   A list of merge points.
        """

        graph = networkx.DiGraph(cfg.graph)
        reversed_cyclic_graph = networkx.reverse(graph_with_loops, copy=False)

        # Remove all "FakeRet" edges
        fakeret_edges = [
            (src, dst) for src, dst, data in graph.edges_iter(data=True)
            if data['jumpkind'] in ('Ijk_FakeRet', 'Ijk_Exit')
        ]
        graph.remove_edges_from(fakeret_edges)

        # Remove all "FakeRet" edges from cyclic_graph as well
        fakeret_edges = [
            (src, dst) for src, dst, data in reversed_cyclic_graph.edges_iter(data=True)
            if data['jumpkind'] in ('Ijk_FakeRet', 'Ijk_Exit')
        ]
        reversed_cyclic_graph.remove_edges_from(fakeret_edges)

        # Perform a topological sort
        sorted_nodes = networkx.topological_sort(graph)

        nodes = [ n for n in sorted_nodes if graph.in_degree(n) > 1 and n.looping_times == 0 ]

        # Reorder nodes based on post-dominance relations
        nodes = sorted(nodes, cmp=lambda n1, n2: (
            1 if self._post_dominate(reversed_cyclic_graph, n1, n2)
            else (-1 if self._post_dominate(reversed_cyclic_graph, n2, n1) else 0)
        ))

        return [ (n.addr, n.looping_times) for n in nodes ]

register_analysis(Veritesting, 'Veritesting')

from simuvex import SimValueError, SimSolverModeError, SimError
from simuvex.s_options import BYPASS_VERITESTING_EXCEPTIONS
from claripy import ClaripyError
