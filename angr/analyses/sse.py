import logging
from collections import defaultdict

import networkx

from simuvex import SimProcedures, o

from ..errors import AngrError
from ..analysis import Analysis
from ..path_group import PathGroup
from ..path import Path, AngrPathError

l = logging.getLogger('angr.analyses.sse')

class SSEError(Exception):
    pass

class CallTracingFilter(object):
    whitelist = {
        SimProcedures['cgc']['receive'],
        SimProcedures['libc.so.6']['read'],
        }

    def __init__(self, project, depth, blacklist=None):
        self._p = project
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
            return True

        try:
            addr = call_target_state.se.exactly_int(ip)
        except (SimValueError, SimSolverModeError):
            self._skipped_targets.add(-1)
            l.debug('Rejecting target %s - cannot be concretized', ip)
            return True

        # Is it in our blacklist?
        if addr in self.blacklist:
            self._skipped_targets.add(addr)
            l.debug('Rejecting target 0x%x', addr)
            return True

        # If the target is a SimProcedure, is it on our whitelist?
        if self._p.is_hooked(addr) and type(self._p.sim_procedures[addr][0]) in CallTracingFilter.whitelist:
            # accept!
            l.debug('Accepting target 0x%x', addr)
            return False

        new_blacklist = self.blacklist[ :: ]
        new_blacklist.append(addr)
        tracing_filter = CallTracingFilter(self._p, depth=self.depth + 1, blacklist=new_blacklist)
        cfg = self._p.analyses.CFG(starts=((addr, jumpkind),),
                                   initial_state=call_target_state,
                                   context_sensitivity_level=0,
                                   call_depth=0,
                                   call_tracing_filter=tracing_filter.filter
                                   )
        cfg.unroll_loops(1)
        if cfg._loop_back_edges:
            # It has loops!
            self._skipped_targets.add(addr)
            l.debug('Rejecting target 0x%x', addr)
            return False

        sim_procedures = [ n for n in cfg.graph.nodes() if n.simprocedure_name is not None ]
        for sp_node in sim_procedures:
            if not self._p.is_hooked(sp_node.addr):
                # This is probably a PathTerminator
                # Just skip it for now
                continue

            if self._p.sim_procedures[sp_node.addr][0] not in CallTracingFilter.whitelist:
                self._skipped_targets.add(addr)
                l.debug('Rejecting target 0x%x', addr)
                return False


        if len(tracing_filter._skipped_targets):
            # Bummer
            self._skipped_targets.add(addr)
            l.debug('Rejecting target 0x%x', addr)
            return True

        # accept!
        l.debug('Accepting target 0x%x', addr)
        return False

class Ref(object):
    def __init__(self, type, addr, bits):
        """
        This is a reference object that is used internally in SSE. It holds less information than SimActions, but it
        has a little bit better interface, and saves a lot more keystrokes.
        """

        self.type = type
        self.addr = addr
        self.bits = bits

    @property
    def offset(self):
        if self.type == 'reg':
            return self.addr

    def __eq__(self, other):
        return self.type == other.type and self.addr == other.addr and self.bits == other.bits

    def __hash__(self):
        return hash("%s_%s_%s" % (self.type, self.addr, self.bits))

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
            raise SSEError('Unable to encode an empty ITETree.')
        elif self.true_expr is None:
            # Ignore the guard, and just encode the other expr
            return self._encode(se, self.false_expr)
        elif self.false_expr is None:
            # Ignore the guard, and just encode the other expr
            return self._encode(se, self.true_expr)


        true_branch_expr = self._encode(se, self.true_expr)
        false_branch_expr = self._encode(se, self.false_expr)

        return se.If(self.guard, true_branch_expr, false_branch_expr)

class SSE(Analysis):
    def __init__(self, input_path, boundaries=None, loop_unrolling_limit=10, enable_function_inlining=False):
        self._input_path = input_path
        self._boundaries = boundaries if boundaries is not None else [ ]
        self._loop_unrolling_limit = loop_unrolling_limit
        self._enable_function_inlining = enable_function_inlining

        l.debug("Static symbolic execution starts at 0x%x", self._input_path.addr)
        l.debug("The execution will terminate at the following addresses: [ %s ]",
                ", ".join([ hex(i) for i in self._boundaries ]))
        l.debug("A loop will be unrolled by a maximum of %d times.", self._loop_unrolling_limit)
        if self._enable_function_inlining:
            l.debug("Function inlining is enabled.")
        else:
            l.debug("Function inlining is disabled.")

        result, final_path_group = self._sse()

        self.result = {
            'result': result,
            'final_path_group': final_path_group,
        }

    def _sse(self):
        """
        Perform static symbolic execution starting from the given point
        """

        p = self._input_path.copy()

        try:
            new_path_group = self._execute_and_merge(p)
        except SSEError as ex:
            l.debug("Exception occurred: %s", str(ex))
            return False, PathGroup(self._p, stashes={'deadended', p})

        l.debug('Returning a set of new paths: %s (deadended: %s, errored: %s, deviated: %s)',
                new_path_group,
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
        ip = state.ip
        ip_int = se.exactly_int(ip)

        # Build a CFG out of the current function

        if self._enable_function_inlining:
            call_tracing_filter = CallTracingFilter(self._p, depth=0)
            filter = call_tracing_filter.filter
        else:
            filter = None
        cfg = self._p.analyses.CFG(starts=(ip_int,),
                                   context_sensitivity_level=0,
                                   call_depth=0,
                                   call_tracing_filter=filter
                                   )
        cfg.normalize()
        cfg.unroll_loops(self._loop_unrolling_limit)
        loop_backedges = cfg._loop_back_edges
        loop_heads = set([ dst.addr for _, dst in loop_backedges ])

        # Find all merge points
        merge_points = self._get_all_merge_points(cfg)

        #
        # Controlled symbolic exploration
        #

        # Initialize the beginning path
        initial_path = path
        initial_path.info['loop_ctrs'] = defaultdict(int)

        # Save the actions, then clean it since we gotta use actions
        saved_actions = initial_path.actions
        initial_path.actions = [ ]

        path_group = PathGroup(self._p, active_paths=[ initial_path ], immutable=False)
        immediate_dominators = cfg.immediate_dominators(cfg.get_any_node(ip_int))

        path_states = { }

        def is_path_errored(path):
            if path._error is not None:
                return path._error
            elif len(path.jumpkinds) > 0 and path.jumpkinds[-1] in Path._jk_all_bad:
                l.debug("Errored jumpkind %s", path.jumpkinds[-1])
                path._error = AngrPathError('path has a failure jumpkind of %s' % path.jumpkinds[-1])
            else:
                try:
                    if path._run is None:
                        ip = path.addr
                        # FIXME: cfg._nodes should also be updated when calling cfg.normalize()
                        size_of_next_irsb = [n for n in cfg.graph.nodes() if n.addr == ip][0].size
                        path.make_sim_run_with_size(size_of_next_irsb)
                except (AngrError, SimError, ClaripyError) as e:
                    l.debug("Catching exception", exc_info=True)
                    path._error = e
                except (TypeError, ValueError, ArithmeticError, MemoryError) as e:
                    l.debug("Catching exception", exc_info=True)
                    path._error = e

            return path._error


        def generate_successors(path):
            ip = path.addr

            if ip in self._boundaries:
                return [ ]

            if ip in loop_heads:
                path.info['loop_ctrs'][ip] += 1

                if path.info['loop_ctrs'][ip] >= self._loop_unrolling_limit + 1:
                    # Make it deadended by returning no successors
                    return [ ]

            path_states[path.addr] = path.state

            # FIXME: cfg._nodes should also be updated when calling cfg.normalize()
            size_of_next_irsb = [ n for n in cfg.graph.nodes() if n.addr == ip ][0].size
            # It has been called by is_path_errored before, but I'm doing it here anyways. Who knows how the logic in
            # PathGroup will change in the future...
            path.make_sim_run_with_size(size_of_next_irsb)

            successors = path.successors

            # Record their guards :-)
            for successing_path in successors:
                if 'guards' not in successing_path.info:
                    successing_path.info['guards'] = [ ]
                last_guard = successing_path.guards[-1]
                if not successing_path.state.se.is_true(last_guard):
                    successing_path.info['guards'].append(last_guard)

            return successors

        while path_group.active:
            # Step one step forward
            path_group.step(successor_func=generate_successors, check_func=is_path_errored)

            # Stash all paths that we do not see in our CFG
            path_group.stash(filter_func=
                             lambda p: (cfg.get_any_node(p.addr) is None),
                             to_stash="deviated"
                             )

            # Stash all paths that we do not care about
            path_group.stash(filter_func=
                             lambda p: (p.state.scratch.jumpkind not in ('Ijk_Boring', 'Ijk_Call', 'Ijk_Ret')
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
                for merge_point_addr, merge_point_looping_times in merge_points:
                    stash_name = "_merge_%x_%d" % (merge_point_addr, merge_point_looping_times)

                    if stash_name in path_group.stashes:
                        stash = path_group.stashes[stash_name]

                        if len(stash) == 1:
                            # Just unstash it
                            path_group.unstash_all(from_stash=stash_name, to_stash='active')
                            break

                        elif len(stash) > 1:
                            # Merge them first
                            merge_info = [ ]
                            for path_to_merge in stash:
                                inputs, outputs = self._io_interface(se, path_to_merge.actions)
                                initial_state = path_states[immediate_dominators[cfg.get_any_node(path_to_merge.addr)].addr]
                                merge_info.append((initial_state, path_to_merge, inputs, outputs))

                            merged_path = self._merge_paths(merge_info)
                            l.debug('Merging %d paths: [ %s ].',
                                    len(merge_info),
                                    ", ".join([ str(p) for _,p,_,_ in merge_info ])
                                    )

                            # Put this merged path back to the stash
                            path_group.stashes[stash_name] = [ merged_path ]
                            # Then unstash it
                            path_group.unstash_all(from_stash=stash_name, to_stash='active')

                            break

        if path_group.deadended or path_group.errored or path_group.deviated:
            # Remove all stashes other than errored or deadended
            path_group.stashes = { name: stash for name, stash in path_group.stashes.items()
                                   if name in ('errored', 'deadended', 'deviated') }

            for d in path_group.deadended + path_group.errored + path_group.deviated:
                del d.info['loop_ctrs']
                d.actions = saved_actions + d.actions

            return path_group

        else:
            return None

    def _merge_paths(self, merge_info_list):

        # Perform merging
        all_outputs = [ ]
        # Merge all outputs together into all_outputs
        # The order must be kept since actions should be applied one by one in order
        # Complexity of the current implementation sucks...
        # TODO: Make th
        for _, _, _, outputs in merge_info_list:
            for ref in outputs:
                if ref not in all_outputs:
                    all_outputs.append(ref)

        merged_path = merge_info_list[0][1].copy()  # We make a copy first
        merged_state = merged_path.state
        merged_state.se._solver.constraints = merge_info_list[0][0].se._solver.constraints[::]
        for ref in all_outputs:
            ite_tree = ITETreeNode()
            previous_ite_node = None
            current_ite_node = ite_tree

            last_ip = None

            for i, merge_info in enumerate(merge_info_list):
                initial_state, final_path, inputs, outputs = merge_info

                # First we should build the value
                if ref in outputs:
                    # Read the final value
                    if ref.type == 'mem':
                        v = final_path.state.mem_expr(ref.addr, length=ref.bits / 8)

                    elif ref.type == 'reg':
                        # FIXME: What if offset is not a multiple of arch_bits?
                        v = final_path.state.reg_expr(ref.offset, length=ref.bits / 8)

                    else:
                        raise SSEError('FINISH ME')

                else:
                    # Read the original value
                    if ref.type == 'mem':
                        v = initial_state.mem_expr(ref.addr, length=ref.bits / 8)

                    elif ref.type == 'reg':
                        # FIXME: What if offset is not a multiple of arch_bits?
                        v = initial_state.reg_expr(ref.offset, length=ref.bits / 8)

                    else:
                        raise SSEError('FINISH ME')

                if ref.type == 'reg' and ref.offset == self._p.arch.ip_offset:
                    # Sanity check!
                    if last_ip is None:
                        last_ip = v
                    else:
                        if merged_state.se.is_true(last_ip != v):
                            raise SSEError("We don't want to merge IP - something is seriously wrong")

                # Then we build one more layer of our ITETree
                if i != len(merge_info_list) - 1:
                    # Guard of this path
                    guards = final_path.info['guards']
                    current_ite_node.guard = initial_state.se.And(*guards)
                    current_ite_node.true_expr = v

                    previous_ite_node = current_ite_node
                    current_ite_node = ITETreeNode()
                    previous_ite_node.false_expr = current_ite_node

                else:
                    # We don't care about the guard anymore
                    previous_ite_node.false_expr = v

            # Create the formula
            formula = ite_tree.encode(merged_state.se)

            # Write the output to merged_state
            if ref.type == 'mem':
                merged_state.store_mem(ref.addr, formula)
                # l.debug('Value %s is stored to memory of merged state at 0x%x', formula, addr)

            elif ref.type == 'reg':
                merged_state.store_reg(ref.offset, formula)
                # l.debug('Value %s is stored to register of merged state at offset %d', formula, offset)

        del merged_path.info['guards']
        return merged_path

    def _unpack_action_obj(self, action_obj):
        return action_obj.ast

    def _io_interface(self, se, actions):
        """
        Get inputs and outputs by parsing the action list.
        :param actions:
        :return:
        """

        inputs = [ ]
        outputs = [ ]

        written_reg_offsets = set()
        written_mem_addrs = set()
        for a in actions:
            if a.type == 'reg':
                offset = a.offset
                size = self._unpack_action_obj(a.size)
                # Neither offset nor size can be symbolic
                ref = Ref('reg', offset, size)

                if a.action == 'read':
                    if offset not in written_reg_offsets:
                        inputs.append(ref)

                elif a.action == 'write':
                    outputs.append(ref)
                    # TODO: Add all possible offsets
                    written_reg_offsets.add(offset)

            elif a.type == 'mem':
                addr_expr = self._unpack_action_obj(a.addr)
                # Memory address can be symbolic, and currently we don't handle symbolic read/write
                # TODO: Handle symbolic memory addresses
                try:
                    addr = se.exactly_int(addr_expr)
                except (SimValueError, SimSolverModeError):
                    raise SSEError("Currently we cannot handle symbolic memory addresses.")

                size = self._unpack_action_obj(a.size)
                ref = Ref('mem', addr, size)

                if a.action == 'read':
                    if addr not in written_mem_addrs:
                        inputs.append(ref)

                elif a.action == 'write':
                    outputs.append(ref)
                    # TODO: Add all possible addresses
                    written_mem_addrs.add(addr)

        return inputs, outputs

    def _get_all_merge_points(self, cfg):
        """
        Return all possible merge points in this CFG.
        :param cfg: The control flow graph, which must be acyclic
        :return: a list of merge points
        """

        graph = networkx.DiGraph(cfg.graph)

        # Remove all "FakeRet" edges
        fakeret_edges = [ (src, dst) for src, dst, data in graph.edges_iter(data=True)
                          if data['jumpkind'] == 'Ijk_FakeRet' ]
        graph.remove_edges_from(fakeret_edges)

        # Perform a topological sort
        sorted_nodes = networkx.topological_sort(graph)

        nodes = [ n for n in sorted_nodes if graph.in_degree(n) > 1 ]

        return list([ (n.addr, n.looping_times) for n in nodes ])

from simuvex import SimValueError, SimSolverModeError
