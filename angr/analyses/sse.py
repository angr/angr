import logging
from collections import defaultdict

import networkx

from ..analysis import Analysis
from ..path_group import PathGroup

l = logging.getLogger('angr.analyses.sse')
# FIXME: Remove this line
l.setLevel(logging.DEBUG)

logging.getLogger('angr.surveyors.explorer').setLevel(logging.DEBUG)

class SSEError(Exception):
    pass



class SSE(Analysis):
    def __init__(self, input_path, boundaries=None, loop_unrolling_limit=10):
        self._input_path = input_path
        self._boundaries = boundaries if boundaries is not None else [ ]
        self._loop_unrolling_limit = loop_unrolling_limit

        l.debug("Static symbolic execution starts at 0x%x", self._input_path.addr)
        l.debug("The execution will terminate at the following addresses: [ %s ]",
                ", ".join([ hex(i) for i in self._boundaries ]))
        l.debug("A loop will be unrolled by a maximum of %d times.", self._loop_unrolling_limit)

        result, final_path_group = self._sse()

        self.result = {
            'result': result,
            'final_path_group': final_path_group,
        }

    def _sse(self):
        """
        Perform static symbolic execution starting from the given point
        """
        from pprint import pprint

        p = self._input_path.copy()

        try:
            new_path_group = self._execute_and_merge(p)
        except SSEError as ex:
            l.debug("Exception occurred: %s", str(ex))
            return False, PathGroup(self._p, stashes={'deadended', p})

        l.debug('Returning a set of new paths: %s (%s)', new_path_group, new_path_group.deadended)
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
        cfg = self._p.analyses.CFG(starts=(ip_int,),
                                   context_sensitivity_level=0,
                                   call_depth=0
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
            path.make_sim_run_with_size(size_of_next_irsb)

            successors = path.successors

            return successors

        while path_group.active:
            # Step one step forward
            path_group.step(successor_func=generate_successors)

            # Stash all paths that we do not care about
            path_group.stash(filter_func=
                             lambda p: (p.state.scratch.jumpkind != 'Ijk_Boring'),
                             to_stash="deadended"
                             )
            if path_group.deadended:
                l.debug('Now we have some deadended paths: %s', path_group.deadended)

            # Stash all possible paths that we should merge later
            for merge_point_addr, merge_point_looping_times in merge_points:
                path_group.stash(filter_func=
                                 lambda p: (p.addr == merge_point_addr), # and
                                            # p.addr_backtrace.count(merge_point_addr) == self._loop_unrolling_limit + 1),
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

                        elif len(stash) > 1:
                            # Merge them first
                            merge_info = [ ]
                            for path_to_merge in stash:
                                inputs, outputs = self._io_interface(se, path_to_merge.actions)
                                # TODO: guards[-1] doesn't always make sense
                                initial_state = path_states[immediate_dominators[cfg.get_any_node(path_to_merge.addr)].addr]
                                merge_info.append((initial_state, path_to_merge, inputs, outputs, path_to_merge.guards[-1]))

                            merged_path = self._merge_paths(merge_info)
                            l.debug('Merging is performed between %d paths.', len(merge_info))

                            # Put this merged path back to the stash
                            path_group.stashes[stash_name] = [ merged_path ]
                            # Then unstash it
                            path_group.unstash_all(from_stash=stash_name, to_stash='active')

        if path_group.deadended:
            # Remove all stashes other than errored or deadended
            path_group.stashes = { name: stash for name, stash in path_group.stashes.items() if name in ('errored', 'deadended') }

            for d in path_group.deadended + path_group.errored:
                del d.info['loop_ctrs']
                d.actions = saved_actions + d.actions

            return path_group

        else:
            return [ ]

    def _merge_paths(self, merge_info):

        # Perform merging
        all_outputs = set()
        for _, _, _, outputs, _ in merge_info:
            all_outputs |= set(outputs)

        merged_path = merge_info[0][1].copy()  # We make a copy first
        merged_state = merged_path.state
        merged_state.se._solver.constraints = merge_info[0][0].se._solver.constraints[::]
        for tpl in all_outputs:
            if_guard = None
            if_trueexpr = None
            if_falseexpr = None

            for initial_state, final_path, inputs, outputs, guard in merge_info:
                if tpl in outputs:
                    # Read the final value
                    if tpl[0] == 'mem':
                        addr, size = tpl[1], tpl[2]
                        v = final_path.state.mem_expr(addr, size)

                    elif tpl[0] == 'reg':
                        offset, size = tpl[1], tpl[2]
                        # FIXME: What if offset is not a multiple of arch_bits?
                        v = final_path.state.reg_expr(offset)

                    else:
                        raise SSEError('FINISH ME')

                    # Create the formula
                    if if_guard is None:
                        if_guard = guard
                        if_trueexpr = v

                    else:
                        if_falseexpr = v

                else:
                    # Read the original value
                    if tpl[0] == 'mem':
                        addr, size = tpl[1], tpl[2]
                        v = initial_state.mem_expr(addr, size)

                    elif tpl[0] == 'reg':
                        offset, size = tpl[1], tpl[2]
                        # FIXME: What if offset is not a multiple of arch_bits?
                        v = initial_state.reg_expr(offset)

                    else:
                        raise SSEError('FINISH ME')

                    if if_guard is None:
                        if_guard = guard
                        if_trueexpr = v

                    else:
                        if_falseexpr = v

            # Create the formula
            formula = merged_state.se.If(if_guard, if_trueexpr, if_falseexpr)

            # Write the output to merged_state
            if tpl[0] == 'mem':
                addr, size = tpl[1], tpl[2]
                merged_state.store_mem(addr, formula)
                # l.debug('Value %s is stored to memory of merged state at 0x%x', formula, addr)

            elif tpl[0] == 'reg':
                offset, size = tpl[1], tpl[2]

                if offset == self._p.arch.ip_offset and merged_state.se.is_true(if_falseexpr != if_trueexpr):
                    raise SSEError('We don\'t want to merge IP')

                merged_state.store_reg(offset, formula)
                # l.debug('Value %s is stored to register of merged state at offset %d', formula, offset)

        return merged_path

    def _unpack_action_obj(self, action_obj):
        return action_obj.ast

    def _io_interface(self, se, actions):
        """
        Get inputs and outputs by parsing the action list.
        :param actions:
        :return:
        """

        inputs = set()
        outputs = set()

        written_reg_offsets = set()
        written_mem_addrs = set()
        for a in actions:
            if a.type == 'reg':
                offset = a.offset
                size = self._unpack_action_obj(a.size)

                if a.action == 'read':
                    if offset not in written_reg_offsets:
                        inputs.add(('reg', offset, size))

                elif a.action == 'write':
                    outputs.add(('reg', offset, size))
                    # TODO: Add all possible offsets
                    written_reg_offsets.add(offset)

            elif a.type == 'mem':
                addr = se.any_int(self._unpack_action_obj(a.addr))
                size = self._unpack_action_obj(a.size)

                if a.action == 'read':
                    if addr not in written_mem_addrs:
                        inputs.add(('mem', addr, size))

                elif a.action == 'write':
                    outputs.add(('mem', addr, size))
                    # TODO: Add all possible addresses
                    written_mem_addrs.add(('mem', addr))

        return inputs, outputs

    def _get_all_merge_points(self, cfg):
        """
        Return all possible merge points in this CFG.
        :param cfg: The control flow graph, which must be acyclic
        :return: a list of merge points
        """

        graph = cfg.graph

        # Perform a topological sort
        sorted_nodes = networkx.topological_sort(graph)

        nodes = [ n for n in sorted_nodes if graph.in_degree(n) > 1 ]

        return list([ (n.addr, n.looping_times) for n in nodes ])
