import logging

import networkx

from ..surveyors import Explorer
from ..analysis import Analysis

l = logging.getLogger('angr.analyses.sse')
# FIXME: Remove this line
l.setLevel(logging.DEBUG)

logging.getLogger('angr.surveyors.explorer').setLevel(logging.DEBUG)

class SSEError(Exception):
    pass

class SSE(Analysis):
    def __init__(self, input_state):
        self._input_state = input_state

        l.debug("Start Veritesting at %s", self._input_state.ip)
        result, final_state = self._sse()

        self.result = {
            'result': result,
            'final_state': final_state,
        }

    def _sse(self):
        """
        Perform static symbolic execution starting from the given point
        """
        from pprint import pprint

        s = self._input_state.copy()

        try:
            new_state = self._execute_and_merge(s)
        except SSEError as ex:
            l.debug("Exception occurred: %s", str(ex))
            return False, s

        return True, new_state

    def _execute_and_merge(self, state):

        se = state.se
        ip = state.ip
        ip_int = se.exactly_int(ip)

        # Get all successors
        simrun = self._p.sim_run(state)
        all_successors = simrun.successors

        l.debug("Got %d successors: %s", len(all_successors), [ a.ip for a in all_successors ])

        next_merge_points = self._next_merge_points(ip_int)
        if len(next_merge_points) == 0:
            # TODO:
            raise SSEError('PUT ME IN')
        l.debug("Next merge points: %s", ",".join([ hex(x) for x in next_merge_points ]))

        # initial_state, final_state, inputs, outputs, guard
        merge_info = [ ]
        if len(all_successors) != 2:
            raise SSEError('We have %d successors, but not 2' % len(all_successors))

        for a in all_successors:
            guard = a.scratch.guard
            # Run until the next merge point
            starting_path = self._p.path_generator.blank_path(a)

            #merge_point = next_merge_points[0]
            #to_avoid = next_merge_points[1 : ]

            if starting_path.addr not in next_merge_points:
                explorer = Explorer(self._p, start=starting_path, find=next_merge_points)
                r = explorer.run()

                if len(r.found) != 1:
                    raise SSEError('We cannot find any merge point (%s)' % ", ".join([ hex(n) for n in next_merge_points ]))

                final_path = r.found[0]
                # It probably needs another tick to get to the actual merge point
                if final_path.addr != next_merge_points[0]:
                    block_size = (next_merge_points[0] - final_path.addr)
                    final_path.make_sim_run_with_size(block_size)
                    final_path = final_path.successors[0]
                final_state = final_path.state

                # Traverse the action list to get inputs and outputs
                inputs, outputs = self._io_interface(se, final_path.actions)

            else:
                final_state = a
                inputs = [ ]
                outputs = [ ]

            merge_info.append((a, final_state, inputs, outputs, guard))

        # Perform merging
        all_outputs = set()
        for _, _, _, outputs, _ in merge_info:
            all_outputs |= set(outputs)

        merged_state = merge_info[0][1].copy()  # We make a copy first
        merged_state.se._solver.constraints = state.se._solver.constraints[ :: ]
        for tpl in all_outputs:
            if_guard = None
            if_trueexpr = None
            if_falseexpr = None

            for initial_state, final_state, inputs, outputs, guard in merge_info:
                if tpl in outputs:
                    # Read the final value
                    if tpl[0] == 'mem':
                        addr, size = tpl[1], tpl[2]
                        v = final_state.mem_expr(addr, size)

                    elif tpl[0] == 'reg':
                        offset, size = tpl[1], tpl[2]
                        # FIXME: What if offset is not a multiple of arch_bits?
                        v = final_state.reg_expr(offset)

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
            formula = se.If(if_guard, if_trueexpr, if_falseexpr)

            # Write the output to merged_state
            if tpl[0] == 'mem':
                addr, size = tpl[1], tpl[2]
                merged_state.store_mem(addr, formula)
                # l.debug('Value %s is stored to memory of merged state at 0x%x', formula, addr)

            elif tpl[0] == 'reg':
                offset, size = tpl[1], tpl[2]

                if offset == self._p.arch.ip_offset and se.is_true(if_falseexpr != if_trueexpr):
                    raise SSEError('We don\'t want to merge IP')

                merged_state.store_reg(offset, formula)
                # l.debug('Value %s is stored to register of merged state at offset %d', formula, offset)

        return merged_state

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

    def _next_merge_points(self, ip):
        """
        Return the closest merge point. We only tracks exits whose jumpkind is Ijk_Boring.
        :param ip: The starting point
        :return: IP of the next merge point
        """

        # Build the CFG starting from IP
        cfg = self._p.analyses.CFG(starts=(ip,), context_sensitivity_level=0, call_depth=0)
        cfg.normalize()
        cfg_graph = networkx.DiGraph()
        for src, dst in cfg.graph.edges():
            cfg_graph.add_edge(src, dst)
        # Remove edges between start_node and its two successors
        start_node = cfg.get_any_node(ip)
        successors = cfg.get_successors(start_node)
        for s in successors:
            cfg_graph.remove_edge(start_node, s)
        end_nodes = [ i for i in cfg_graph if cfg_graph.out_degree(i) == 0 and i.simprocedure_name is None ]
        if len(end_nodes) == 0:
            __import__('ipdb').set_trace()
            raise SSEError('Cannot find the end node of CFG starting at 0x%x' % ip)

        from collections import defaultdict
        merge_points = defaultdict(set)
        for end_node in end_nodes:
            doms = self._immediate_postdominators(cfg_graph, end_node)

            for s in successors:
                if s in doms:
                    merge_points[s].add(doms[s])

        print merge_points
        end_nodes = [i for i in cfg.graph if cfg.graph.out_degree(i) == 0 and i.simprocedure_name is None]
        print "Real end_nodes: ", end_nodes
        for end_node in end_nodes:
            doms = cfg.immediate_postdominators(end_node)
            if start_node in doms: print doms[start_node]
            for s in successors:
                if start_node in doms:
                    merge_points[s].add(doms[start_node])

        common_merge_points = merge_points[successors[0]].intersection(merge_points[successors[1]])
        print common_merge_points

        graph_for_verification = networkx.DiGraph()
        for src, dst, data in cfg.graph.edges(data=True):
            if data['jumpkind'] == 'Ijk_Boring':
                graph_for_verification.add_edge(src, dst)

        final_merge_points = set()
        for m in common_merge_points:
            skip = False
            for suc in successors:
                if m is not suc and m not in networkx.algorithms.descendants(graph_for_verification, suc):
                    skip = True
                    break
            if not skip: final_merge_points.add(m)

        print final_merge_points

        return [ s.addr for s in final_merge_points ]

        traversed_irsbs = set()
        minimum_distance = { }
        # BFS
        start = cfg.get_any_node(ip)

        __import__('ipdb').set_trace()
        queue = [ (start, 0) ]
        merge_points = [ ]

        while queue:
            node, distance = queue[0]
            print "Node %s, distance to starting point is %d" % (node, distance)
            queue = queue[ 1 : ]

            new_distance = distance + 1
            successors_and_jumpkind = cfg.get_successors_and_jumpkind(node, excluding_fakeret=True)
            for s, j in successors_and_jumpkind:
                if j == 'Ijk_Boring':
                    if s.addr in traversed_irsbs:
                        merge_points.append((s.addr, minimum_distance[s.addr]))

                    else:
                        traversed_irsbs.add(s.addr)
                        queue.append((s, new_distance))
                        if s.addr not in minimum_distance:
                            minimum_distance[s.addr] = new_distance

                else:
                    break

        merge_points = list(set(merge_points))
        merge_points = sorted(merge_points, key=lambda i: i[1])

        return [ m[0] for m in merge_points ]
