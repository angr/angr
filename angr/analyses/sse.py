import logging

from ..surveyors import Explorer
from ..analysis import Analysis

l = logging.getLogger('angr.analyses.sse')
# FIXME: Remove this line
l.setLevel(logging.DEBUG)

logging.getLogger('angr.surveyors.explorer').setLevel(logging.DEBUG)

class SSE(Analysis):
    def __init__(self, input_state):
        self._input_state = input_state

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
        except Exception:
            return False, s

        return True, new_state

    def _execute_and_merge(self, state):

        se = state.se
        ip = state.ip
        ip_int = se.exactly_int(ip)

        # Get all successors
        simrun = self._p.sim_run(state)
        all_successors = simrun.successors

        l.debug("Got %d successors: %s", len(all_successors), all_successors)

        next_merge_points = self._next_merge_points(ip_int)
        if len(next_merge_points) == 0:
            # TODO:
            raise Exception('PUT ME IN')
        l.debug("Next merge points: %s", ",".join([ hex(x) for x in next_merge_points ]))

        # initial_state, final_state, inputs, outputs, guard
        merge_info = [ ]
        assert len(all_successors) == 2
        for a in all_successors:
            guard = a.log.guard
            # Run until the next merge point
            starting_path = self._p.path_generator.blank_path(a)
            explorer = Explorer(self._p, start=starting_path, find=next_merge_points)
            r = explorer.run()

            assert len(r.found) == 1

            final_path = r.found[0]
            final_state = final_path.state

            # Traverse the action list to get inputs and outputs
            inputs, outputs = self._io_interface(se, final_path.actions)
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
                        raise Exception('FINISH ME')

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
                        raise Exception('FINISH ME')

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
        cfg = self._p.analyses.CFG(starts=(ip,), context_sensitivity_level=0, call_depth=1)

        traversed_irsbs = set()
        # BFS
        start = cfg.get_any_node(ip)
        traversed_irsbs.add(start.addr)

        queue = [ (start, 0) ]
        merge_points = [ ]
        while queue:
            node, distance = queue[0]
            queue = queue[ 1 : ]

            successors_and_jumpkind = cfg.get_successors_and_jumpkind(node, excluding_fakeret=True)
            for s, j in successors_and_jumpkind:
                if j == 'Ijk_Boring':
                    if s.addr in traversed_irsbs:
                        merge_points.append((s.addr, distance + 1))

                    else:
                        traversed_irsbs.add(s.addr)
                        queue.append((s, distance + 1))

                else:
                    break

        merge_points = list(set(merge_points))
        merge_points = sorted(merge_points, key=lambda i: i[1])

        return [ m[0] for m in merge_points ]
