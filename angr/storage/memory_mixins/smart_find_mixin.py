import claripy

from . import MemoryMixin
from ...errors import SimSegfaultException

class SmartFindMixin(MemoryMixin):
    def find(self, addr, data, max_search,
             default=None,
             endness=None,
             chunk_size=None,
             max_symbolic_bytes=None,
             condition=None,
             **kwargs):

        if endness is None:
            endness = self.endness
            if endness is None:
                endness = 'Iend_BE'

        stride = self._find_stride(data)

        if chunk_size is None:
            chunk_size = min(max_search, 0x80)

        cases = []
        match_indices = []
        constraints = []

        try:
            for i, (subaddr, element) in enumerate(self._find_iter_items(addr, stride, chunk_size, max_search, endness, condition, max_symbolic_bytes, **kwargs)):
                comparison, concrete_comparison = self._find_compare(element, data, **kwargs)

                if concrete_comparison is False:
                    continue

                match_indices.append(i*stride)
                if isinstance(subaddr, int):
                    subaddr = claripy.BVV(subaddr, size=self.state.arch.bits)
                cases.append((comparison, subaddr))

                if concrete_comparison is True:
                    break

            else:
                # the loop terminated, meaning we exhausted some sort of limit instead of finding a concrete answer.
                if default is None:
                    constraints.append(claripy.Or(*(c for c, _ in cases)))
        except SimSegfaultException:
            if chunk_size > 1:
                return self.find(addr, data, max_search,
                                 default=default,
                                 endness=endness,
                                 chunk_size=1,
                                 max_symbolic_bytes=max_symbolic_bytes,
                                 condition=condition,
                                 **kwargs)
            raise

        if len(cases) == 1:
            return cases[0][1], constraints, match_indices

        return self._find_process_cases(cases, match_indices, constraints, default, **kwargs)

    def _find_stride(self, target):
        if type(target) is bytes:
            return len(target)
        return len(target) // self.state.arch.byte_width

    def _find_iter_items(self, addr, stride, chunk_size, max_search, endness, condition, max_symbolic_bytes, **kwargs):
        if condition is None:
            condition = self.state.solver.true
        chunk = None
        chunk_progress = chunk_size
        for i in range(0, max_search, stride):
            subaddr = addr + i
            if chunk_progress == chunk_size:
                chunk = self.load(subaddr, size=stride*chunk_size, endness=endness, condition=condition & self._find_condition(addr + i, **kwargs), **kwargs)
                chunk_progress = 0

            chunk_idx = (chunk_progress if endness == 'Iend_BE' else chunk_size - 1 - chunk_progress)*stride
            chunk_progress += 1
            b = chunk.get_bytes(chunk_idx, stride)

            if self._find_are_bytes_symbolic(b) and max_symbolic_bytes is not None:
                if max_symbolic_bytes:
                    max_symbolic_bytes -= 1
                else:
                    return
            yield subaddr, b

    def _find_are_bytes_symbolic(self, b):
        return b.symbolic

    def _find_condition(self, target_addr, **kwargs):
        # TODO: fill this in in order to make each load have the correct condition associated with it
        return claripy.true

    def _find_compare(self, element, target, **kwargs):
        comparison = element == target
        if self.state.solver.is_true(comparison):
            concrete_comparison = True
        elif self.state.solver.is_false(comparison):
            concrete_comparison = False
        else:
            concrete_comparison = None
        return comparison, concrete_comparison

    def _find_process_cases(self, cases, match_indices, constraints, default, **kwargs):
        if default is None:
            default = claripy.BVV(0, self.state.arch.bits)
        if cases and cases[-1][0].is_true():
            default = cases.pop(-1)[1]
        result = self.state.solver.ite_cases(cases, default)
        return result, constraints, match_indices
