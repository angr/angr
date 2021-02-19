import claripy

from . import MemoryMixin
from ...errors import SimSegfaultException

class SmartFindMixin(MemoryMixin):
    def find(self, addr, needle, max_search,
             default=None,
             endness=None,
             chunk_size=None,
             max_symbolic_bytes=None,
             condition=None,
             char_size=1,
             **kwargs):

        if endness is None:
            endness = self.endness
            if endness is None:
                endness = 'Iend_BE'

        char_num = self._calc_char_num(needle, char_size)

        # chunk_size is the number of bytes to cache in memory for comparison
        if chunk_size is None:
            chunk_size = min(max_search, max(0x80, char_num))

        cases = []
        match_indices = []
        constraints = []

        try:
            for i, (subaddr, element) in enumerate(self._find_iter_items(addr, char_num, char_size, chunk_size, max_search, endness, condition, max_symbolic_bytes, **kwargs)):
                comparison, concrete_comparison = self._find_compare(element, needle, **kwargs)

                if concrete_comparison is False:
                    continue

                match_indices.append(i)
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
                return self.find(addr, needle, max_search,
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

    def _calc_char_num(self, needle, char_size):
        """
        calculate the number of chars in needle
        char can be of multiple bytes here
        """
        if type(needle) is bytes:
            return len(needle)
        bytelen = len(needle) // self.state.arch.byte_width
        if bytelen % char_size != 0:
            bytelen += char_size - (bytelen % char_size)
        return bytelen // char_size

    def _find_iter_items(self, addr, char_num, char_size, chunk_size, max_search, endness, condition, max_symbolic_bytes, **kwargs):
        """
        generate comparison items by iterating through the string
        able to handle wide characters
        """
        if condition is None:
            condition = self.state.solver.true
        chunk = None
        chunk_progress = chunk_size

        # iterate through the string by the unit of chars
        for i in range(0, max_search, char_size):
            subaddr = addr + i
            if chunk_progress == chunk_size :
                # need to prefetch a little bit more chars
                chunk = self.load(subaddr, size=char_size*(chunk_size+char_num), endness=endness, condition=condition & self._find_condition(addr + i, **kwargs), **kwargs)
                chunk_progress = 0

            chunk_idx = (chunk_progress if endness == 'Iend_BE' else chunk_size - 1 - chunk_progress)
            chunk_progress += 1
            substr = chunk.get_bytes(chunk_idx*char_size, char_num*char_size)

            # only check the first character or each symbolic character will be recorded many times
            # FIXME: this actually keeps track of "max_symbolic_chars"
            if self._find_are_bytes_symbolic(substr.get_bytes(0, char_size)) and max_symbolic_bytes is not None:
                if max_symbolic_bytes:
                    max_symbolic_bytes -= 1
                else:
                    return
            yield subaddr, substr

    def _find_are_bytes_symbolic(self, b):
        if not b.symbolic:
            return False
        if b.uninitialized:
            return True
        return len(self.state.solver.eval_upto(b, 2)) > 1

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
