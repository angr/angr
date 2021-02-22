import claripy

from ..smart_find_mixin import SmartFindMixin


class StaticFindMixin(SmartFindMixin):  # pylint:disable=abstract-method
    """
    Implements data finding for abstract memory.
    """

    def find(self, addr, data, max_search,
             default=None,
             endness=None,
             chunk_size=None,
             max_symbolic_bytes=None,
             condition=None,
             char_size=1,
             **kwargs): #pylint:disable=arguments-differ

        if endness is None:
            endness = self.endness
            if endness is None:
                endness = 'Iend_BE'

        char_num = self._calc_char_num(data, char_size)

        # chunk_size is the number of bytes to cache in memory for comparison
        if chunk_size is None:
            chunk_size = min(max_search, max(0x80, char_num))

        match_indices = []

        for i, (_, element) in enumerate(self._find_iter_items(addr, char_num, char_size, chunk_size, max_search, endness, condition, max_symbolic_bytes, **kwargs)):
            comparison, concrete_comparison = self._find_compare(element, data, **kwargs)

            if comparison:
                match_indices.append(i)

            if concrete_comparison is True:
                break

        r_union = claripy.ESI(self.state.arch.bits)
        for index in match_indices:
            r_union = r_union.union(addr + index)
        return r_union, [ ], match_indices

    def _find_compare(self, element, target, **kwargs):
        elem_si = element._model_vsa  # pylint:disable=protected-access
        target_si = target._model_vsa  # pylint:disable=protected-access

        comparison, concrete_comparison = False, False

        # we only support strided intervals
        if isinstance(elem_si, claripy.vsa.StridedInterval):
            comparison = not elem_si.intersection(target_si).is_empty
            concrete_comparison = elem_si.identical(target_si)

        return comparison, concrete_comparison

    def _find_are_bytes_symbolic(self, b):
        # we only support strided intervals
        return not isinstance(b._model_vsa, claripy.vsa.StridedInterval)  # pylint:disable=protected-access
