from typing import Iterable, Tuple, Any

from . import MemoryMixin


class SymbolicMergerMixin(MemoryMixin):
    def _merge_values(self, values: Iterable[Tuple[Any, Any]], merged_size: int, **kwargs):
        merged_val = values[0][0]
        for tm, fv in values[1:]:
            merged_val = self.state.solver.If(fv, tm, merged_val)
        return merged_val
