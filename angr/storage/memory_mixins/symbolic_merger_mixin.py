from typing import Any
from collections.abc import Iterable

from . import MemoryMixin


class SymbolicMergerMixin(MemoryMixin):
    def _merge_values(self, values: Iterable[tuple[Any, Any]], merged_size: int, **kwargs):
        merged_val = self.state.solver.BVV(0, merged_size * self.state.arch.byte_width)
        for tm, fv in values:
            merged_val = self.state.solver.If(fv, tm, merged_val)
        return merged_val
