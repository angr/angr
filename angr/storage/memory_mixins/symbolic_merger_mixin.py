from __future__ import annotations
from collections.abc import Iterable
from typing import Any

import claripy

from . import MemoryMixin


class SymbolicMergerMixin(MemoryMixin):
    def _merge_values(self, values: Iterable[tuple[Any, Any]], merged_size: int, **kwargs):
        merged_val = claripy.BVV(0, merged_size * self.state.arch.byte_width)
        for tm, fv in values:
            merged_val = claripy.If(fv, tm, merged_val)
        return merged_val
