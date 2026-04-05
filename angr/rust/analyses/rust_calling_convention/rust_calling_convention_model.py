from __future__ import annotations
from collections import defaultdict
from pprint import pformat
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from angr.rust.sim_type import RustSimTypeFunction


class RustCallingConventionModel:
    """Stores inferred calling convention facts for a Rust function."""

    def __init__(self):
        self.memory_writes = defaultdict(dict)
        self.callsite_memory_writes = defaultdict(dict)
        self.memory_reads = defaultdict(dict)
        self.none_discriminant = None
        self.inferred_prototype: RustSimTypeFunction | None = None
        self.has_write_to_arg0 = False
        self.const_ret_values = set()  # set of (ret_value, overflow_ret_value|None) tuples

    def __str__(self):
        return pformat({"Inferred prototype": self.inferred_prototype}, indent=2)
