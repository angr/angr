from typing import Set

import archinfo

from ...keyed_region import KeyedRegion
from .domain import BaseConstraint


class FunctionPrototypeAnalysisState:
    def __init__(self, arch: archinfo.Arch):
        self.arch = arch
        self.registers = KeyedRegion()  # indexed by register offset
        self.stack = KeyedRegion()  # indexed by stack offset
        self.constraints: Set[BaseConstraint] = set()

    def copy(self) -> 'FunctionPrototypeAnalysisState':
        r = FunctionPrototypeAnalysisState(self.arch)
        r.registers = self.registers.copy()
        r.stack = self.stack.copy()
        r.constraints = self.constraints.copy()
        return r

    def merge(self, *others) -> 'FunctionPrototypeAnalysisState':
        state = self.copy()
        for other in others:
            other: 'FunctionPrototypeAnalysisState'
            state.registers.merge(other.registers)
            state.stack.merge(other.stack)
            state.constraints |= other.constraints
        return state
