from __future__ import annotations

import itertools
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from angr.analyses.decompiler.variable_map import VariableMap


class Manager:
    """
    AIL manager class used during AIL generation and simplification.
    """

    _block_addr: int

    def __init__(self, name: str | None = None, arch=None):
        self.name = name
        self.arch = arch

        self.atom_ctr = itertools.count()

        # Attached by Clinic so that optimization passes, peephole optimizations, and region
        # simplifiers can use VariableMap.
        self.variable_map: VariableMap | None = None

        self._ins_addr: int | None = None

        ###
        # vex specific
        ###
        self.vex_stmt_idx: int | None = None
        self.tyenv = None

    def next_atom(self):
        return next(self.atom_ctr)

    def reset(self):
        self.atom_ctr = itertools.count()

    @property
    def ins_addr(self) -> int | None:
        return self._ins_addr

    @ins_addr.setter
    def ins_addr(self, v):
        self._ins_addr = v
