from __future__ import annotations

import itertools


class Manager:
    _block_addr: int

    def __init__(self, name: str | None = None, arch=None):
        self.name = name
        self.arch = arch

        self.atom_ctr = itertools.count()

        # An optional side container (analyses.decompiler.VariableMap) that maps atom .idx values to variable-related
        # information. It is attached by Clinic so that optimization passes, peephole optimizations, and region
        # simplifiers (all of which hold a reference to this Manager) can read and update variable information without
        # storing it on the AIL atoms themselves. Kept untyped here to avoid an ailment->angr import dependency.
        self.variable_map = None

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
