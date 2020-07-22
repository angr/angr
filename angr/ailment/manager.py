import itertools
from typing import Optional


class Manager:
    def __init__(self, name: Optional[str]=None, arch=None):
        self.name = name
        self.arch = arch

        self.atom_ctr = itertools.count()

        self._ins_addr: Optional[int] = None

        ###
        # vex specific
        ###
        self.vex_stmt_idx: Optional[int] = None
        self.tyenv = None
        self.block_addr = None

    def next_atom(self):
        return next(self.atom_ctr)

    def reset(self):
        self.atom_ctr = itertools.count()

    @property
    def ins_addr(self) -> Optional[int]:
        return self._ins_addr

    @ins_addr.setter
    def ins_addr(self, v):
        self._ins_addr = v
