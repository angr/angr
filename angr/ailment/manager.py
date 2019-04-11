
import itertools


class Manager(object):
    def __init__(self, name=None, arch=None):
        self.name = name
        self.arch = arch

        self.atom_ctr = itertools.count()

        self._ins_addr = None

        ###
        # vex specific
        ###
        self.tyenv = None
        self.block_addr = None

    def next_atom(self):
        return next(self.atom_ctr)

    def reset(self):
        self.atom_ctr = itertools.count()

    @property
    def ins_addr(self):
        return self._ins_addr

    @ins_addr.setter
    def ins_addr(self, v):
        self._ins_addr = v
