
import itertools


class Manager(object):
    def __init__(self, name=None, arch=None):
        self.name = name
        self.arch = arch

        self.atom_ctr = itertools.count()

        ###
        # vex specific
        ###
        self.tyenv = None

    def next_atom(self):
        return self.atom_ctr.next()

    def reset(self):
        self.atom_ctr = itertools.count()
