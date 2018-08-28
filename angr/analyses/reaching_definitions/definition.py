
from .atoms import MemoryLocation, Register
from .dataset import DataSet


class Definition(object):
    def __init__(self, atom, codeloc, data):

        self.atom = atom
        self.codeloc = codeloc
        self.data = data

        # convert everything into a DataSet
        if not isinstance(self.data, DataSet):
            self.data = DataSet(self.data, self.data.bits)

    def __eq__(self, other):
        return self.atom == other.atom and self.codeloc == other.codeloc and self.data == other.data

    def __repr__(self):
        return 'Definition %#x {Atom: %s, Codeloc: %s, Data: %s}' % (id(self), self.atom, self.codeloc, self.data)

    def __hash__(self):
        return hash((self.atom, self.codeloc, self.data))

    @property
    def offset(self):
        if type(self.atom) is MemoryLocation:
            return self.atom.addr
        elif type(self.atom) is Register:
            return self.atom.reg_offset
        else:
            raise ValueError('Unsupported operation offset on %s.' % type(self.atom))

    @property
    def size(self):
        if type(self.atom) is MemoryLocation:
            return self.atom.size
        elif type(self.atom) is Register:
            return self.atom.size
        else:
            raise ValueError('Unsupported operation size on %s.' % type(self.atom))
