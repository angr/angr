import logging
l = logging.getLogger("angr.codenode")


class CodeNode(object):

    __slots__ = ['addr', 'size', '_graph', 'thumb', '_hash']

    def __init__(self, addr, size, graph=None, thumb=False):
        self.addr = addr
        self.size = size
        self.thumb = thumb
        self._graph = graph

        self._hash = None

    def __len__(self):
        return self.size

    def __eq__(self, other):
        if type(other) is Block:  # pylint: disable=unidiomatic-typecheck
            raise TypeError("You do not want to be comparing a CodeNode to a Block")
        return type(self) is type(other) and \
            self.addr == other.addr and \
            self.size == other.size and \
            self.is_hook == other.is_hook and \
            self.thumb == other.thumb

    def __ne__(self, other):
        return not self == other

    def __cmp__(self, other):
        raise TypeError("Comparison with a code node")

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((self.addr, self.size))
        return self._hash

    def successors(self):
        if self._graph is None:
            raise ValueError("Cannot calculate successors for graphless node")
        return list(self._graph.successors(self))

    def predecessors(self):
        if self._graph is None:
            raise ValueError("Cannot calculate predecessors for graphless node")
        return list(self._graph.predecessors(self))

    def __getstate__(self):
        return (self.addr, self.size)

    def __setstate__(self, dat):
        self.__init__(*dat)

    is_hook = None


class BlockNode(CodeNode):

    __slots__ = ['bytestr']

    is_hook = False
    def __init__(self, addr, size, bytestr=None, **kwargs):
        super(BlockNode, self).__init__(addr, size, **kwargs)
        self.bytestr = bytestr

    def __repr__(self):
        return '<BlockNode at %#x (size %d)>' % (self.addr, self.size)

    def __getstate__(self):
        return (self.addr, self.size, self.bytestr, self.thumb)

    def __setstate__(self, dat):
        self.__init__(*dat[:-1], thumb=dat[-1])


class HookNode(CodeNode):

    __slots__ = ['sim_procedure']

    is_hook = True
    def __init__(self, addr, size, sim_procedure, **kwargs):
        super(HookNode, self).__init__(addr, size, **kwargs)
        self.sim_procedure = sim_procedure

    def __repr__(self):
        return '<HookNode %r at %#x (size %s)>' % (self.sim_procedure, self.addr, self.size)

    def __hash__(self):
        return hash((self.addr, self.size, self.sim_procedure))

    def __eq__(self, other):
        return super(HookNode, self).__eq__(other) and \
            self.sim_procedure == other.sim_procedure

    def __getstate__(self):
        return (self.addr, self.size, self.sim_procedure)

    def __setstate__(self, dat):
        self.__init__(*dat)

from .block import Block
