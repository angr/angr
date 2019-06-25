
from .xref_types import XRefType
from ...serializable import Serializable


class XRef(Serializable):

    __slots__ = ('type', 'src', 'dst', )

    def __init__(self, xref_type, src, dst):
        self.type = xref_type
        self.src = src
        self.dst = dst

    def __repr__(self):
        return "<XRef %s: %s->%s>" % (
            XRefType.to_string(self.type),
            self.src,
            self.dst
        )

    def __eq__(self, other):
        return type(other) is XRef and \
               other.type == self.type and \
               other.from_loc == self.src and \
               other.to_loc == self.dst

    def __hash__(self):
        return hash((XRef, self.type, self.src, self.dst))
