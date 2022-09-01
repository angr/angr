from typing import Set

from ...engines.light import SpOffset
from ...code_location import CodeLocation
from .atoms import Atom, MemoryLocation, Register
from .tag import Tag


class Definition:
    """
    An atom definition.

    :ivar atom:     The atom being defined.
    :ivar codeloc:  Where this definition is created in the original binary code.
    :ivar data:     A concrete value (or many concrete values) that the atom holds when the definition is created.
    :ivar dummy:    Tell whether the definition should be considered dummy or not. During simplification by AILment,
                    definitions marked as dummy will not be removed.
    :ivar tags:     A set of tags containing information about the definition gathered during analyses.
    """

    __slots__ = ('atom', 'codeloc', 'data', 'dummy', 'tags', '_hash', )

    def __init__(self, atom: Atom, codeloc: CodeLocation, dummy: bool=False, tags: Set[Tag]=None):

        self.atom: Atom = atom
        self.codeloc: CodeLocation = codeloc
        self.dummy: bool = dummy
        self.tags = tags or set()
        self._hash = None

    def __eq__(self, other):
        return self.atom == other.atom and self.codeloc == other.codeloc

    def __repr__(self):
        if not self.tags:
            return '<Definition {Atom:%s, Codeloc:%s}%s>' % (self.atom, self.codeloc, "" if not self.dummy else "dummy")
        else:
            return '<Definition {Tags:%s, Atom:%s, Codeloc:%s}%s>' % (repr(self.tags), self.atom, self.codeloc,
                                                                    "" if not self.dummy else " dummy")

    def __str__(self):
        pretty_tags = "\n".join([str(tag) for tag in self.tags])
        return f"Definition:\n" \
               f"Atom: {self.atom}\n" \
               f"CodeLoc: {self.codeloc}\n" \
               f"Tags: {pretty_tags}"

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((self.atom, self.codeloc))
        return self._hash

    @property
    def offset(self) -> int:
        if isinstance(self.atom, Register):
            return self.atom.reg_offset
        elif isinstance(self.atom, MemoryLocation):
            if isinstance(self.atom.addr, SpOffset):
                return self.atom.addr.offset
            else:
                return self.atom.addr
        else:
            raise ValueError('Unsupported operation offset on %s.' % type(self.atom))

    @property
    def size(self) -> int:
        if isinstance(self.atom, Register):
            return self.atom.size
        elif isinstance(self.atom, MemoryLocation):
            return self.atom.bits // 8
        else:
            raise ValueError('Unsupported operation size on %s.' % type(self.atom))
