from typing import Set

from ...engines.light import SpOffset
from ...code_location import CodeLocation
from .atoms import Atom, MemoryLocation, Register, Tmp, GuardUse, ConstantSrc
from .tag import Tag


class Definition:
    """
    An atom definition.

    :ivar atom:     The atom being defined.
    :ivar codeloc:  Where this definition is created in the original binary code.
    :ivar dummy:    Tell whether the definition should be considered dummy or not. During simplification by AILment,
                    definitions marked as dummy will not be removed.
    :ivar tags:     A set of tags containing information about the definition gathered during analyses.
    """

    __slots__ = (
        "atom",
        "codeloc",
        "dummy",
        "tags",
        "_hash",
    )

    def __init__(self, atom: Atom, codeloc: CodeLocation, dummy: bool = False, tags: Set[Tag] = None):
        self.atom: Atom = atom
        self.codeloc: CodeLocation = codeloc
        self.dummy: bool = dummy
        self.tags = tags or set()
        self._hash = None

    def __eq__(self, other):
        return self.atom == other.atom and self.codeloc == other.codeloc

    def __repr__(self):
        if not self.tags:
            return "<Definition {{Atom:{}, Codeloc:{}}}{}>".format(
                self.atom, self.codeloc, "" if not self.dummy else "dummy"
            )
        else:
            return "<Definition {{Tags:{}, Atom:{}, Codeloc:{}}}{}>".format(
                repr(self.tags), self.atom, self.codeloc, "" if not self.dummy else " dummy"
            )

    def __str__(self):
        pretty_tags = "\n".join([str(tag) for tag in self.tags])
        return f"Definition:\n" f"Atom: {self.atom}\n" f"CodeLoc: {self.codeloc}\n" f"Tags: {pretty_tags}"

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
            raise ValueError("Unsupported operation offset on %s." % type(self.atom))

    @property
    def size(self) -> int:
        if isinstance(self.atom, Register):
            return self.atom.size
        elif isinstance(self.atom, MemoryLocation):
            return self.atom.bits // 8
        else:
            raise ValueError("Unsupported operation size on %s." % type(self.atom))

    def matches(self, kind=None, bbl_addr=None, ins_addr=None) -> bool:
        """
        Return whether this definition has certain characteristics.

        :param kind:        Specifies the kind of atom that must match. One of the strings "reg", "mem", "tmp",
                            "guard", "const", or None.
        :param bbl_addr:    The codeloc must be from this basic block
        :param ins_addr:    The codeloc must be from this instruction
        """
        if kind is not None:
            if kind == 'reg' and not isinstance(self.atom, Register):
                return False
            if kind == 'mem' and not isinstance(self.atom, MemoryLocation):
                return False
            if kind == 'tmp' and not isinstance(self.atom, Tmp):
                return False
            if kind == 'guard' and not isinstance(self.atom, GuardUse):
                return False
            if kind == 'const' and not isinstance(self.atom, ConstantSrc):
                return False
        if bbl_addr is not None and self.codeloc.block_addr != bbl_addr:
            return False
        if ins_addr is not None and self.codeloc.ins_addr != ins_addr:
            return False
        return True
