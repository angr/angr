from __future__ import annotations
from typing import Literal, TypeVar, Generic
from dataclasses import dataclass
import logging

from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal
from angr.sim_variable import SimTemporaryVariable
from angr.sim_variable import SimMemoryVariable
from angr.sim_variable import SimStackVariable
from angr.sim_variable import SimRegisterVariable
from angr.misc.ux import once

from ...engines.light import SpOffset
from ...code_location import CodeLocation, ExternalCodeLocation
from .atoms import Atom, MemoryLocation, Register, Tmp, AtomKind, atom_kind_mapping, VirtualVariable
from .tag import Tag
from ...sim_variable import SimVariable

log = logging.getLogger(__name__)


@dataclass
class DefinitionMatchPredicate:
    """
    A dataclass indicating several facts which much all must match in order for a definition to match. Largely an
    internal class; don't worry about this.
    """

    kind: AtomKind | type[Atom] | None = None
    bbl_addr: int | None = None
    ins_addr: int | None = None
    variable: SimVariable | None = None
    variable_manager: VariableManagerInternal | None | Literal[False] = None
    stack_offset: int | None = None
    reg_name: str | int | None = None
    heap_offset: int | None = None
    global_addr: int | None = None
    tmp_idx: int | None = None
    const_val: int | None = None
    extern: bool | None = None

    @staticmethod
    def construct(predicate: DefinitionMatchPredicate | None = None, **kwargs) -> DefinitionMatchPredicate:
        if predicate is None:
            predicate = DefinitionMatchPredicate(**kwargs)
            predicate.normalize()
        return predicate

    def normalize(self):
        if self.variable is not None:
            if isinstance(self.variable, SimRegisterVariable):
                self.reg_name = self.variable.reg
            elif isinstance(self.variable, SimStackVariable):
                if self.variable.base != "bp":
                    log.warning("Cannot match against variables with %s base (need bp)", self.variable.base)
                else:
                    self.stack_offset = self.variable.offset
            elif isinstance(self.variable, SimMemoryVariable):
                # TODO region
                if isinstance(self.variable.addr, int):
                    self.global_addr = self.variable.addr
                else:
                    log.warning(
                        "Cannot match against memory variable with %s addr (need int)",
                        type(self.variable.addr).__name__,
                    )
            elif isinstance(self.variable, SimTemporaryVariable):
                self.tmp_idx = self.variable.tmp_id
            else:
                log.warning(
                    "Cannot match against definition to %s (need reg, stack, mem, or tmp)", type(self.variable).__name__
                )

        if self.reg_name is not None:
            self.kind = AtomKind.REGISTER
        elif self.stack_offset is not None or self.heap_offset is not None or self.global_addr is not None:
            self.kind = AtomKind.MEMORY
        elif self.const_val is not None:
            self.kind = AtomKind.CONSTANT
        elif self.tmp_idx is not None:
            self.kind = AtomKind.TMP

    def matches(self, defn: Definition) -> bool:
        if self.variable is not None:
            if self.variable_manager is False:
                pass
            elif self.variable_manager is not None:
                if not self.variable_manager.is_variable_used_at(
                    self.variable, (defn.codeloc.bbl_addr, defn.codeloc.stmt_idx)
                ):
                    return False
            elif once("definition_matches_no_variable_manager"):
                log.warning(
                    "Cannot match definitions to variables on the basis of locations without a variable manager."
                )
                log.warning("Pass variable_manager=False to acknowledge this explicitly.")
        if self.bbl_addr is not None and defn.codeloc.block_addr != self.bbl_addr:
            return False
        if self.ins_addr is not None and defn.codeloc.ins_addr != self.ins_addr:
            return False
        if self.extern is not None and isinstance(defn.codeloc, ExternalCodeLocation) != self.extern:
            return False

        if self.kind is not None:
            if not isinstance(self.kind, type):
                self.kind = atom_kind_mapping[self.kind]
            if not isinstance(defn.atom, self.kind):
                return False

        if isinstance(defn.atom, Register):
            if self.reg_name is not None:
                if isinstance(self.reg_name, int):
                    if not defn.atom.reg_offset <= self.reg_name < defn.atom.reg_offset + defn.atom.size:
                        return False
                elif isinstance(self.reg_name, str):
                    if defn.atom.arch is not None:
                        if self.reg_name != defn.atom.name:
                            return False
                    else:
                        log.warning(
                            "Attempting to match by register name against a definition which does not have an arch"
                        )
                        return False
                else:
                    raise TypeError(self.reg_name)
        elif isinstance(defn.atom, MemoryLocation):
            if self.stack_offset is not None and (
                not isinstance(defn.atom.addr, SpOffset)
                or defn.atom.addr.base != "sp"  # TODO???????
                or defn.atom.addr.offset != self.stack_offset
            ):
                return False
        elif isinstance(defn.atom, Tmp) and self.tmp_idx is not None and self.tmp_idx != defn.atom.tmp_idx:
            return False

        return True


A = TypeVar("A", bound=Atom)


class Definition(Generic[A]):
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

    def __init__(self, atom: A, codeloc: CodeLocation, dummy: bool = False, tags: set[Tag] | None = None):
        self.atom: A = atom
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
        if isinstance(self.atom, MemoryLocation):
            if isinstance(self.atom.addr, SpOffset):
                return self.atom.addr.offset
            return self.atom.addr
        raise ValueError(f"Unsupported operation offset on {type(self.atom)}.")

    @property
    def size(self) -> int:
        if isinstance(self.atom, Register):
            return self.atom.size
        if isinstance(self.atom, MemoryLocation):
            return self.atom.bits // 8
        if isinstance(self.atom, VirtualVariable):
            return self.atom.size
        raise ValueError(f"Unsupported operation size on {type(self.atom)}.")

    def matches(self, **kwargs) -> bool:
        """
        Return whether this definition has certain characteristics.

        """
        return DefinitionMatchPredicate.construct(**kwargs).matches(self)
