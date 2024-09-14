from __future__ import annotations
from typing import Any, TYPE_CHECKING, overload
from collections.abc import Iterable, Generator
import weakref
import logging
from enum import Enum, auto

from collections import defaultdict

import claripy
from claripy.annotation import Annotation
import archinfo

from angr.misc.ux import deprecated
from angr.errors import SimMemoryMissingError, SimMemoryError
from angr.storage.memory_mixins import MultiValuedMemory
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.knowledge_plugins.key_definitions.definition import A
from angr.engines.light import SpOffset
from angr.code_location import CodeLocation, ExternalCodeLocation
from .atoms import Atom, Register, MemoryLocation, Tmp, ConstantSrc
from .definition import Definition, Tag
from .heap_address import HeapAddress
from .uses import Uses

if TYPE_CHECKING:
    from angr.project import Project
    from angr.storage import SimMemoryObject


l = logging.getLogger(name=__name__)


class DerefSize(Enum):
    """
    An enum for specialized kinds of dereferences

    NULL_TERMINATE -    Dereference until the first byte which could be a literal null. Return a value including the
                        terminator.
    """

    NULL_TERMINATE = auto()


#
# Annotations
#


class DefinitionAnnotation(Annotation):
    """
    An annotation that attaches a `Definition` to an AST.
    """

    __slots__ = ("definition", "_hash")

    def __init__(self, definition):
        super().__init__()
        self.definition = definition
        self._hash = hash((DefinitionAnnotation, self.definition))

    @property
    def relocatable(self):
        return True

    @property
    def eliminatable(self):
        return False

    def __hash__(self):
        return self._hash

    def __eq__(self, other: object):
        if type(other) is DefinitionAnnotation:
            return self.definition == other.definition
        return False

    def __repr__(self):
        return f"<{self.__class__.__name__}({self.definition!r})"


# pylint: disable=W1116
class LiveDefinitions:
    """
    A LiveDefinitions instance contains definitions and uses for register, stack, memory, and temporary variables,
    uncovered during the analysis.
    """

    INITIAL_SP_32BIT = 0x7FFF0000
    INITIAL_SP_64BIT = 0x7FFFFFFF0000
    _tops = {}

    __slots__ = (
        "project",
        "arch",
        "track_tmps",
        "registers",
        "stack",
        "heap",
        "memory",
        "tmps",
        "others",
        "other_uses",
        "register_uses",
        "stack_uses",
        "heap_uses",
        "memory_uses",
        "uses_by_codeloc",
        "tmp_uses",
        "_canonical_size",
        "__weakref__",
    )

    def __init__(
        self,
        arch: archinfo.Arch,
        track_tmps: bool = False,
        canonical_size=8,
        registers=None,
        stack=None,
        memory=None,
        heap=None,
        tmps=None,
        others=None,
        register_uses=None,
        stack_uses=None,
        heap_uses=None,
        memory_uses=None,
        tmp_uses=None,
        other_uses=None,
        element_limit=5,
        merge_into_tops: bool = True,
    ):
        self.project: Project | None = None
        self.arch = arch
        self.track_tmps = track_tmps
        self._canonical_size: int = canonical_size  # TODO: Drop canonical_size

        self.registers: MultiValuedMemory = (
            MultiValuedMemory(
                memory_id="reg",
                top_func=self.top,
                is_top_func=self.is_top,
                skip_missing_values_during_merging=False,
                page_kwargs={"mo_cmp": self._mo_cmp},
                endness=self.arch.register_endness,
                element_limit=element_limit,
                merge_into_top=merge_into_tops,
            )
            if registers is None
            else registers
        )
        self.stack: MultiValuedMemory = (
            MultiValuedMemory(
                memory_id="mem",
                top_func=self.top,
                is_top_func=self.is_top,
                skip_missing_values_during_merging=False,
                page_kwargs={"mo_cmp": self._mo_cmp},
                element_limit=element_limit,
                merge_into_top=merge_into_tops,
            )
            if stack is None
            else stack
        )
        self.memory: MultiValuedMemory = (
            MultiValuedMemory(
                memory_id="mem",
                top_func=self.top,
                is_top_func=self.is_top,
                skip_missing_values_during_merging=False,
                page_kwargs={"mo_cmp": self._mo_cmp},
                element_limit=element_limit,
                merge_into_top=merge_into_tops,
            )
            if memory is None
            else memory
        )
        self.heap: MultiValuedMemory = (
            MultiValuedMemory(
                memory_id="mem",
                top_func=self.top,
                is_top_func=self.is_top,
                skip_missing_values_during_merging=False,
                page_kwargs={"mo_cmp": self._mo_cmp},
                element_limit=element_limit,
                merge_into_top=merge_into_tops,
            )
            if heap is None
            else heap
        )
        self.tmps: dict[int, set[Definition]] = {} if tmps is None else tmps
        self.others: dict[Atom, MultiValues] = others if others is not None else {}

        # set state
        self.registers.set_state(self)
        self.stack.set_state(self)
        self.memory.set_state(self)
        self.heap.set_state(self)

        self.register_uses = Uses() if register_uses is None else register_uses
        self.stack_uses = Uses() if stack_uses is None else stack_uses
        self.heap_uses = Uses() if heap_uses is None else heap_uses
        self.memory_uses = Uses() if memory_uses is None else memory_uses
        self.tmp_uses: dict[int, set[CodeLocation]] = defaultdict(set) if tmp_uses is None else tmp_uses
        self.other_uses = Uses() if other_uses is None else other_uses

        self.uses_by_codeloc: dict[CodeLocation, set[Definition]] = defaultdict(set)

    @property
    @deprecated("registers")
    def register_definitions(self) -> MultiValuedMemory:
        return self.registers

    @property
    @deprecated("stack")
    def stack_definitions(self) -> MultiValuedMemory:
        return self.stack

    @property
    @deprecated("memory")
    def memory_definitions(self) -> MultiValuedMemory:
        return self.memory

    @property
    @deprecated("heap")
    def heap_definitions(self) -> MultiValuedMemory:
        return self.heap

    def __repr__(self):
        ctnt = "LiveDefs"
        if self.tmps:
            ctnt += ", %d tmpdefs" % len(self.tmps)
        return f"<{ctnt}>"

    def copy(self, discard_tmpdefs=False) -> LiveDefinitions:
        rd = LiveDefinitions(
            self.arch,
            track_tmps=self.track_tmps,
            canonical_size=self._canonical_size,
            registers=self.registers.copy(),
            stack=self.stack.copy(),
            heap=self.heap.copy(),
            memory=self.memory.copy(),
            tmps=self.tmps.copy() if not discard_tmpdefs else None,
            others=dict(self.others),
            register_uses=self.register_uses.copy(),
            stack_uses=self.stack_uses.copy(),
            heap_uses=self.heap_uses.copy(),
            memory_uses=self.memory_uses.copy(),
            tmp_uses=self.tmp_uses.copy() if not discard_tmpdefs else None,
            other_uses=self.other_uses.copy(),
        )

        rd.project = self.project
        return rd

    def reset_uses(self):
        self.stack_uses = Uses()
        self.register_uses = Uses()
        self.memory_uses = Uses()
        self.heap_uses = Uses()
        self.other_uses = Uses()

    def _get_weakref(self):
        return weakref.proxy(self)

    @staticmethod
    def _mo_cmp(
        mo_self: SimMemoryObject | set[SimMemoryObject],
        mo_other: SimMemoryObject | set[SimMemoryObject],
        addr: int,
        size: int,
    ):  # pylint:disable=unused-argument
        # comparing bytes from two sets of memory objects
        # we don't need to resort to byte-level comparison. object-level is good enough.

        if type(mo_self) is set and type(mo_other) is set and len(mo_self) == 1 and len(mo_other) == 1:
            a = next(iter(mo_self))
            b = next(iter(mo_other))
            return a.object is b.object and a.endness == b.endness

        values_self = set()
        values_other = set()
        if type(mo_self) is set:
            for mo in mo_self:
                values_self.add(mo.object)
        else:
            values_self.add(mo_self)
        if type(mo_other) is set:
            for mo in mo_other:
                values_other.add(mo.object)
        else:
            values_other.add(mo_other)
        return values_self == values_other

    @staticmethod
    def top(bits: int):
        """
        Get a TOP value.

        :param bits:    Width of the TOP value (in bits).
        :return:        The TOP value.
        """

        if bits in LiveDefinitions._tops:
            return LiveDefinitions._tops[bits]
        r = claripy.BVS("TOP", bits, explicit_name=True)
        LiveDefinitions._tops[bits] = r
        return r

    @staticmethod
    def is_top(expr) -> bool:
        """
        Check if the given expression is a TOP value.

        :param expr:    The given expression.
        :return:        True if the expression is TOP, False otherwise.
        """
        if isinstance(expr, claripy.ast.Base):
            if expr.op == "BVS" and expr.args[0] == "TOP":
                return True
            if "TOP" in expr.variables:
                return True
        return False

    def stack_address(self, offset: int) -> claripy.ast.bv.BV | None:
        base = claripy.BVS("stack_base", self.arch.bits, explicit_name=True)
        if offset:
            return base + offset
        return base

    @staticmethod
    def is_stack_address(addr: claripy.ast.Base) -> bool:
        return "stack_base" in addr.variables

    @staticmethod
    def get_stack_offset(addr: claripy.ast.Base, had_stack_base=False) -> int | None:
        if had_stack_base and addr.op == "BVV":
            assert isinstance(addr, claripy.ast.BV)
            return addr.concrete_value
        if "TOP" in addr.variables:
            return None
        if "stack_base" in addr.variables:
            if addr.op == "BVS":
                return 0
            if addr.op == "__add__":
                if len(addr.args) == 2:
                    off0 = LiveDefinitions.get_stack_offset(addr.args[0], had_stack_base=True)
                    off1 = LiveDefinitions.get_stack_offset(addr.args[1], had_stack_base=True)
                    if off0 is not None and off1 is not None:
                        return off0 + off1
                elif len(addr.args) == 1:
                    return 0
            elif addr.op == "__sub__" and len(addr.args) == 2:
                off0 = LiveDefinitions.get_stack_offset(addr.args[0], had_stack_base=True)
                off1 = LiveDefinitions.get_stack_offset(addr.args[1], had_stack_base=True)
                if off0 is not None and off1 is not None:
                    return off0 - off1
        return None

    @staticmethod
    def annotate_with_def(symvar: claripy.ast.BV, definition: Definition) -> claripy.ast.BV:
        """

        :param symvar:
        :param definition:
        :return:
        """

        # strip existing definition annotations
        annotations_to_remove = []
        for anno in symvar.annotations:
            if isinstance(anno, DefinitionAnnotation):
                annotations_to_remove.append(anno)

        # annotate with the new definition annotation
        return symvar.annotate(DefinitionAnnotation(definition), remove_annotations=annotations_to_remove)

    @staticmethod
    def extract_defs(symvar: claripy.ast.Base) -> Generator[Definition]:
        for anno in symvar.annotations:
            if isinstance(anno, DefinitionAnnotation):
                yield anno.definition

    @staticmethod
    def extract_defs_from_annotations(annos: Iterable[Annotation]) -> set[Definition]:
        defs = set()
        for anno in annos:
            if isinstance(anno, DefinitionAnnotation):
                defs.add(anno.definition)
        return defs

    @staticmethod
    def extract_defs_from_mv(mv: MultiValues) -> Generator[Definition]:
        for vs in mv.values():
            for v in vs:
                yield from LiveDefinitions.extract_defs(v)

    def get_sp(self) -> int:
        """
        Return the concrete value contained by the stack pointer.
        """
        assert self.arch.sp_offset is not None
        sp_values: MultiValues = self.registers.load(self.arch.sp_offset, size=self.arch.bytes)
        sp_v = sp_values.one_value()
        if sp_v is None:
            # multiple values of sp exists. still return a value if there is only one value (maybe with different
            # definitions)
            values = [v for v in next(iter(sp_values.values())) if self.get_stack_offset(v) is not None]
            assert len({self.get_stack_offset(v) for v in values}) == 1
            result = self.get_stack_address(values[0])
            assert result is not None
            return result

        result = self.get_stack_address(sp_v)
        assert result is not None
        return result

    def get_sp_offset(self) -> int | None:
        """
        Return the offset of the stack pointer.
        """
        assert self.arch.sp_offset is not None
        sp_values: MultiValues = self.registers.load(self.arch.sp_offset, size=self.arch.bytes)
        sp_v = sp_values.one_value()
        if sp_v is None:
            values = [v for v in next(iter(sp_values.values())) if self.get_stack_offset(v) is not None]
            assert len({self.get_stack_offset(v) for v in values}) == 1
            return self.get_stack_offset(values[0])

        return self.get_stack_offset(sp_v)

    def get_stack_address(self, offset: claripy.ast.Base) -> int | None:
        offset_int = self.get_stack_offset(offset)
        if offset_int is None:
            return None
        return self.stack_offset_to_stack_addr(offset_int)

    def stack_offset_to_stack_addr(self, offset) -> int:
        if self.arch.bits == 32:
            base_v = self.INITIAL_SP_32BIT
            mask = 0xFFFF_FFFF
        elif self.arch.bits == 64:
            base_v = self.INITIAL_SP_64BIT
            mask = 0xFFFF_FFFF_FFFF_FFFF
        else:
            raise ValueError("Unsupported architecture word size %d" % self.arch.bits)
        return (base_v + offset) & mask

    def merge(self, *others: LiveDefinitions) -> tuple[LiveDefinitions, bool]:
        state = self.copy()

        merge_occurred = state.registers.merge([other.registers for other in others], None)
        merge_occurred |= state.heap.merge([other.heap for other in others], None)
        merge_occurred |= state.memory.merge([other.memory for other in others], None)
        merge_occurred |= state.stack.merge([other.stack for other in others], None)

        for other in others:
            for k in other.others:
                if k in self.others:
                    thing = self.others[k].merge(other.others[k])
                    if thing != self.others[k]:
                        merge_occurred = True
                        self.others[k] = thing
                else:
                    self.others[k] = other.others[k]
                    merge_occurred = True

            merge_occurred |= state.register_uses.merge(other.register_uses)
            merge_occurred |= state.stack_uses.merge(other.stack_uses)
            merge_occurred |= state.heap_uses.merge(other.heap_uses)
            merge_occurred |= state.memory_uses.merge(other.memory_uses)
            merge_occurred |= state.other_uses.merge(other.other_uses)

        return state, merge_occurred

    def compare(self, other: LiveDefinitions) -> bool:
        r0 = self.registers.compare(other.registers)
        if r0 is False:
            return False
        r1 = self.heap.compare(other.heap)
        if r1 is False:
            return False
        r2 = self.memory.compare(other.memory)
        if r2 is False:
            return False
        r3 = self.stack.compare(other.stack)
        if r3 is False:
            return False

        r4 = True
        for k in other.others:
            if k in self.others:
                thing = self.others[k].merge(other.others[k])
                if thing != self.others[k]:
                    r4 = False
                    break
            else:
                r4 = False
                break

        return r0 and r1 and r2 and r3 and r4

    def kill_definitions(self, atom: Atom) -> None:
        """
        Overwrite existing definitions w.r.t 'atom' with a dummy definition instance. A dummy definition will not be
        removed during simplification.

        :param atom:
        :return: None
        """

        if isinstance(atom, Register):
            self.registers.erase(atom.reg_offset, size=atom.size)
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset):
                if atom.addr.offset is not None:
                    stack_addr = self.stack_offset_to_stack_addr(atom.addr.offset)
                    self.stack.erase(stack_addr, size=atom.size)
                else:
                    l.warning("Skip stack storing since the stack offset is None.")
            elif isinstance(atom.addr, HeapAddress):
                self.heap.erase(atom.addr.value, size=atom.size)
            elif isinstance(atom.addr, int):
                self.memory.erase(atom.addr, size=atom.size)
            elif isinstance(atom.addr, claripy.ast.Base):
                if atom.addr.concrete:
                    self.memory.erase(atom.addr.concrete_value, size=atom.size)
                elif self.is_stack_address(atom.addr):
                    stack_addr = self.get_stack_address(atom.addr)
                    if stack_addr is None:
                        l.warning(
                            "Failed to convert stack address %s to a concrete stack address. Skip the store.", atom.addr
                        )
                    else:
                        self.stack.erase(stack_addr, size=atom.size)
                else:
                    return
            else:
                return
        elif isinstance(atom, Tmp):
            del self.tmps[atom.tmp_idx]
        else:
            del self.others[atom]

    def kill_and_add_definition(
        self,
        atom: Atom,
        code_loc: CodeLocation,
        data: MultiValues,
        dummy=False,
        tags: set[Tag] | None = None,
        endness=None,
        annotated=False,
    ) -> MultiValues | None:
        if data is None:
            raise TypeError("kill_and_add_definition() does not take None as data.")

        if annotated:
            d = data
        else:
            definition: Definition = Definition(atom, code_loc, dummy=dummy, tags=tags)
            d = MultiValues()
            for offset, vs in data.items():
                for v in vs:
                    d.add_value(offset, self.annotate_with_def(v, definition))

        # set_object() replaces kill (not implemented) and add (add) in one step
        if isinstance(atom, Register):
            try:
                self.registers.store(
                    atom.reg_offset,
                    d,
                    size=atom.size,
                    endness=endness,
                )
            except SimMemoryError:
                l.warning("Failed to store register definition %s at %d.", d, atom.reg_offset, exc_info=True)
        elif isinstance(atom, MemoryLocation):
            if endness is None:
                endness = atom.endness

            if isinstance(atom.addr, SpOffset):
                if atom.addr.offset is not None:
                    stack_addr = self.stack_offset_to_stack_addr(atom.addr.offset)
                    self.stack.store(stack_addr, d, size=atom.size, endness=endness)
                else:
                    l.warning("Skip stack storing since the stack offset is None.")
            elif isinstance(atom.addr, HeapAddress):
                self.heap.store(atom.addr.value, d, size=atom.size, endness=endness)
            elif isinstance(atom.addr, int):
                self.memory.store(atom.addr, d, size=atom.size, endness=endness)
            elif isinstance(atom.addr, claripy.ast.Base):
                if atom.addr.concrete:
                    self.memory.store(atom.addr.concrete_value, d, size=atom.size, endness=endness)
                elif self.is_stack_address(atom.addr):
                    stack_addr = self.get_stack_address(atom.addr)
                    if stack_addr is None:
                        l.warning(
                            "Failed to convert stack address %s to a concrete stack address. Skip the store.", atom.addr
                        )
                    else:
                        self.stack.store(stack_addr, d, size=atom.size, endness=endness)
                else:
                    return None
            else:
                return None
        elif isinstance(atom, Tmp):
            if self.track_tmps:
                self.tmps[atom.tmp_idx] = {definition}
            else:
                self.tmps[atom.tmp_idx] = self.uses_by_codeloc[code_loc]
                return None
        else:
            self.others[atom] = d

        return d

    def add_use(self, atom: Atom, code_loc: CodeLocation, expr: Any | None = None) -> None:
        if isinstance(atom, Register):
            self.add_register_use(atom.reg_offset, atom.size, code_loc, expr=expr)
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset):
                self.add_stack_use(atom, code_loc, expr=expr)
            elif isinstance(atom.addr, HeapAddress):
                self.add_heap_use(atom, code_loc, expr=expr)
            elif isinstance(atom.addr, int):
                self.add_memory_use(atom, code_loc, expr=expr)
            else:
                # ignore RegisterOffset
                pass
        elif isinstance(atom, Tmp):
            self.add_tmp_use(atom, code_loc)
        else:
            for defn in self.get_definitions(atom):
                self.other_uses.add_use(defn, code_loc, expr)
                self.uses_by_codeloc[code_loc].add(defn)

    def add_use_by_def(self, definition: Definition, code_loc: CodeLocation, expr: Any = None) -> None:
        if isinstance(definition.atom, Register):
            self.add_register_use_by_def(definition, code_loc, expr=expr)
        elif isinstance(definition.atom, MemoryLocation):
            if isinstance(definition.atom.addr, SpOffset):
                self.add_stack_use_by_def(definition, code_loc, expr=expr)
            elif isinstance(definition.atom.addr, HeapAddress):
                self.add_heap_use_by_def(definition, code_loc, expr=expr)
            elif isinstance(definition.atom.addr, int):
                self.add_memory_use_by_def(definition, code_loc, expr=expr)
            else:
                # ignore RegisterOffset
                pass
        elif type(definition.atom) is Tmp:
            self.add_tmp_use_by_def(definition, code_loc)
        elif type(definition.atom) is ConstantSrc:
            # ignore constants
            pass
        else:
            self.other_uses.add_use(definition, code_loc, expr)

    def get_definitions(
        self, thing: A | Definition[A] | Iterable[A] | Iterable[Definition[A]] | MultiValues
    ) -> set[Definition[Atom]]:
        if isinstance(thing, MultiValues):
            defs = set()
            for vs in thing.values():
                for v in vs:
                    defs.update(LiveDefinitions.extract_defs_from_annotations(v.annotations))
            return defs
        if isinstance(thing, Atom):
            pass
        elif isinstance(thing, Definition):
            thing = thing.atom
        else:
            defs = set()
            for atom2 in thing:
                defs |= self.get_definitions(atom2)
            return defs

        if isinstance(thing, Register):
            return self.get_register_definitions(thing.reg_offset, thing.size)
        if isinstance(thing, MemoryLocation):
            if isinstance(thing.addr, SpOffset):
                return self.get_stack_definitions(thing.addr.offset, thing.size)
            if isinstance(thing.addr, HeapAddress):
                return self.get_heap_definitions(thing.addr.value, size=thing.size)
            if isinstance(thing.addr, int):
                return self.get_memory_definitions(thing.addr, thing.size)
            return set()
        if isinstance(thing, Tmp):
            return self.get_tmp_definitions(thing.tmp_idx)
        defs = set()
        mv = self.others.get(thing, None)
        if mv is not None:
            defs |= self.get_definitions(mv)
        return defs

    def get_tmp_definitions(self, tmp_idx: int) -> set[Definition]:
        if tmp_idx in self.tmps:
            return self.tmps[tmp_idx]
        return set()

    def get_register_definitions(self, reg_offset: int, size: int) -> set[Definition]:
        try:
            annotations = self.registers.load_annotations(reg_offset, size)
        except SimMemoryMissingError as ex:
            if ex.missing_addr > reg_offset:
                annotations = self.registers.load_annotations(reg_offset, ex.missing_addr - reg_offset)
            else:
                # nothing we can do
                return set()

        return LiveDefinitions.extract_defs_from_annotations(annotations)

    def get_stack_values(self, stack_offset: int, size: int, endness: str) -> MultiValues | None:
        stack_addr = self.stack_offset_to_stack_addr(stack_offset)
        try:
            return self.stack.load(stack_addr, size=size, endness=endness)
        except SimMemoryMissingError:
            return None

    def get_stack_definitions(self, stack_offset: int, size: int) -> set[Definition]:
        try:
            stack_addr = self.stack_offset_to_stack_addr(stack_offset)
            annotations = self.stack.load_annotations(stack_addr, size)
        except SimMemoryMissingError:
            return set()

        return LiveDefinitions.extract_defs_from_annotations(annotations)

    def get_heap_definitions(self, heap_addr: int, size: int) -> set[Definition]:
        try:
            annotations = self.heap.load_annotations(heap_addr, size)
        except SimMemoryMissingError:
            return set()

        return LiveDefinitions.extract_defs_from_annotations(annotations)

    def get_memory_definitions(self, addr: int, size: int) -> set[Definition]:
        try:
            annotations = self.memory.load_annotations(addr, size)
        except SimMemoryMissingError:
            return set()

        return LiveDefinitions.extract_defs_from_annotations(annotations)

    @deprecated("get_definitions")
    def get_definitions_from_atoms(self, atoms: Iterable[A]) -> Iterable[Definition]:
        result = set()
        for atom in atoms:
            result |= self.get_definitions(atom)
        return result

    @deprecated("get_values")
    def get_value_from_definition(self, definition: Definition) -> MultiValues | None:
        return self.get_value_from_atom(definition.atom)

    @deprecated("get_one_value")
    def get_one_value_from_definition(self, definition: Definition) -> claripy.ast.bv.BV | None:
        return self.get_one_value_from_atom(definition.atom)

    @deprecated("get_concrete_value")
    def get_concrete_value_from_definition(self, definition: Definition) -> int | None:
        return self.get_concrete_value_from_atom(definition.atom)

    @deprecated("get_values")
    def get_value_from_atom(self, atom: Atom) -> MultiValues | None:
        if isinstance(atom, Register):
            try:
                return self.registers.load(atom.reg_offset, size=atom.size)
            except SimMemoryMissingError:
                return None
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset):
                stack_addr = self.stack_offset_to_stack_addr(atom.addr.offset)
                try:
                    return self.stack.load(stack_addr, size=atom.size, endness=atom.endness)
                except SimMemoryMissingError:
                    return None
            elif isinstance(atom.addr, HeapAddress):
                try:
                    return self.heap.load(atom.addr.value, size=atom.size, endness=atom.endness)
                except SimMemoryMissingError:
                    return None
            elif isinstance(atom.addr, int):
                try:
                    return self.memory.load(atom.addr, size=atom.size, endness=atom.endness)
                except SimMemoryMissingError:
                    return None
            else:
                # ignore RegisterOffset
                return None
        else:
            return None

    @deprecated("get_one_value")
    def get_one_value_from_atom(self, atom: Atom) -> claripy.ast.bv.BV | None:
        r = self.get_value_from_atom(atom)
        if r is None:
            return None
        return r.one_value()

    @deprecated("get_concrete_value")
    def get_concrete_value_from_atom(self, atom: Atom) -> int | None:
        r = self.get_one_value_from_atom(atom)
        if r is None:
            return None
        if r.symbolic:
            return None
        return r.concrete_value

    def get_values(self, spec: A | Definition[A] | Iterable[A] | Iterable[Definition[A]]) -> MultiValues | None:
        if isinstance(spec, Definition):
            atom = spec.atom
        elif isinstance(spec, Atom):
            atom = spec
        else:
            result = None
            for atom in spec:
                r = self.get_values(atom)
                if r is None:
                    continue
                result = r if result is None else result.merge(r)
            return result

        if isinstance(atom, Register):
            try:
                return self.registers.load(atom.reg_offset, size=atom.size)
            except SimMemoryMissingError:
                return None
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset):
                stack_addr = self.stack_offset_to_stack_addr(atom.addr.offset)
                try:
                    return self.stack.load(stack_addr, size=atom.size, endness=atom.endness)
                except SimMemoryMissingError:
                    return None
            elif isinstance(atom.addr, HeapAddress):
                try:
                    return self.heap.load(atom.addr.value, size=atom.size, endness=atom.endness)
                except SimMemoryMissingError:
                    return None
            elif isinstance(atom.addr, int):
                try:
                    return self.memory.load(atom.addr, size=atom.size, endness=atom.endness)
                except SimMemoryMissingError:
                    pass
                if self.project is not None:
                    try:
                        bytestring = self.project.loader.memory.load(atom.addr, atom.size)
                        if atom.endness == archinfo.Endness.LE:
                            bytestring = bytes(reversed(bytestring))
                        return MultiValues(
                            self.annotate_with_def(claripy.BVV(bytestring), Definition(atom, ExternalCodeLocation()))
                        )
                    except KeyError:
                        pass
                return None
            else:
                # ignore RegisterOffset
                return None
        else:
            return self.others.get(atom, None)

    def get_one_value(
        self,
        spec: A | Definition[A] | Iterable[A] | Iterable[Definition[A]],
        strip_annotations: bool = False,
    ) -> claripy.ast.bv.BV | None:
        r = self.get_values(spec)
        if r is None:
            return None
        return r.one_value(strip_annotations=strip_annotations)

    @overload
    def get_concrete_value(
        self, spec: A | Definition[A] | Iterable[A] | Iterable[Definition[A]], cast_to: type[int] = ...
    ) -> int | None: ...

    @overload
    def get_concrete_value(
        self,
        spec: A | Definition[A] | Iterable[A] | Iterable[Definition[A]],
        cast_to: type[bytes] = ...,
    ) -> bytes | None: ...

    def get_concrete_value(
        self,
        spec: A | Definition[A] | Iterable[A] | Iterable[Definition[A]],
        cast_to: type[int] | type[bytes] = int,
    ) -> int | bytes | None:
        r = self.get_one_value(spec, strip_annotations=True)
        if r is None:
            return None
        if r.symbolic:
            return None
        result = r.concrete_value
        if issubclass(cast_to, bytes):
            return result.to_bytes(len(r) // 8, "big")
        return result

    def add_register_use(self, reg_offset: int, size: int, code_loc: CodeLocation, expr: Any | None = None) -> None:
        # get all current definitions
        try:
            mvs: MultiValues = self.registers.load(reg_offset, size=size)
        except SimMemoryMissingError:
            return

        for vs in mvs.values():
            for v in vs:
                for def_ in self.extract_defs(v):
                    self.add_register_use_by_def(def_, code_loc, expr=expr)

    def add_register_use_by_def(self, def_: Definition, code_loc: CodeLocation, expr: Any | None = None) -> None:
        self.register_uses.add_use(def_, code_loc, expr=expr)
        self.uses_by_codeloc[code_loc].add(def_)

    def add_stack_use(self, atom: MemoryLocation, code_loc: CodeLocation, expr: Any | None = None) -> None:
        if not isinstance(atom.addr, SpOffset):
            raise TypeError(f"Atom {atom!r} is not a stack location atom.")

        for current_def in self.get_definitions(atom):
            self.add_stack_use_by_def(current_def, code_loc, expr=expr)

    def add_stack_use_by_def(self, def_: Definition, code_loc: CodeLocation, expr: Any | None = None) -> None:
        self.stack_uses.add_use(def_, code_loc, expr=expr)
        self.uses_by_codeloc[code_loc].add(def_)

    def add_heap_use(self, atom: MemoryLocation, code_loc: CodeLocation, expr: Any | None = None) -> None:
        if not isinstance(atom.addr, HeapAddress):
            raise TypeError(f"Atom {atom!r} is not a heap location atom.")

        current_defs = self.get_definitions(atom)

        for current_def in current_defs:
            self.add_heap_use_by_def(current_def, code_loc, expr=expr)

    def add_heap_use_by_def(self, def_: Definition, code_loc: CodeLocation, expr: Any | None = None) -> None:
        self.heap_uses.add_use(def_, code_loc, expr=expr)
        self.uses_by_codeloc[code_loc].add(def_)

    def add_memory_use(self, atom: MemoryLocation, code_loc: CodeLocation, expr: Any | None = None) -> None:
        # get all current definitions
        current_defs: set[Definition] = self.get_definitions(atom)

        for current_def in current_defs:
            self.add_memory_use_by_def(current_def, code_loc, expr=expr)

    def add_memory_use_by_def(self, def_: Definition, code_loc: CodeLocation, expr: Any | None = None) -> None:
        self.memory_uses.add_use(def_, code_loc, expr=expr)
        self.uses_by_codeloc[code_loc].add(def_)

    def add_tmp_use(self, atom: Tmp, code_loc: CodeLocation) -> None:
        if self.track_tmps:
            if atom.tmp_idx in self.tmps:
                defs = self.tmps[atom.tmp_idx]
                for def_ in defs:
                    self.add_tmp_use_by_def(def_, code_loc)
        else:
            if atom.tmp_idx in self.tmps:
                defs = self.tmps[atom.tmp_idx]
                for d in defs:
                    assert type(d.atom) is not Tmp
                    self.add_use_by_def(d, code_loc)

    def add_tmp_use_by_def(self, def_: Definition, code_loc: CodeLocation) -> None:
        if not isinstance(def_.atom, Tmp):
            raise TypeError(f"Atom {def_.atom!r} is not a Tmp atom.")

        self.tmp_uses[def_.atom.tmp_idx].add(code_loc)
        self.uses_by_codeloc[code_loc].add(def_)

    @overload
    def deref(
        self,
        pointer: MultiValues | A | Definition[A] | Iterable[A] | Iterable[Definition[A]],
        size: int | DerefSize,
        endness: archinfo.Endness = ...,
    ) -> set[MemoryLocation]: ...

    @overload
    def deref(
        self,
        pointer: int | claripy.ast.BV | HeapAddress | SpOffset,
        size: int | DerefSize,
        endness: archinfo.Endness = ...,
    ) -> MemoryLocation | None: ...

    def deref(self, pointer, size, endness=archinfo.Endness.BE):
        if isinstance(pointer, (Atom, Definition)):
            pointer = self.get_values(pointer)
            if pointer is None:
                return set()

        if isinstance(pointer, set):
            result = set()
            for ptr_atom in pointer:
                result.update(self.deref(ptr_atom, size, endness))
            return result

        if isinstance(pointer, MultiValues):
            result = set()
            for vs in pointer.values():
                for value in vs:
                    atom = self.deref(value, size, endness)
                    if atom is not None:
                        result.add(atom)
            return result

        if isinstance(pointer, (HeapAddress, SpOffset, int)):
            addr = pointer
        else:
            assert isinstance(pointer, claripy.ast.BV)
            if self.is_top(pointer):
                return None

            # TODO this can be simplified with the walrus operator
            stack_offset = self.get_stack_offset(pointer)
            if stack_offset is not None:
                addr = SpOffset(len(pointer), stack_offset)
            else:
                heap_offset = self.get_heap_offset(pointer)
                if heap_offset is not None:
                    addr = HeapAddress(heap_offset)
                elif pointer.op == "BVV":
                    addr = pointer.args[0]
                else:
                    # cannot resolve
                    return None

        if isinstance(size, DerefSize):
            assert size == DerefSize.NULL_TERMINATE
            for sz in range(4096):  # arbitrary
                # truly evil that this is an abstraction we have to contend with
                mv = self.get_values(MemoryLocation(addr + sz, 1, endness))
                if mv is not None and 0 in mv and any(one.op == "BVV" and one.args[0] == 0 for one in mv[0]):
                    size = sz + 1
                    break
            else:
                l.warning(
                    "Could not resolve cstring dereference at %s to a concrete size",
                    hex(addr) if isinstance(addr, int) else addr,
                )
                size = 4096

        return MemoryLocation(addr, size, endness)

    @staticmethod
    def is_heap_address(addr: claripy.ast.Base) -> bool:
        return "heap_base" in addr.variables

    @staticmethod
    def get_heap_offset(addr: claripy.ast.Base) -> int | None:
        if "heap_base" in addr.variables:
            if addr.op == "BVS":
                return 0
            if addr.op == "__add__" and len(addr.args) == 2 and addr.args[1].op == "BVV":
                return addr.args[1].concrete_value
        return None

    def heap_address(self, offset: int | HeapAddress) -> claripy.ast.BV:
        if isinstance(offset, HeapAddress):
            if not isinstance(offset.value, int):
                raise TypeError("TODO: what's this? contact @rhelmot")
            offset = offset.value
        base = claripy.BVS("heap_base", self.arch.bits, explicit_name=True)
        if offset:
            return base + offset
        return base
