import weakref
from typing import Optional, Iterable, Dict, Set, Generator, Tuple, Union, Any, TYPE_CHECKING
import logging

import claripy
from claripy.annotation import Annotation
import archinfo

from collections import defaultdict

from ...errors import SimMemoryMissingError, SimMemoryError
from ...storage.memory_mixins import MultiValuedMemory
from ...storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from ...engines.light import SpOffset
from ...code_location import CodeLocation
from .atoms import Atom, Register, MemoryLocation, Tmp, FunctionCall, ConstantSrc
from .definition import Definition, Tag
from .heap_address import HeapAddress
from .uses import Uses

if TYPE_CHECKING:
    from angr.storage import SimMemoryObject


l = logging.getLogger(name=__name__)


#
# Annotations
#


class DefinitionAnnotation(Annotation):

    __slots__ = ('definition', )

    def __init__(self, definition):
        super().__init__()
        self.definition = definition

    @property
    def relocatable(self):
        return True

    @property
    def eliminatable(self):
        return False

    def __hash__(self):
        return hash((self.definition, self.relocatable, self.eliminatable))

    def __eq__(self, other: 'object'):
        if isinstance(other, DefinitionAnnotation):
            return  self.definition == other.definition \
                and self.relocatable == other.relocatable \
                and self.eliminatable == other.eliminatable
        else:
            raise ValueError("DefinitionAnnotation can only check equality with other DefinitionAnnotation")

    def __repr__(self):
        return f"<{self.__class__.__name__}({repr(self.definition)})"

# pylint: disable=W1116
class LiveDefinitions:
    """
    A LiveDefinitions instance contains definitions and uses for register, stack, memory, and temporary variables,
    uncovered during the analysis.
    """

    INITIAL_SP_32BIT = 0x7fff0000
    INITIAL_SP_64BIT = 0x7fffffff0000
    _tops = {}

    __slots__ = ('project', 'arch', 'track_tmps', 'register_definitions', 'stack_definitions', 'heap_definitions',
                 'memory_definitions', 'tmps', 'register_uses', 'stack_uses', 'heap_uses',
                 'memory_uses', 'uses_by_codeloc', 'tmp_uses', '_canonical_size', '__weakref__', )

    def __init__(self, arch: archinfo.Arch, track_tmps: bool=False, canonical_size=8,
                 register_definitions=None,
                 stack_definitions=None,
                 memory_definitions=None,
                 heap_definitions=None,
                 ):

        self.project = None
        self.arch = arch
        self.track_tmps = track_tmps
        self._canonical_size: int = canonical_size  # TODO: Drop canonical_size

        self.register_definitions = MultiValuedMemory(memory_id="reg",
                                                      top_func=self.top,
                                                      skip_missing_values_during_merging=False,
                                                      page_kwargs={'mo_cmp': self._mo_cmp}) \
            if register_definitions is None else register_definitions
        self.stack_definitions = MultiValuedMemory(memory_id="mem",
                                                   top_func=self.top,
                                                   skip_missing_values_during_merging=False,
                                                   page_kwargs={'mo_cmp': self._mo_cmp}) \
            if stack_definitions is None else stack_definitions
        self.memory_definitions = MultiValuedMemory(memory_id="mem",
                                                    top_func=self.top,
                                                    skip_missing_values_during_merging=False,
                                                    page_kwargs={'mo_cmp': self._mo_cmp}) \
            if memory_definitions is None else memory_definitions
        self.heap_definitions = MultiValuedMemory(memory_id="mem",
                                                  top_func=self.top,
                                                  skip_missing_values_during_merging=False,
                                                  page_kwargs={'mo_cmp': self._mo_cmp}) \
            if heap_definitions is None else heap_definitions
        self.tmps: Dict[int, Set[Definition]] = {}

        # set state
        self.register_definitions.set_state(self)
        self.stack_definitions.set_state(self)
        self.memory_definitions.set_state(self)
        self.heap_definitions.set_state(self)

        self.register_uses = Uses()
        self.stack_uses = Uses()
        self.heap_uses = Uses()
        self.memory_uses = Uses()
        self.uses_by_codeloc: Dict[CodeLocation,Set[Definition]] = defaultdict(set)
        self.tmp_uses: Dict[int,Set[CodeLocation]] = defaultdict(set)

    def __repr__(self):
        ctnt = "LiveDefs"
        if self.tmps:
            ctnt += ", %d tmpdefs" % len(self.tmps)
        return "<%s>" % ctnt

    def copy(self) -> 'LiveDefinitions':
        rd = LiveDefinitions(self.arch, track_tmps=self.track_tmps, canonical_size=self._canonical_size,
                             register_definitions=self.register_definitions.copy(),
                             stack_definitions=self.stack_definitions.copy(),
                             heap_definitions=self.heap_definitions.copy(),
                             memory_definitions=self.memory_definitions.copy(),
                             )

        rd.tmps = self.tmps.copy()
        rd.register_uses = self.register_uses.copy()
        rd.stack_uses = self.stack_uses.copy()
        rd.heap_uses = self.heap_uses.copy()
        rd.memory_uses = self.memory_uses.copy()
        rd.tmp_uses = self.tmp_uses.copy()

        return rd

    def _get_weakref(self):
        return weakref.proxy(self)

    @staticmethod
    def _mo_cmp(mo_self: Union['SimMemoryObject', Set['SimMemoryObject']],
                mo_other: Union['SimMemoryObject', Set['SimMemoryObject']], addr: int, size: int):  # pylint:disable=unused-argument
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

    def stack_address(self, offset: int) -> claripy.ast.Base:
        base = claripy.BVS("stack_base", self.arch.bits, explicit_name=True)
        if offset:
            return base + offset
        return base

    @staticmethod
    def is_stack_address(addr: claripy.ast.Base) -> bool:
        return "stack_base" in addr.variables

    @staticmethod
    def get_stack_offset(addr: claripy.ast.Base) -> Optional[int]:
        if "stack_base" in addr.variables:
            if addr.op == "BVS":
                return 0
            elif addr.op == "__add__":
                if len(addr.args) == 2 and addr.args[1].op == "BVV":
                    return addr.args[1]._model_concrete.value
                if len(addr.args) == 1:
                    return 0
            elif addr.op == "__sub__" and len(addr.args) == 2 and addr.args[1].op == "BVV":
                return -addr.args[1]._model_concrete.value
        return None

    @staticmethod
    def annotate_with_def(symvar: claripy.ast.Base, definition: Definition):
        """

        :param symvar:
        :param definition:
        :return:
        """

        # strip existing definition annotations
        annotations_to_remove = [ ]
        for anno in symvar.annotations:
            if isinstance(anno, DefinitionAnnotation):
                annotations_to_remove.append(anno)
        if annotations_to_remove:
            symvar = symvar.remove_annotations(annotations_to_remove)

        # annotate with the new definition annotation
        return symvar.annotate(DefinitionAnnotation(definition))

    @staticmethod
    def extract_defs(symvar: claripy.ast.Base) -> Generator[Definition,None,None]:
        for anno in symvar.annotations:
            if isinstance(anno, DefinitionAnnotation):
                yield anno.definition

    def get_sp(self) -> int:
        """
        Return the concrete value contained by the stack pointer.
        """
        sp_values: MultiValues = self.register_definitions.load(self.arch.sp_offset, size=self.arch.bytes)
        sp_v = sp_values.one_value()
        if sp_v is None:
            # multiple values of sp exists. still return a value if there is only one value (maybe with different
            # definitions)
            values = list(filter(self.get_stack_offset, next(iter(sp_values.values.values()))))
            if len(set(map(self.get_stack_offset, values))) == 1:
                return self.get_stack_address(next(iter(values)))
            assert False

        return self.get_stack_address(sp_v)

    def get_stack_address(self, offset: claripy.ast.Base) -> Optional[int]:
        offset = self.get_stack_offset(offset)
        if offset is None:
            return None
        return self.stack_offset_to_stack_addr(offset)

    def stack_offset_to_stack_addr(self, offset) -> int:
        if self.arch.bits == 32:
            base_v = self.INITIAL_SP_32BIT
            mask = 0xffff_ffff
        elif self.arch.bits == 64:
            base_v = self.INITIAL_SP_64BIT
            mask = 0xffff_ffff_ffff_ffff
        else:
            raise ValueError("Unsupported architecture word size %d" % self.arch.bits)
        return (base_v + offset) & mask

    def merge(self, *others) -> Tuple['LiveDefinitions',bool]:

        state = self.copy()

        merge_occurred = state.register_definitions.merge([ other.register_definitions for other in others ], None)
        merge_occurred |= state.heap_definitions.merge([other.heap_definitions for other in others], None)
        merge_occurred |= state.memory_definitions.merge([other.memory_definitions for other in others], None)
        merge_occurred |= state.stack_definitions.merge([other.stack_definitions for other in others], None)

        for other in others:
            other: LiveDefinitions

            merge_occurred |= state.register_uses.merge(other.register_uses)
            merge_occurred |= state.stack_uses.merge(other.stack_uses)
            merge_occurred |= state.heap_uses.merge(other.heap_uses)
            merge_occurred |= state.memory_uses.merge(other.memory_uses)

        return state, merge_occurred

    def kill_definitions(self, atom: Atom) -> None:
        """
        Overwrite existing definitions w.r.t 'atom' with a dummy definition instance. A dummy definition will not be
        removed during simplification.

        :param atom:
        :return: None
        """

        if isinstance(atom, Register):
            self.register_definitions.erase(atom.reg_offset, size=atom.size)
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset):
                if atom.addr.offset is not None:
                    stack_addr = self.stack_offset_to_stack_addr(atom.addr.offset)
                    self.stack_definitions.erase(stack_addr, size=atom.size)
                else:
                    l.warning("Skip stack storing since the stack offset is None.")
            elif isinstance(atom.addr, HeapAddress):
                self.heap_definitions.erase(atom.addr.value, size=atom.size)
            elif isinstance(atom.addr, int):
                self.memory_definitions.erase(atom.addr, size=atom.size)
            elif isinstance(atom.addr, claripy.ast.Base):
                if atom.addr.concrete:
                    self.memory_definitions.erase(atom.addr._model_concrete.value, size=atom.size)
                elif self.is_stack_address(atom.addr):
                    stack_addr = self.get_stack_address(atom.addr)
                    if stack_addr is None:
                        l.warning("Failed to convert stack address %s to a concrete stack address. Skip the store.",
                                  atom.addr)
                    else:
                        self.stack_definitions.erase(stack_addr, size=atom.size)
                else:
                    return
            else:
                return
        elif isinstance(atom, Tmp):
            del self.tmps[atom.tmp_idx]
        else:
            raise NotImplementedError()

    def kill_and_add_definition(self, atom: Atom, code_loc: CodeLocation, data: MultiValues,
                                dummy=False, tags: Set[Tag]=None, endness=None,
                                annotated=False) -> Optional[MultiValues]:
        if data is None:
            raise TypeError("kill_and_add_definition() does not take None as data.")

        if annotated:
            d = data
        else:
            definition: Definition = Definition(atom, code_loc, dummy=dummy, tags=tags)
            d = MultiValues()
            for offset, vs in data.values.items():
                for v in vs:
                    d.add_value(offset, self.annotate_with_def(v, definition))

        # set_object() replaces kill (not implemented) and add (add) in one step
        if isinstance(atom, Register):
            try:
                self.register_definitions.store(atom.reg_offset, d, size=atom.size, endness=endness)
            except SimMemoryError:
                l.warning("Failed to store register definition %s at %d.", d, atom.reg_offset, exc_info=True)
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset):
                if atom.addr.offset is not None:
                    stack_addr = self.stack_offset_to_stack_addr(atom.addr.offset)
                    self.stack_definitions.store(stack_addr, d, size=atom.size, endness=endness)
                else:
                    l.warning("Skip stack storing since the stack offset is None.")
            elif isinstance(atom.addr, HeapAddress):
                self.heap_definitions.store(atom.addr.value, d, size=atom.size, endness=endness)
            elif isinstance(atom.addr, int):
                self.memory_definitions.store(atom.addr, d, size=atom.size, endness=endness)
            elif isinstance(atom.addr, claripy.ast.Base):
                if atom.addr.concrete:
                    self.memory_definitions.store(atom.addr._model_concrete.value, d, size=atom.size, endness=endness)
                elif self.is_stack_address(atom.addr):
                    stack_addr = self.get_stack_address(atom.addr)
                    if stack_addr is None:
                        l.warning("Failed to convert stack address %s to a concrete stack address. Skip the store.",
                                  atom.addr)
                    else:
                        self.stack_definitions.store(stack_addr, d, size=atom.size, endness=endness)
                else:
                    return None
            else:
                return None
        elif isinstance(atom, Tmp):
            if self.track_tmps:
                self.tmps[atom.tmp_idx] = { definition }
            else:
                self.tmps[atom.tmp_idx] = self.uses_by_codeloc[code_loc]
                return None
        else:
            raise NotImplementedError()

        return d

    def add_use(self, atom: Atom, code_loc: CodeLocation, expr: Optional[Any]=None) -> None:
        if isinstance(atom, Register):
            self._add_register_use(atom, code_loc, expr=expr)
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset):
                self._add_stack_use(atom, code_loc, expr=expr)
            elif isinstance(atom.addr, HeapAddress):
                self._add_heap_use(atom, code_loc, expr=expr)
            elif isinstance(atom.addr, int):
                self._add_memory_use(atom, code_loc, expr=expr)
            else:
                # ignore RegisterOffset
                pass
        elif isinstance(atom, Tmp):
            self._add_tmp_use(atom, code_loc)
        else:
            raise TypeError("Unsupported atom type %s." % type(atom))

    def add_use_by_def(self, definition: Definition, code_loc: CodeLocation, expr: Any=None) -> None:
        if isinstance(definition.atom, Register):
            self._add_register_use_by_def(definition, code_loc, expr=expr)
        elif isinstance(definition.atom, MemoryLocation):
            if isinstance(definition.atom.addr, SpOffset):
                self._add_stack_use_by_def(definition, code_loc, expr=expr)
            elif isinstance(definition.atom.addr, HeapAddress):
                self._add_heap_use_by_def(definition, code_loc, expr=expr)
            elif isinstance(definition.atom.addr, int):
                self._add_memory_use_by_def(definition, code_loc, expr=expr)
            else:
                # ignore RegisterOffset
                pass
        elif type(definition.atom) is Tmp:
            self._add_tmp_use_by_def(definition, code_loc)
        elif type(definition.atom) is FunctionCall:
            # ignore function calls
            pass
        elif type(definition.atom) is ConstantSrc:
            # ignore constants
            pass
        else:
            raise TypeError()

    def get_definitions(self, atom: Atom) -> Iterable[Definition]:
        if isinstance(atom, Register):
            try:
                values: MultiValues = self.register_definitions.load(atom.reg_offset, size=atom.size)
            except SimMemoryMissingError:
                return
            for vs in values.values.values():
                for v in vs:
                    yield from self.extract_defs(v)
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset):
                stack_addr = self.stack_offset_to_stack_addr(atom.addr.offset)
                try:
                    mv: MultiValues = self.stack_definitions.load(stack_addr, size=atom.size, endness=atom.endness)
                except SimMemoryMissingError:
                    return
                for vs in mv.values.values():
                    for v in vs:
                        yield from self.extract_defs(v)
            elif isinstance(atom.addr, HeapAddress):
                try:
                    mv: MultiValues = self.heap_definitions.load(atom.addr.value, size=atom.size, endness=atom.endness)
                except SimMemoryMissingError:
                    return
                for vs in mv.values.values():
                    for v in vs:
                        yield from self.extract_defs(v)
            elif isinstance(atom.addr, int):
                try:
                    values = self.memory_definitions.load(atom.addr, size=atom.size, endness=atom.endness)
                except SimMemoryMissingError:
                    return
                for vs in values.values.values():
                    for v in vs:
                        yield from self.extract_defs(v)
            else:
                return
        elif isinstance(atom, Tmp):
            if atom.tmp_idx in self.tmps:
                for tmp in self.tmps[atom.tmp_idx]:
                    yield tmp
            else:
                return
        else:
            raise TypeError()

    def get_definitions_from_atoms(self, atoms: Iterable[Atom]) -> Iterable[Definition]:
        result = set()
        for atom in atoms:
            result |= set(self.get_definitions(atom))
        return result

    def get_value_from_definition(self, definition: Definition) -> MultiValues:
        return self.get_value_from_atom(definition.atom)

    def get_value_from_atom(self, atom: Atom) -> Optional[MultiValues]:
        if isinstance(atom, Register):
            try:
                return self.register_definitions.load(atom.reg_offset, size=atom.size)
            except SimMemoryMissingError:
                return None
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset):
                stack_addr = self.stack_offset_to_stack_addr(atom.addr.offset)
                try:
                    return self.stack_definitions.load(stack_addr, size=atom.size, endness=atom.endness)
                except SimMemoryMissingError:
                    return None
            elif isinstance(atom.addr, HeapAddress):
                try:
                    return self.heap_definitions.load(atom.addr.value, size=atom.size, endness=atom.endness)
                except SimMemoryMissingError:
                    return None
            elif isinstance(atom.addr, int):
                try:
                    return self.memory_definitions.load(atom.addr, size=atom.size, endness=atom.endness)
                except SimMemoryMissingError:
                    return None
            else:
                # ignore RegisterOffset
                return None
        else:
            return None
    #
    # Private methods
    #

    def _add_register_use(self, atom: Register, code_loc: CodeLocation, expr: Optional[Any]=None) -> None:
        # get all current definitions
        try:
            values: MultiValues = self.register_definitions.load(atom.reg_offset, size=atom.size)
        except SimMemoryMissingError:
            return

        for vs in values.values.values():
            for v in vs:
                for def_ in self.extract_defs(v):
                    self._add_register_use_by_def(def_, code_loc, expr=expr)

    def _add_register_use_by_def(self, def_: Definition, code_loc: CodeLocation, expr: Optional[Any]=None) -> None:
        self.register_uses.add_use(def_, code_loc, expr=expr)
        self.uses_by_codeloc[code_loc].add(def_)

    def _add_stack_use(self, atom: MemoryLocation, code_loc: CodeLocation, expr: Optional[Any]=None) -> None:

        if not isinstance(atom.addr, SpOffset):
            raise TypeError("Atom %r is not a stack location atom." % atom)

        for current_def in self.get_definitions(atom):
            self._add_stack_use_by_def(current_def, code_loc, expr=expr)

    def _add_stack_use_by_def(self, def_: Definition, code_loc: CodeLocation, expr: Optional[Any]=None) -> None:
        self.stack_uses.add_use(def_, code_loc, expr=expr)
        self.uses_by_codeloc[code_loc].add(def_)

    def _add_heap_use(self, atom: MemoryLocation, code_loc: CodeLocation, expr: Optional[Any]=None) -> None:

        if not isinstance(atom.addr, HeapAddress):
            raise TypeError("Atom %r is not a heap location atom." % atom)

        current_defs = self.heap_definitions.get_objects_by_offset(atom.addr.value)

        for current_def in current_defs:
            self._add_heap_use_by_def(current_def, code_loc, expr=expr)

    def _add_heap_use_by_def(self, def_: Definition, code_loc: CodeLocation, expr: Optional[Any]=None) -> None:
        self.heap_uses.add_use(def_, code_loc, expr=expr)
        self.uses_by_codeloc[code_loc].add(def_)

    def _add_memory_use(self, atom: MemoryLocation, code_loc: CodeLocation, expr: Optional[Any]=None) -> None:

        # get all current definitions
        current_defs: Iterable[Definition] = self.get_definitions(atom)

        for current_def in current_defs:
            self._add_memory_use_by_def(current_def, code_loc, expr=expr)

    def _add_memory_use_by_def(self, def_: Definition, code_loc: CodeLocation, expr: Optional[Any]=None) -> None:
        self.memory_uses.add_use(def_, code_loc, expr=expr)
        self.uses_by_codeloc[code_loc].add(def_)

    def _add_tmp_use(self, atom: Tmp, code_loc: CodeLocation) -> None:

        if self.track_tmps:
            if atom.tmp_idx in self.tmps:
                defs = self.tmps[atom.tmp_idx]
                for def_ in defs:
                    self._add_tmp_use_by_def(def_, code_loc)
        else:
            if atom.tmp_idx in self.tmps:
                defs = self.tmps[atom.tmp_idx]
                for d in defs:
                    assert not type(d.atom) is Tmp
                    self.add_use_by_def(d, code_loc)

    def _add_tmp_use_by_def(self, def_: Definition, code_loc: CodeLocation) -> None:

        if not isinstance(def_.atom, Tmp):
            raise TypeError("Atom %r is not a Tmp atom." % def_.atom)

        self.tmp_uses[def_.atom.tmp_idx].add(code_loc)
        self.uses_by_codeloc[code_loc].add(def_)
