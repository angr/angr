from typing import Optional, Iterable, Dict, Set
import logging

import archinfo

from collections import defaultdict

from ...engines.light import SpOffset
from ...keyed_region import KeyedRegion
from ...code_location import CodeLocation
from .atoms import Atom, Register, MemoryLocation, Tmp
from .definition import Definition
from .undefined import undefined
from .uses import Uses
from .dataset import DataSet


l = logging.getLogger(name=__name__)


class LiveDefinitions:
    """
    A LiveDefinitions instance contains definitions and uses for register, stack, memory, and temporary variables,
    uncovered during the analysis.
    """

    __slots__ = ('arch', 'track_tmps', 'register_definitions', 'stack_definitions', 'memory_definitions',
                 'tmp_definitions', 'register_uses', 'stack_uses', 'memory_uses', 'uses_by_codeloc', 'tmp_uses', )

    def __init__(self, arch: archinfo.Arch, track_tmps: bool=False):

        self.arch = arch
        self.track_tmps = track_tmps

        self.register_definitions = KeyedRegion()
        self.stack_definitions = KeyedRegion()
        self.memory_definitions = KeyedRegion()
        self.tmp_definitions: Dict[int,Set[Definition]] = {}

        self.register_uses = Uses()
        self.stack_uses = Uses()
        self.memory_uses = Uses()
        self.uses_by_codeloc: Dict[CodeLocation,Set[Definition]] = defaultdict(set)
        self.tmp_uses: Dict[int,Set[CodeLocation]] = defaultdict(set)

    def __repr__(self):
        ctnt = "LiveDefs, %d regdefs, %d stackdefs, %d memdefs" % (
                len(self.register_definitions),
                len(self.stack_definitions),
                len(self.memory_definitions),
                )
        if self.tmp_definitions:
            ctnt += ", %d tmpdefs" % len(self.tmp_definitions)
        return "<%s>" % ctnt

    def copy(self) -> 'LiveDefinitions':
        rd = LiveDefinitions(self.arch, track_tmps=self.track_tmps)

        rd.register_definitions = self.register_definitions.copy()
        rd.stack_definitions = self.stack_definitions.copy()
        rd.memory_definitions = self.memory_definitions.copy()
        rd.tmp_definitions = self.tmp_definitions.copy()
        rd.register_uses = self.register_uses.copy()
        rd.stack_uses = self.stack_uses.copy()
        rd.memory_uses = self.memory_uses.copy()
        rd.tmp_uses = self.tmp_uses.copy()

        return rd

    def get_sp(self) -> int:
        """
        Return the concrete value contained by the stack pointer.
        """
        sp_definitions = self.register_definitions.get_objects_by_offset(self.arch.sp_offset)

        assert len(sp_definitions) == 1
        [sp_definition] = sp_definitions

        # Assuming sp_definition has only one concrete value.
        return sp_definition.data.get_first_element()

    def merge(self, *others):

        state = self.copy()

        for other in others:
            other: LiveDefinitions
            state.register_definitions.merge(other.register_definitions)
            state.stack_definitions.merge(other.stack_definitions)
            state.memory_definitions.merge(other.memory_definitions)

            state.register_uses.merge(other.register_uses)
            state.stack_uses.merge(other.stack_uses)
            state.memory_uses.merge(other.memory_uses)

        return state

    def kill_definitions(self, atom: Atom, code_loc: CodeLocation, data: Optional[DataSet]=None, dummy=True) -> None:
        """
        Overwrite existing definitions w.r.t 'atom' with a dummy definition instance. A dummy definition will not be
        removed during simplification.

        :param atom:
        :param CodeLocation code_loc:
        :return: None
        """

        data = DataSet(undefined, atom.size)
        self.kill_and_add_definition(atom, code_loc, data, dummy=dummy)

    def kill_and_add_definition(self, atom: Atom, code_loc: CodeLocation, data: Optional[DataSet],
                                dummy=False) -> Optional[Definition]:
        data = data or DataSet(undefined, atom.size)
        definition: Definition = Definition(atom, code_loc, data, dummy=dummy)

        # set_object() replaces kill (not implemented) and add (add) in one step
        if isinstance(atom, Register):
            self.register_definitions.set_object(atom.reg_offset, definition, atom.size)
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset):
                self.stack_definitions.set_object(atom.addr.offset, definition, atom.size)
            elif isinstance(atom.addr, int):
                self.memory_definitions.set_object(atom.addr, definition, atom.size)
            else:
                return None
        elif isinstance(atom, Tmp):
            if self.track_tmps:
                self.tmp_definitions[atom.tmp_idx] = { definition }
            else:
                self.tmp_definitions[atom.tmp_idx] = self.uses_by_codeloc[code_loc]
                return None
        else:
            raise NotImplementedError()

        return definition

    def add_use(self, atom: Atom, code_loc) -> None:
        if isinstance(atom, Register):
            self._add_register_use(atom, code_loc)
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset):
                self._add_stack_use(atom, code_loc)
            elif isinstance(atom.addr, int):
                self._add_memory_use(atom, code_loc)
            else:
                # ignore RegisterOffset
                pass
        elif isinstance(atom, Tmp):
            self._add_tmp_use(atom, code_loc)
        else:
            raise TypeError("Unsupported atom type %s." % type(atom))

    def add_use_by_def(self, definition: Definition, code_loc: CodeLocation) -> None:
        if isinstance(definition.atom, Register):
            self._add_register_use_by_def(definition, code_loc)
        elif isinstance(definition.atom, MemoryLocation):
            if isinstance(definition.atom.addr, SpOffset):
                self._add_stack_use_by_def(definition, code_loc)
            elif isinstance(definition.atom.addr, MemoryLocation):
                self._add_memory_use_by_def(definition, code_loc)
            else:
                # ignore RegisterOffset
                pass
        elif type(definition.atom) is Tmp:
            self._add_tmp_use_by_def(definition, code_loc)
        else:
            raise TypeError()

    def get_definitions(self, atom) -> Iterable[Definition]:
        if isinstance(atom, Register):
            return self.register_definitions.get_objects_by_offset(atom.reg_offset)
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset):
                return self.stack_definitions.get_objects_by_offset(atom.addr.offset)
            elif isinstance(atom.addr, int):
                return self.memory_definitions.get_objects_by_offset(atom.addr)
            else:
                return [ ]
        elif type(atom) is Tmp:
            return self.tmp_definitions[atom.tmp_idx]
        else:
            raise TypeError()

    #
    # Private methods
    #

    def _add_register_use(self, atom: Register, code_loc: CodeLocation) -> None:
        # get all current definitions
        current_defs: Iterable[Definition] = self.register_definitions.get_objects_by_offset(atom.reg_offset)

        for current_def in current_defs:
            self._add_register_use_by_def(current_def, code_loc)

    def _add_register_use_by_def(self, def_: Definition, code_loc: CodeLocation) -> None:
        self.register_uses.add_use(def_, code_loc)
        self.uses_by_codeloc[code_loc].add(def_)

    def _add_stack_use(self, atom: MemoryLocation, code_loc: CodeLocation) -> None:

        if not isinstance(atom.addr, SpOffset):
            raise TypeError("Atom %r is not a stack location atom." % atom)

        current_defs = self.stack_definitions.get_objects_by_offset(atom.addr.offset)

        for current_def in current_defs:
            self._add_stack_use_by_def(current_def, code_loc)

    def _add_stack_use_by_def(self, def_: Definition, code_loc: CodeLocation) -> None:
        self.stack_uses.add_use(def_, code_loc)
        self.uses_by_codeloc[code_loc].add(def_)

    def _add_memory_use(self, atom: MemoryLocation, code_loc: CodeLocation) -> None:

        # get all current definitions
        current_defs: Iterable[Definition] = self.memory_definitions.get_objects_by_offset(atom.addr)

        for current_def in current_defs:
            self._add_memory_use_by_def(current_def, code_loc)

    def _add_memory_use_by_def(self, def_: Definition, code_loc: CodeLocation) -> None:
        self.memory_uses.add_use(def_, code_loc)
        self.uses_by_codeloc[code_loc].add(def_)

    def _add_tmp_use(self, atom: Tmp, code_loc: CodeLocation) -> None:

        if self.track_tmps:
            defs = self.tmp_definitions[atom.tmp_idx]
            for def_ in defs:
                self._add_tmp_use_by_def(def_, code_loc)
        else:
            defs = self.tmp_definitions[atom.tmp_idx]
            for d in defs:
                assert not type(d.atom) is Tmp
                self.add_use_by_def(d, code_loc)

    def _add_tmp_use_by_def(self, def_: Definition, code_loc: CodeLocation) -> None:

        if not isinstance(def_.atom, Tmp):
            raise TypeError("Atom %r is not a Tmp atom." % def_.atom)

        self.tmp_uses[def_.atom.tmp_idx].add(code_loc)
        self.uses_by_codeloc[code_loc].add(def_)
