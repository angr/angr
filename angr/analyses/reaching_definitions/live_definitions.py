from typing import Optional, Iterable, Dict, Set
import logging

import archinfo

from collections import defaultdict

from ...calling_conventions import SimCC, SimRegArg, SimStackArg
from ...engines.light import SpOffset
from ...keyed_region import KeyedRegion
from ..code_location import CodeLocation
from .atoms import Atom, GuardUse, Register, MemoryLocation, Tmp
from .dataset import DataSet
from .definition import Definition
from .external_codeloc import ExternalCodeLocation
from .subject import Subject, SubjectType
from .undefined import undefined
from .uses import Uses


l = logging.getLogger(name=__name__)


class LiveDefinitions:

    __slots__ = ('arch', '_subject', '_track_tmps', 'analysis', 'register_definitions', 'stack_definitions',
                 'memory_definitions', 'tmp_definitions', 'register_uses', 'stack_uses', 'memory_uses',
                 'uses_by_codeloc', 'tmp_uses', 'all_definitions', 'current_codeloc', 'codeloc_uses')

    """
    Represents the internal state of the ReachingDefinitionsAnalysis.

    It contains definitions and uses for register, stack, memory, and temporary variables, uncovered during the analysis.

    :param angr.analyses.reaching_definitions.Subject: The subject being analysed.
    :param archinfo.Arch arch: The architecture targeted by the program.
    :param Boolean track_tmps: Only tells whether or not temporary variables should be taken into consideration when
                              representing the state of the analysis.
                              Should be set to true when the analysis has counted uses and definitions for temporary
                              variables, false otherwise.
    :param angr.analyses.analysis.Analysis analysis: The analysis that generated the state represented by this object.
    :param int rtoc_value: When the targeted architecture is ppc64, the initial function needs to know the `rtoc_value`.
    """
    def __init__(self, arch: archinfo.Arch, subject: Subject, track_tmps: bool=False, analysis=None, rtoc_value=None):

        # handy short-hands
        self.arch = arch
        self._subject = subject
        self._track_tmps = track_tmps
        self.analysis = analysis

        self.register_definitions = KeyedRegion()
        self.stack_definitions = KeyedRegion()
        self.memory_definitions = KeyedRegion()
        self.tmp_definitions: Dict[int,Set[Definition]] = {}
        self.all_definitions: Set[Definition] = set()

        self._set_initialization_values(subject, rtoc_value)

        self.register_uses = Uses()
        self.stack_uses = Uses()
        self.memory_uses = Uses()
        self.uses_by_codeloc: Dict[CodeLocation,Set[Definition]] = defaultdict(set)
        self.tmp_uses: Dict[int,Set[CodeLocation]] = defaultdict(set)
        self.current_codeloc: Optional[CodeLocation] = None
        self.codeloc_uses: Set[Definition] = set()

    def __repr__(self):
        ctnt = "LiveDefs, %d regdefs, %d stackdefs, %d memdefs" % (
                len(self.register_definitions),
                len(self.stack_definitions),
                len(self.memory_definitions),
                )
        if self._track_tmps:
            ctnt += ", %d tmpdefs" % len(self.tmp_definitions)
        return "<%s>" % ctnt

    @property
    def dep_graph(self):
        return self.analysis.dep_graph

    def _set_initialization_values(self, subject: Subject, rtoc_value: Optional[int]=None):
        if subject.type is SubjectType.Function:
            if isinstance(self.arch, archinfo.arch_ppc64.ArchPPC64) and not rtoc_value:
                raise ValueError('The architecture being ppc64, the parameter `rtoc_value` should be provided.')

            self._initialize_function(
                subject.cc,
                subject.content.addr,
                rtoc_value,
            )
        elif subject.type is SubjectType.Block:
            pass

        return self

    def _initialize_function(self, cc: SimCC, func_addr: int, rtoc_value: Optional[int]=None):
        # initialize stack pointer
        sp = Register(self.arch.sp_offset, self.arch.bytes)
        sp_def = Definition(sp, ExternalCodeLocation(), DataSet(SpOffset(self.arch.bits, 0), self.arch.bits))
        self.register_definitions.set_object(sp_def.offset, sp_def, sp_def.size)
        if self.arch.name.startswith('MIPS'):
            if func_addr is None:
                l.warning("func_addr must not be None to initialize a function in mips")
            t9 = Register(self.arch.registers['t9'][0], self.arch.bytes)
            t9_def = Definition(t9, ExternalCodeLocation(), DataSet(func_addr, self.arch.bits))
            self.register_definitions.set_object(t9_def.offset,t9_def,t9_def.size)

        if cc is not None and cc.args is not None:
            for arg in cc.args:
                # initialize register parameters
                if isinstance(arg, SimRegArg):
                    # FIXME: implement reg_offset handling in SimRegArg
                    reg_offset = self.arch.registers[arg.reg_name][0]
                    reg = Register(reg_offset, self.arch.bytes)
                    reg_def = Definition(reg, ExternalCodeLocation(), DataSet(undefined, self.arch.bits))
                    self.register_definitions.set_object(reg.reg_offset, reg_def, reg.size)
                # initialize stack parameters
                elif isinstance(arg, SimStackArg):
                    sp_offset = SpOffset(self.arch.bits, arg.stack_offset)
                    ml = MemoryLocation(sp_offset, arg.size)
                    ml_def = Definition(ml, ExternalCodeLocation(), DataSet(undefined, arg.size * 8))
                    self.stack_definitions.set_object(arg.stack_offset, ml_def, ml.size)
                else:
                    raise TypeError('Unsupported parameter type %s.' % type(arg).__name__)

        # architecture dependent initialization
        if self.arch.name.lower().find('ppc64') > -1:
            if rtoc_value is None:
                raise TypeError("rtoc_value must be provided on PPC64.")
            offset, size = self.arch.registers['rtoc']
            rtoc = Register(offset, size)
            rtoc_def = Definition(rtoc, ExternalCodeLocation(), DataSet(rtoc_value, self.arch.bits))
            self.register_definitions.set_object(rtoc.reg_offset, rtoc_def, rtoc.size)
        elif self.arch.name.lower().find('mips64') > -1:
            offset, size = self.arch.registers['t9']
            t9 = Register(offset, size)
            t9_def = Definition(t9, ExternalCodeLocation(), DataSet({func_addr}, self.arch.bits))
            self.register_definitions.set_object(t9.reg_offset, t9_def, t9.size)

    def copy(self) -> 'LiveDefinitions':
        rd = type(self)(
            self.arch,
            self._subject,
            track_tmps=self._track_tmps,
            analysis=self.analysis,
        )

        rd.register_definitions = self.register_definitions.copy()
        rd.stack_definitions = self.stack_definitions.copy()
        rd.memory_definitions = self.memory_definitions.copy()
        rd.tmp_definitions = self.tmp_definitions.copy()
        rd.register_uses = self.register_uses.copy()
        rd.stack_uses = self.stack_uses.copy()
        rd.memory_uses = self.memory_uses.copy()
        rd.tmp_uses = self.tmp_uses.copy()
        rd.all_definitions = self.all_definitions.copy()

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

            state.all_definitions.update(other.all_definitions)

        return state

    def _cycle(self, code_loc: CodeLocation) -> None:
        if code_loc != self.current_codeloc:
            self.current_codeloc = code_loc
            self.codeloc_uses = set()

    def kill_definitions(self, atom: Atom, code_loc: CodeLocation, data: Optional[DataSet]=None, dummy=True) -> None:
        """
        Overwrite existing definitions w.r.t 'atom' with a dummy definition instance. A dummy definition will not be
        removed during simplification.

        :param atom:
        :param CodeLocation code_loc:
        :param object data:
        :return: None
        """

        if data is None:
            data = DataSet(undefined, atom.size)

        self.kill_and_add_definition(atom, code_loc, data, dummy=dummy)

    def kill_and_add_definition(self, atom: Atom, code_loc: CodeLocation, data: Optional[DataSet],
                                dummy=False) -> Optional[Definition]:
        self._cycle(code_loc)

        definition: Optional[Definition]

        if isinstance(atom, Register):
            definition = self._kill_and_add_register_definition(atom, code_loc, data, dummy=dummy)
        elif isinstance(atom, MemoryLocation):
            if isinstance(atom.addr, SpOffset):
                definition = self._kill_and_add_stack_definition(atom, code_loc, data, dummy=dummy)
            elif isinstance(atom.addr, int):
                definition = self._kill_and_add_memory_definition(atom, code_loc, data, dummy=dummy)
            else:
                # ignore
                definition = None
        elif isinstance(atom, Tmp):
            definition = self._add_tmp_definition(atom, code_loc, data)
        else:
            raise NotImplementedError()

        if definition is not None:
            self.all_definitions.add(definition)

            if self.dep_graph is not None:
                stack_use = set(filter(
                    lambda u: isinstance(u.atom, MemoryLocation) and u.atom.is_on_stack,
                    self.codeloc_uses
                ))

                sp_offset = self.arch.sp_offset
                bp_offset = self.arch.bp_offset

                for used in self.codeloc_uses:
                    # sp is always used as a stack pointer, and we do not track dependencies against stack pointers.
                    # bp is sometimes used as a base pointer. we recognize such cases by checking if there is a use to
                    # the stack variable.
                    #
                    # There are two cases for which it is superfluous to report a dependency on (a use of) stack/base
                    # pointers:
                    # - The `Definition` *uses* a `MemoryLocation` pointing to the stack;
                    # - The `Definition` *is* a `MemoryLocation` pointing to the stack.
                    is_using_spbp_while_memory_address_on_stack_is_used = (
                        isinstance(used.atom, Register) and
                        used.atom.reg_offset in (sp_offset, bp_offset) and
                        len(stack_use) > 0
                    )
                    is_using_spbp_to_define_memory_location_on_stack = (
                        isinstance(definition.atom, MemoryLocation) and
                        definition.atom.is_on_stack and
                        isinstance(used.atom, Register) and
                        used.atom.reg_offset in (sp_offset, bp_offset)
                    )

                    if not (
                        is_using_spbp_while_memory_address_on_stack_is_used or
                        is_using_spbp_to_define_memory_location_on_stack
                    ):
                        # Moderately confusing misnomers. This is an edge from a def to a use, since the
                        # "uses" are actually the definitions that we're using and the "definition" is the
                        # new definition; i.e. The def that the old def is used to construct so this is
                        # really a graph where nodes are defs and edges are uses.
                        self.dep_graph.add_edge(used, definition)

        return definition

    def add_use(self, atom: Atom, code_loc) -> None:
        self._cycle(code_loc)
        self.codeloc_uses.update(self.get_definitions(atom))

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

    def add_use_by_def(self, definition, code_loc) -> None:
        self._cycle(code_loc)
        self.codeloc_uses.update({definition})

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

    def mark_guard(self, code_loc: CodeLocation, data: DataSet, target):
        self._cycle(code_loc)
        atom = GuardUse(target)
        kinda_definition = Definition(atom, code_loc, data)

        if self.dep_graph is not None:
            for used in self.codeloc_uses:
                self.dep_graph.add_edge(used, kinda_definition)

    #
    # Private methods
    #

    def _kill_and_add_register_definition(self, atom: Register, code_loc: CodeLocation, data: Optional[DataSet],
                                          dummy=False) -> Definition:

        if data is None:
            data = DataSet(undefined, atom.size)
        definition = Definition(atom, code_loc, data, dummy=dummy)
        # set_object() replaces kill (not implemented) and add (add) in one step
        self.register_definitions.set_object(atom.reg_offset, definition, atom.size)
        return definition

    def _kill_and_add_stack_definition(self, atom: MemoryLocation, code_loc: CodeLocation, data: Optional[DataSet],
                                       dummy=False) -> Definition:
        if not isinstance(atom.addr, SpOffset):
            raise TypeError("Atom %r does not represent a stack variable." % atom)
        if data is None:
            data = DataSet(undefined, atom.size)
        definition = Definition(atom, code_loc, data, dummy=dummy)
        self.stack_definitions.set_object(atom.addr.offset, definition, data.bits // 8)
        return definition

    def _kill_and_add_memory_definition(self, atom: MemoryLocation, code_loc: CodeLocation, data: Optional[DataSet],
                                        dummy=False) -> Definition:
        if data is None:
            data = DataSet(undefined, atom.size)
        definition = Definition(atom, code_loc, data, dummy=dummy)
        # set_object() replaces kill (not implemented) and add (add) in one step
        self.memory_definitions.set_object(atom.addr, definition, atom.size)
        return definition

    def _add_tmp_definition(self, atom: Tmp, code_loc: CodeLocation, data: Optional[DataSet]) -> Optional[Definition]:

        if self._track_tmps:
            if data is None:
                data = DataSet(undefined, atom.size)
            def_ = Definition(atom, code_loc, data)
            self.tmp_definitions[atom.tmp_idx] = { def_ }
            return def_
        else:
            self.tmp_definitions[atom.tmp_idx] = self.uses_by_codeloc[code_loc]
            return None

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

        if self._track_tmps:
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
