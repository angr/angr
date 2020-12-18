from typing import Optional, Iterable, Set, TYPE_CHECKING
import logging

import archinfo

from ...knowledge_plugins.key_definitions import LiveDefinitions
from ...knowledge_plugins.key_definitions.atoms import Atom, GuardUse, Register, MemoryLocation
from ...knowledge_plugins.key_definitions.definition import Definition
from ...knowledge_plugins.key_definitions.environment import Environment
from ...knowledge_plugins.key_definitions.tag import InitialValueTag, ParameterTag, Tag
from ...knowledge_plugins.key_definitions.undefined import UNDEFINED
from ...knowledge_plugins.key_definitions.dataset import DataSet
from ...calling_conventions import SimCC, SimRegArg, SimStackArg
from ...engines.light import SpOffset
from ...code_location import CodeLocation
from .external_codeloc import ExternalCodeLocation
from .heap_allocator import HeapAllocator
from .subject import Subject, SubjectType

if TYPE_CHECKING:
    from .reaching_definitions import ReachingDefinitionsAnalysis


l = logging.getLogger(name=__name__)


class ReachingDefinitionsState:
    """
    Represents the internal state of the ReachingDefinitionsAnalysis.

    It contains a data class LiveDefinitions, which stores both definitions and uses for register, stack, memory, and
    temporary variables, uncovered during the analysis.

    :param subject: The subject being analysed.
    :ivar arch: The architecture targeted by the program.
    :param track_tmps: Only tells whether or not temporary variables should be taken into consideration when
                              representing the state of the analysis.
                              Should be set to true when the analysis has counted uses and definitions for temporary
                              variables, false otherwise.
    :param analysis: The analysis that generated the state represented by this object.
    :param rtoc_value: When the targeted architecture is ppc64, the initial function needs to know the `rtoc_value`.
    :param live_definitions:
    :param canonical_size:
        The sizes (in bytes) that objects with an UNKNOWN_SIZE are treated as for operations where sizes are necessary.
    :param heap_allocator: Mechanism to model the management of heap memory.
    :param environment: Representation of the environment of the analysed program.
    """

    __slots__ = ('arch', '_subject', '_track_tmps', 'analysis', 'current_codeloc', 'codeloc_uses', 'live_definitions',
                 'all_definitions', '_canonical_size', 'heap_allocator', '_environment', )

    def __init__(self, arch: archinfo.Arch, subject: Subject, track_tmps: bool=False,
                 analysis: Optional['ReachingDefinitionsAnalysis']=None, rtoc_value=None,
                 live_definitions=None, canonical_size: int=8, heap_allocator: HeapAllocator=None,
                 environment: Environment=None):

        # handy short-hands
        self.arch = arch
        self._subject = subject
        self._track_tmps = track_tmps
        self.analysis = analysis
        self._canonical_size: int = canonical_size

        if live_definitions is None:
            # the first time this state is created. initialize it
            self.live_definitions = LiveDefinitions(self.arch, track_tmps=self._track_tmps,
                                                    canonical_size=canonical_size)
            self._set_initialization_values(subject, rtoc_value)
        else:
            # this state is a copy from a previous state. skip the initialization
            self.live_definitions = live_definitions

        self.all_definitions: Set[Definition] = set()

        self.heap_allocator = heap_allocator or HeapAllocator(canonical_size)
        self._environment: Environment = environment or Environment()

        self.current_codeloc: Optional[CodeLocation] = None
        self.codeloc_uses: Set[Definition] = set()

    @property
    def tmp_definitions(self): return self.live_definitions.tmp_definitions

    @property
    def tmp_uses(self): return self.live_definitions.tmp_uses

    @property
    def register_uses(self): return self.live_definitions.register_uses

    @property
    def register_definitions(self): return self.live_definitions.register_definitions

    @property
    def stack_definitions(self): return self.live_definitions.stack_definitions

    @property
    def stack_uses(self): return self.live_definitions.stack_uses

    @property
    def heap_definitions(self): return self.live_definitions.heap_definitions

    @property
    def heap_uses(self): return self.live_definitions.heap_uses

    @property
    def memory_uses(self): return self.live_definitions.memory_uses

    @property
    def memory_definitions(self): return self.live_definitions.memory_definitions

    @property
    def uses_by_codeloc(self): return self.live_definitions.uses_by_codeloc

    def get_sp(self) -> int: return self.live_definitions.get_sp()

    @property
    def environment(self): return self._environment

    @property
    def dep_graph(self):
        return self.analysis.dep_graph

    def __repr__(self):
        ctnt = "RDState-%r" % (self.live_definitions)
        return "{%s}" % ctnt

    def _set_initialization_values(self, subject: Subject, rtoc_value: Optional[int]=None):
        if subject.type == SubjectType.Function:
            if isinstance(self.arch, archinfo.arch_ppc64.ArchPPC64) and not rtoc_value:
                raise ValueError('The architecture being ppc64, the parameter `rtoc_value` should be provided.')

            self._initialize_function(
                subject.cc,
                subject.content.addr,
                rtoc_value,
            )
        elif subject.type == SubjectType.CallTrace:
            if isinstance(self.arch, archinfo.arch_ppc64.ArchPPC64) and not rtoc_value:
                raise ValueError('The architecture being ppc64, the parameter `rtoc_value` should be provided.')

            self._initialize_function(
                subject.cc,
                subject.content.current_function_address(),
                rtoc_value,
            )
        elif subject.type == SubjectType.Block:
            pass

        return self

    def _initialize_function(self, cc: SimCC, func_addr: int, rtoc_value: Optional[int]=None):
        # initialize stack pointer
        sp = Register(self.arch.sp_offset, self.arch.bytes)
        sp_def = Definition(sp, ExternalCodeLocation(), DataSet(SpOffset(self.arch.bits, 0), self.arch.bits), tags={InitialValueTag()})
        self.register_definitions.set_object(sp_def.offset, sp_def, sp_def.size)
        if self.arch.name.startswith('MIPS'):
            if func_addr is None:
                l.warning("func_addr must not be None to initialize a function in mips")
            t9 = Register(self.arch.registers['t9'][0], self.arch.bytes)
            t9_def = Definition(t9, ExternalCodeLocation(), DataSet(func_addr, self.arch.bits), tags={InitialValueTag()})
            self.register_definitions.set_object(t9_def.offset,t9_def,t9_def.size)

        if cc is not None and cc.args is not None:
            for arg in cc.args:
                # initialize register parameters
                if isinstance(arg, SimRegArg):
                    # FIXME: implement reg_offset handling in SimRegArg
                    reg_offset = self.arch.registers[arg.reg_name][0]
                    reg = Register(reg_offset, self.arch.bytes)
                    reg_def = Definition(reg, ExternalCodeLocation(), DataSet(UNDEFINED, self.arch.bits), tags={ParameterTag()})
                    self.register_definitions.set_object(reg.reg_offset, reg_def, reg.size)
                # initialize stack parameters
                elif isinstance(arg, SimStackArg):
                    sp_offset = SpOffset(self.arch.bits, arg.stack_offset)
                    ml = MemoryLocation(sp_offset, arg.size)
                    ml_def = Definition(ml, ExternalCodeLocation(), DataSet(UNDEFINED, arg.size * 8), tags={ParameterTag()})
                    self.stack_definitions.set_object(arg.stack_offset, ml_def, ml.size)
                else:
                    raise TypeError('Unsupported parameter type %s.' % type(arg).__name__)

        # architecture dependent initialization
        if self.arch.name.lower().find('ppc64') > -1:
            if rtoc_value is None:
                raise TypeError("rtoc_value must be provided on PPC64.")
            offset, size = self.arch.registers['rtoc']
            rtoc = Register(offset, size)
            rtoc_def = Definition(rtoc, ExternalCodeLocation(), DataSet(rtoc_value, self.arch.bits), tags=InitialValueTag())
            self.register_definitions.set_object(rtoc.reg_offset, rtoc_def, rtoc.size)
        elif self.arch.name.lower().find('mips64') > -1:
            offset, size = self.arch.registers['t9']
            t9 = Register(offset, size)
            t9_def = Definition(t9, ExternalCodeLocation(), DataSet({func_addr}, self.arch.bits), tags=InitialValueTag())
            self.register_definitions.set_object(t9.reg_offset, t9_def, t9.size)

    def copy(self) -> 'ReachingDefinitionsState':
        rd = ReachingDefinitionsState(
            self.arch,
            self._subject,
            track_tmps=self._track_tmps,
            analysis=self.analysis,
            live_definitions=self.live_definitions.copy(),
            canonical_size=self._canonical_size,
            heap_allocator=self.heap_allocator,
            environment=self._environment,
        )

        return rd

    def merge(self, *others):

        state = self.copy()

        for other in others:
            other: 'ReachingDefinitionsState'
            state.live_definitions = state.live_definitions.merge(other.live_definitions)
            state._environment = state.environment.merge(other.environment)

        return state

    def _cycle(self, code_loc: CodeLocation) -> None:
        if code_loc != self.current_codeloc:
            self.current_codeloc = code_loc
            self.codeloc_uses = set()

    def kill_definitions(self, atom: Atom, code_loc: CodeLocation, data: Optional[DataSet]=None, dummy=True, tags: Set[Tag]=None) -> None:
        """
        Overwrite existing definitions w.r.t 'atom' with a dummy definition instance. A dummy definition will not be
        removed during simplification.

        :param atom:
        :param CodeLocation code_loc:
        :param object data:
        :return: None
        """

        if data is None:
            data = DataSet(UNDEFINED, atom.size)

        self.kill_and_add_definition(atom, code_loc, data, dummy=dummy, tags=tags)

    def kill_and_add_definition(self, atom: Atom, code_loc: CodeLocation, data: Optional[DataSet],
                                dummy=False, tags: Set[Tag]=None) -> Optional[Definition]:
        self._cycle(code_loc)

        definition: Optional[Definition]
        definition = self.live_definitions.kill_and_add_definition(atom, code_loc, data, dummy=dummy, tags=tags)

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
                        self.dep_graph.add_dependencies_for_concrete_pointers_of(
                            used,
                            self.analysis.project.kb.cfgs['CFGFast'],
                            self.analysis.project.loader
                        )

        return definition

    def add_use(self, atom: Atom, code_loc) -> None:
        self._cycle(code_loc)
        self.codeloc_uses.update(self.get_definitions(atom))

        self.live_definitions.add_use(atom, code_loc)

    def add_use_by_def(self, definition: Definition, code_loc: CodeLocation) -> None:
        self._cycle(code_loc)
        self.codeloc_uses.add(definition)

        self.live_definitions.add_use_by_def(definition, code_loc)

    def get_definitions(self, atom: Atom) -> Iterable[Definition]:
        return self.live_definitions.get_definitions(atom)

    def mark_guard(self, code_loc: CodeLocation, data: DataSet, target):
        self._cycle(code_loc)
        atom = GuardUse(target)
        kinda_definition = Definition(atom, code_loc, data)

        if self.dep_graph is not None:
            for used in self.codeloc_uses:
                self.dep_graph.add_edge(used, kinda_definition)
