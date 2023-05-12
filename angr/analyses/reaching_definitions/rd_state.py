from typing import Optional, Iterable, Set, Tuple, Any, TYPE_CHECKING, Iterator, Union
import logging

import archinfo
import claripy

from ...analyses.reaching_definitions.call_trace import CallTrace
from ...storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from ...storage.memory_mixins import MultiValuedMemory
from ...knowledge_plugins.key_definitions import LiveDefinitions
from ...knowledge_plugins.key_definitions.atoms import (
    Atom,
    GuardUse,
    Register,
    MemoryLocation,
    ConstantSrc,
)
from ...knowledge_plugins.functions.function import Function
from ...knowledge_plugins.key_definitions.definition import Definition
from ...knowledge_plugins.key_definitions.environment import Environment
from ...knowledge_plugins.key_definitions.tag import InitialValueTag, ParameterTag, Tag
from ...knowledge_plugins.key_definitions.heap_address import HeapAddress
from ...calling_conventions import SimCC, SimRegArg, SimStackArg
from ...engines.light import SpOffset
from ...code_location import CodeLocation
from .external_codeloc import ExternalCodeLocation
from .heap_allocator import HeapAllocator
from .subject import Subject, SubjectType

if TYPE_CHECKING:
    from .reaching_definitions import ReachingDefinitionsAnalysis


l = logging.getLogger(name=__name__)

#
# Reaching definitions state
#


class ReachingDefinitionsState:
    """
    Represents the internal state of the ReachingDefinitionsAnalysis.

    It contains a data class LiveDefinitions, which stores both definitions and uses for register, stack, memory, and
    temporary variables, uncovered during the analysis.

    :param subject: The subject being analyzed.
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
    :param environment: Representation of the environment of the analyzed program.
    """

    __slots__ = (
        "arch",
        "_subject",
        "_track_tmps",
        "analysis",
        "codeloc",
        "codeloc_uses",
        "live_definitions",
        "all_definitions",
        "_canonical_size",
        "heap_allocator",
        "_environment",
        "_track_consts",
        "_sp_adjusted",
        "exit_observed",
    )

    def __init__(
        self,
        codeloc: CodeLocation,
        arch: archinfo.Arch,
        subject: Subject,
        track_tmps: bool = False,
        track_consts: bool = False,
        analysis: Optional["ReachingDefinitionsAnalysis"] = None,
        rtoc_value=None,
        live_definitions: Optional[LiveDefinitions] = None,
        canonical_size: int = 8,
        heap_allocator: HeapAllocator = None,
        environment: Environment = None,
        sp_adjusted: bool = False,
        all_definitions: Optional[Set[Definition]] = None,
    ):
        # handy short-hands
        self.codeloc = codeloc
        self.arch: archinfo.Arch = arch
        self._subject = subject
        self._track_tmps = track_tmps
        self._track_consts = track_consts
        self.analysis = analysis
        self._canonical_size: int = canonical_size
        self._sp_adjusted: bool = sp_adjusted

        self.all_definitions: Set[Definition] = set() if all_definitions is None else all_definitions

        if live_definitions is None:
            # the first time this state is created. initialize it
            self.live_definitions = LiveDefinitions(
                self.arch, track_tmps=self._track_tmps, canonical_size=canonical_size
            )
            self._set_initialization_values(subject, rtoc_value)
        else:
            # this state is a copy from a previous state. skip the initialization
            self.live_definitions = live_definitions

        self.heap_allocator = heap_allocator or HeapAllocator(canonical_size)
        self._environment: Environment = environment or Environment()

        self.codeloc_uses: Set[Definition] = set()

        # have we observed an exit statement or not during the analysis of the *last instruction* of a block? we should
        # not perform any sp updates if it is the case. this is for handling conditional returns in ARM binaries.
        # this variable is not copied to new states because it only tracks if an exit statement is observed in a single
        # block and is always set to False at the beginning of the analysis of each block.
        self.exit_observed: bool = False

    #
    # Util methods for working with the memory model
    #

    def top(self, bits: int):
        return self.live_definitions.top(bits)

    def is_top(self, *args):
        return self.live_definitions.is_top(*args)

    def heap_address(self, offset: int) -> claripy.ast.Base:
        base = claripy.BVS("heap_base", self.arch.bits, explicit_name=True)
        if offset:
            return base + offset
        return base

    @staticmethod
    def is_heap_address(addr: claripy.ast.Base) -> bool:
        return "heap_base" in addr.variables

    @staticmethod
    def get_heap_offset(addr: claripy.ast.Base) -> Optional[int]:
        if "heap_base" in addr.variables:
            if addr.op == "BVS":
                return 0
            elif addr.op == "__add__" and len(addr.args) == 2 and addr.args[1].op == "BVV":
                return addr.args[1]._model_concrete.value
        return None

    def stack_address(self, offset: int) -> claripy.ast.Base:
        return self.live_definitions.stack_address(offset)

    def is_stack_address(self, addr: claripy.ast.Base) -> bool:
        return self.live_definitions.is_stack_address(addr)

    def get_stack_offset(self, addr: claripy.ast.Base) -> Optional[int]:
        offset = self.live_definitions.get_stack_offset(addr)
        if offset is not None:
            return self._to_signed(offset)
        return None

    def _initial_stack_pointer(self):
        if self.arch.bits == 32:
            return claripy.BVS("stack_base", 32, explicit_name=True)
        elif self.arch.bits == 64:
            return claripy.BVS("stack_base", 64, explicit_name=True)
        else:
            raise ValueError("Unsupported architecture word size %d" % self.arch.bits)

    def _to_signed(self, n):
        if n >= 2 ** (self.arch.bits - 1):
            # convert it to a negative number
            return n - 2**self.arch.bits
        return n

    def annotate_with_def(self, symvar: claripy.ast.Base, definition: Definition) -> claripy.ast.Base:
        """

        :param symvar:
        :param definition:
        :return:
        """
        return self.live_definitions.annotate_with_def(symvar, definition)

    def annotate_mv_with_def(self, mv: MultiValues, definition: Definition) -> MultiValues:
        return MultiValues(
            offset_to_values={
                offset: {self.annotate_with_def(value, definition) for value in values} for offset, values in mv.items()
            }
        )

    def extract_defs(self, symvar: claripy.ast.Base) -> Iterator[Definition]:
        yield from self.live_definitions.extract_defs(symvar)

    #
    # Other methods
    #

    @property
    def tmp_definitions(self):
        return self.live_definitions.tmps

    @property
    def tmp_uses(self):
        return self.live_definitions.tmp_uses

    @property
    def register_uses(self):
        return self.live_definitions.register_uses

    @property
    def register_definitions(self) -> MultiValuedMemory:
        return self.live_definitions.register_definitions

    @property
    def stack_definitions(self) -> MultiValuedMemory:
        return self.live_definitions.stack_definitions

    @property
    def stack_uses(self):
        return self.live_definitions.stack_uses

    @property
    def heap_definitions(self) -> MultiValuedMemory:
        return self.live_definitions.heap_definitions

    @property
    def heap_uses(self):
        return self.live_definitions.heap_uses

    @property
    def memory_uses(self):
        return self.live_definitions.memory_uses

    @property
    def memory_definitions(self) -> MultiValuedMemory:
        return self.live_definitions.memory_definitions

    @property
    def uses_by_codeloc(self):
        return self.live_definitions.uses_by_codeloc

    def get_sp(self) -> int:
        return self.live_definitions.get_sp()

    def get_stack_address(self, offset: claripy.ast.Base) -> int:
        return self.live_definitions.get_stack_address(offset)

    @property
    def environment(self):
        return self._environment

    @property
    def _dep_graph(self):
        return self.analysis._dep_graph

    @property
    def dep_graph(self):
        return self.analysis.dep_graph

    def __repr__(self):
        ctnt = "RDState-%r" % (self.live_definitions)
        return "{%s}" % ctnt

    def _set_initialization_values(self, subject: Subject, rtoc_value: Optional[int] = None):
        if subject.type == SubjectType.Function:
            if isinstance(self.arch, archinfo.arch_ppc64.ArchPPC64) and not rtoc_value:
                raise ValueError("The architecture being ppc64, the parameter `rtoc_value` should be provided.")

            self._initialize_function(
                subject.cc,
                subject.content.addr,
                rtoc_value,
            )
        elif subject.type == SubjectType.CallTrace:
            if isinstance(self.arch, archinfo.arch_ppc64.ArchPPC64) and not rtoc_value:
                raise ValueError("The architecture being ppc64, the parameter `rtoc_value` should be provided.")

            self._initialize_function(
                subject.cc,
                subject.content.current_function_address(),
                rtoc_value,
            )
        elif subject.type == SubjectType.Block:
            pass

        return self

    def _generate_call_string(self, current_address: int) -> Tuple[int, ...]:
        if isinstance(self._subject.content, Function):
            return (self._subject.content.addr,)
        elif isinstance(self._subject.content, CallTrace):
            if any(current_address == x.caller_func_addr for x in self._subject.content.callsites):
                callsites = iter(reversed([x.caller_func_addr for x in self._subject.content.callsites]))
                for call_addr in callsites:
                    if current_address == call_addr:
                        break
                return tuple(callsites)
            else:
                return tuple(x.caller_func_addr for x in self._subject.content.callsites)
        else:
            l.warning("Subject with unknown content-type")
            return None

    def _initialize_function(self, cc: SimCC, func_addr: int, rtoc_value: Optional[int] = None):
        # initialize stack pointer
        call_string = self._generate_call_string(func_addr)
        sp_atom = Register(self.arch.sp_offset, self.arch.bytes)
        sp_def = Definition(sp_atom, ExternalCodeLocation(call_string), tags={InitialValueTag()})
        sp = self.annotate_with_def(self._initial_stack_pointer(), sp_def)
        self.register_definitions.store(self.arch.sp_offset, sp)

        if cc is not None:
            prototype = self.analysis.kb.functions[func_addr].prototype
            if prototype is not None:
                for loc in cc.arg_locs(prototype):
                    for arg in loc.get_footprint():
                        # initialize register parameters
                        if isinstance(arg, SimRegArg):
                            # FIXME: implement reg_offset handling in SimRegArg
                            reg_offset = self.arch.registers[arg.reg_name][0]
                            reg_atom = Register(reg_offset, self.arch.bytes)
                            reg_def = Definition(
                                reg_atom, ExternalCodeLocation(call_string), tags={ParameterTag(function=func_addr)}
                            )
                            self.all_definitions.add(reg_def)
                            reg = self.annotate_with_def(self.top(self.arch.bits), reg_def)
                            self.register_definitions.store(reg_offset, reg)

                        # initialize stack parameters
                        elif isinstance(arg, SimStackArg):
                            ml_atom = MemoryLocation(SpOffset(self.arch.bits, arg.stack_offset), arg.size)
                            ml_def = Definition(
                                ml_atom, ExternalCodeLocation(call_string), tags={ParameterTag(function=func_addr)}
                            )
                            self.all_definitions.add(ml_def)
                            ml = self.annotate_with_def(self.top(self.arch.bits), ml_def)
                            stack_address = self.get_stack_address(self.stack_address(arg.stack_offset))
                            self.stack_definitions.store(stack_address, ml, endness=self.arch.memory_endness)
                        else:
                            raise TypeError("Unsupported parameter type %s." % type(arg).__name__)

        # architecture dependent initialization
        if self.arch.name.startswith("PPC64"):
            if rtoc_value is None:
                raise TypeError("rtoc_value must be provided on PPC64.")
            offset, size = self.arch.registers["rtoc"]
            rtoc_atom = Register(offset, size)
            rtoc_def = Definition(rtoc_atom, ExternalCodeLocation(call_string), tags={InitialValueTag()})
            self.all_definitions.add(rtoc_def)
            rtoc = self.annotate_with_def(claripy.BVV(rtoc_value, self.arch.bits), rtoc_def)
            self.register_definitions.store(offset, rtoc)
        elif self.arch.name.startswith("MIPS64"):
            offset, size = self.arch.registers["t9"]
            t9_atom = Register(offset, size)
            t9_def = Definition(t9_atom, ExternalCodeLocation(call_string), tags={InitialValueTag()})
            self.all_definitions.add(t9_def)
            t9 = self.annotate_with_def(claripy.BVV(func_addr, self.arch.bits), t9_def)
            self.register_definitions.store(offset, t9)
        elif self.arch.name.startswith("MIPS"):
            if func_addr is None:
                l.warning("func_addr must not be None to initialize a function in mips")
            t9_offset = self.arch.registers["t9"][0]
            t9_atom = Register(t9_offset, self.arch.bytes)
            t9_def = Definition(t9_atom, ExternalCodeLocation(call_string), tags={InitialValueTag()})
            self.all_definitions.add(t9_def)
            t9 = self.annotate_with_def(claripy.BVV(func_addr, self.arch.bits), t9_def)
            self.register_definitions.store(t9_offset, t9)

    def copy(self) -> "ReachingDefinitionsState":
        rd = ReachingDefinitionsState(
            self.codeloc,
            self.arch,
            self._subject,
            track_tmps=self._track_tmps,
            track_consts=self._track_consts,
            analysis=self.analysis,
            live_definitions=self.live_definitions.copy(),
            canonical_size=self._canonical_size,
            heap_allocator=self.heap_allocator,
            environment=self._environment,
            sp_adjusted=self._sp_adjusted,
            all_definitions=self.all_definitions.copy(),
        )

        return rd

    def merge(self, *others) -> Tuple["ReachingDefinitionsState", bool]:
        state = self.copy()
        others: Iterable["ReachingDefinitionsState"]

        state.live_definitions, merged_0 = state.live_definitions.merge(*[other.live_definitions for other in others])
        state._environment, merged_1 = state.environment.merge(*[other.environment for other in others])

        return state, merged_0 or merged_1

    def move_codelocs(self, new_codeloc: CodeLocation) -> None:
        if self.codeloc != new_codeloc:
            self.codeloc = new_codeloc
            self.codeloc_uses = set()

    def kill_definitions(self, atom: Atom) -> None:
        """
        Overwrite existing definitions w.r.t 'atom' with a dummy definition instance. A dummy definition will not be
        removed during simplification.
        """

        self.live_definitions.kill_definitions(atom)

    def kill_and_add_definition(
        self,
        atom: Atom,
        data: MultiValues,
        dummy=False,
        tags: Set[Tag] = None,
        endness=None,  # XXX destroy
        annotated: bool = False,
        uses: Optional[Set[Definition]] = None,
        override_codeloc: Optional[CodeLocation] = None,
    ) -> Tuple[Optional[MultiValues], Set[Definition]]:
        codeloc = override_codeloc or self.codeloc
        mv = self.live_definitions.kill_and_add_definition(
            atom, codeloc, data, dummy=dummy, tags=tags, endness=endness, annotated=annotated
        )

        if mv is not None:
            defs = set(LiveDefinitions.extract_defs_from_mv(mv))
            self.all_definitions |= defs

            if self._dep_graph is not None:
                stack_use = {u for u in self.codeloc_uses if isinstance(u.atom, MemoryLocation) and u.atom.is_on_stack}

                sp_offset = self.arch.sp_offset
                bp_offset = self.arch.bp_offset

                values = set()
                for vs in mv.values():
                    for v in vs:
                        values.add(v)

                if uses is None:
                    uses = self.codeloc_uses
                for used in uses:
                    # sp is always used as a stack pointer, and we do not track dependencies against stack pointers.
                    # bp is sometimes used as a base pointer. we recognize such cases by checking if there is a use to
                    # the stack variable.
                    #
                    # There are two cases for which it is superfluous to report a dependency on (a use of) stack/base
                    # pointers:
                    # - The `Definition` *uses* a `MemoryLocation` pointing to the stack;
                    # - The `Definition` *is* a `MemoryLocation` pointing to the stack.
                    is_using_spbp_while_memory_address_on_stack_is_used = (
                        isinstance(used.atom, Register)
                        and used.atom.reg_offset in (sp_offset, bp_offset)
                        and len(stack_use) > 0
                    )
                    is_using_spbp_to_define_memory_location_on_stack = (
                        isinstance(atom, MemoryLocation)
                        and (
                            atom.is_on_stack
                            or (isinstance(atom.addr, claripy.ast.Base) and self.is_stack_address(atom.addr))
                        )
                        and isinstance(used.atom, Register)
                        and used.atom.reg_offset in (sp_offset, bp_offset)
                    )

                    if not (
                        is_using_spbp_while_memory_address_on_stack_is_used
                        or is_using_spbp_to_define_memory_location_on_stack
                    ):
                        # Moderately confusing misnomers. This is an edge from a def to a use, since the
                        # "uses" are actually the definitions that we're using and the "definition" is the
                        # new definition; i.e. The def that the old def is used to construct so this is
                        # really a graph where nodes are defs and edges are uses.
                        self._dep_graph.add_node(used)
                        for def_ in defs:
                            if not def_.dummy:
                                self._dep_graph.add_edge(used, def_)
                        self._dep_graph.add_dependencies_for_concrete_pointers_of(
                            values,
                            used,
                            self.analysis.project.kb.cfgs.get_most_accurate(),
                            self.analysis.project.loader,
                        )
        else:
            defs = set()

        return mv, defs

    def add_use(self, atom: Atom, expr: Optional[Any] = None) -> None:
        self.codeloc_uses.update(self.get_definitions(atom))

        self.live_definitions.add_use(atom, self.codeloc, expr=expr)

    def add_use_by_def(self, definition: Definition, expr: Optional[Any] = None) -> None:
        self.codeloc_uses.add(definition)

        self.live_definitions.add_use_by_def(definition, self.codeloc, expr=expr)

    def add_tmp_use(self, tmp: int, expr: Optional[Any] = None) -> None:
        defs = self.live_definitions.get_tmp_definitions(tmp)
        self.add_tmp_use_by_defs(defs, expr=expr)

    def add_tmp_use_by_defs(
        self, defs: Iterable[Definition], expr: Optional[Any] = None
    ) -> None:  # pylint:disable=unused-argument
        for definition in defs:
            self.codeloc_uses.add(definition)
            # if track_tmps is False, definitions may not be Tmp definitions
            self.live_definitions.add_use_by_def(definition, self.codeloc, expr=expr)

    def add_register_use(self, reg_offset: int, size: int, expr: Optional[Any] = None) -> None:
        defs = self.live_definitions.get_register_definitions(reg_offset, size)
        self.add_register_use_by_defs(defs, expr=expr)

    def add_register_use_by_defs(self, defs: Iterable[Definition], expr: Optional[Any] = None) -> None:
        for definition in defs:
            self.codeloc_uses.add(definition)
            self.live_definitions.add_register_use_by_def(definition, self.codeloc, expr=expr)

    def add_stack_use(self, stack_offset: int, size: int, endness, expr: Optional[Any] = None) -> None:
        defs = self.live_definitions.get_stack_definitions(stack_offset, size, endness)
        self.add_stack_use_by_defs(defs, expr=expr)

    def add_stack_use_by_defs(self, defs: Iterable[Definition], expr: Optional[Any] = None):
        for definition in defs:
            self.codeloc_uses.add(definition)
            self.live_definitions.add_stack_use_by_def(definition, self.codeloc, expr=expr)

    def add_heap_use(self, heap_offset: int, size: int, endness, expr: Optional[Any] = None) -> None:
        defs = self.live_definitions.get_heap_definitions(heap_offset, size, endness)
        self.add_heap_use_by_defs(defs, expr=expr)

    def add_heap_use_by_defs(self, defs: Iterable[Definition], expr: Optional[Any] = None):
        for definition in defs:
            self.codeloc_uses.add(definition)
            self.live_definitions.add_heap_use_by_def(definition, self.codeloc, expr=expr)

    def add_memory_use_by_def(self, definition: Definition, expr: Optional[Any] = None):
        self.codeloc_uses.add(definition)
        self.live_definitions.add_memory_use_by_def(definition, self.codeloc, expr=expr)

    def add_memory_use_by_defs(self, defs: Iterable[Definition], expr: Optional[Any] = None):
        for definition in defs:
            self.codeloc_uses.add(definition)
            self.live_definitions.add_memory_use_by_def(definition, self.codeloc, expr=expr)

    def get_definitions(self, atom: Atom) -> Iterable[Definition]:
        yield from self.live_definitions.get_definitions(atom)

    def get_values(self, spec: Union[Atom, Definition]) -> Optional[MultiValues]:
        return self.live_definitions.get_values(spec)

    def get_one_value(self, spec: Union[Atom, Definition]) -> Optional[claripy.ast.base.Base]:
        return self.live_definitions.get_one_value(spec)

    def get_concrete_value(self, spec: Union[Atom, Definition]) -> Optional[int]:
        return self.live_definitions.get_concrete_value(spec)

    def mark_guard(self, target):
        atom = GuardUse(target)
        kinda_definition = Definition(atom, self.codeloc)

        if self._dep_graph is not None:
            self._dep_graph.add_node(kinda_definition)
            for used in self.codeloc_uses:
                self._dep_graph.add_edge(used, kinda_definition)

    def mark_const(self, value: int, size: int):
        atom = ConstantSrc(value, size)
        kinda_definition = Definition(atom, self.codeloc)

        if self._dep_graph is not None and self._track_consts:
            self._dep_graph.add_node(kinda_definition)
            self.codeloc_uses.add(kinda_definition)
            self.live_definitions.uses_by_codeloc[self.codeloc].add(kinda_definition)

    def downsize(self):
        self.all_definitions = set()

    def pointer_to_atoms(self, pointer: MultiValues, size: int, endness: str) -> Set[MemoryLocation]:
        """
        Given a MultiValues, return the set of atoms that loading or storing to the pointer with that value
        could define or use.
        """
        result = set()
        for vs in pointer.values():
            for value in vs:
                atom = self.pointer_to_atom(value, size, endness)
                if atom is not None:
                    result.add(atom)

        return result

    def pointer_to_atom(self, value: claripy.ast.base.Base, size: int, endness: str) -> Optional[MemoryLocation]:
        if self.is_top(value):
            return None

        # TODO this can be simplified with the walrus operator
        stack_offset = self.get_stack_offset(value)
        if stack_offset is not None:
            addr = SpOffset(len(value), stack_offset)
        else:
            heap_offset = self.get_heap_offset(value)
            if heap_offset is not None:
                addr = HeapAddress(heap_offset)
            elif value.op == "BVV":
                addr = value.args[0]
            else:
                # cannot resolve
                return None

        return MemoryLocation(addr, size, endness)
