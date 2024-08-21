import logging
from typing import TYPE_CHECKING

import claripy
from archinfo import Arch
from angr.sim_type import SimType, SimTypeFunction
from angr.analyses.reaching_definitions.subject import Subject
from angr.analyses.reaching_definitions.call_trace import CallTrace
from angr.calling_conventions import SimRegArg, SimStackArg, SimCC, SimFunctionArgument
from angr.engines.light import SpOffset
from angr.knowledge_plugins import Function
from angr.knowledge_plugins.key_definitions.atoms import Register, MemoryLocation
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.tag import ParameterTag, InitialValueTag
from angr.code_location import ExternalCodeLocation

l = logging.getLogger(name=__name__)

if TYPE_CHECKING:
    from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState


class RDAStateInitializer:
    """
    This class acts as the basic implementation for the logic that initializes the base state
    for the reaching definitions analysis.

    It also defines the _interface_ that a state initializer should implement,
    if the language/runtime being analyzed requires more complicated logic to set up the state.

    This code/logic was previously part of the ReachingDefinitionsState class, but this was moved here to separate
    these two concerns, and allow easily changing the initialization logic without having to change the state class.

    """

    def __init__(self, arch: Arch, project=None):
        self.arch: Arch = arch
        self.project = project

    def initialize_function_state(
        self, state: "ReachingDefinitionsState", cc: SimCC | None, func_addr: int, rtoc_value: int | None = None
    ) -> None:
        """
        This is the entry point to the state initialization logic.
        It will be called during the initialization of an ReachingDefinitionsState,
        if the state was freshly created (without existing live_definitions)
        """
        call_string = self._generate_call_string(state._subject, func_addr)
        ex_loc = ExternalCodeLocation(call_string)
        if state.analysis is not None:
            state.analysis.model.at_new_stmt(ex_loc)

        # Setup Stack pointer
        self.initialize_stack_pointer(state, func_addr, ex_loc)

        # initialize function arguments, based on the calling convention and signature
        if state.analysis is not None and cc is not None:
            prototype = state.analysis.kb.functions[func_addr].prototype
        else:
            prototype = None
        self.initialize_all_function_arguments(state, func_addr, ex_loc, cc, prototype)

        # architecture dependent initialization
        self.initialize_architectural_state(state, func_addr, ex_loc, rtoc_value)

        if state.analysis is not None:
            state.analysis.model.make_liveness_snapshot()

    def initialize_all_function_arguments(
        self,
        state: "ReachingDefinitionsState",
        func_addr: int,
        ex_loc: ExternalCodeLocation,
        cc: SimCC | None,
        prototype: SimTypeFunction | None,
    ) -> None:
        """
        This method handles the setup for _all_ arguments of a function.

        The default implementation uses the calling convention to extract the argument locations, associates them with
        the type, and passes them to the logic for one argument.

        You probably don't need to override this
        """
        if cc is not None and prototype is not None:
            # Type inference for zip is broken in PyCharm 2023.* currently, so we help out manually
            loc: SimFunctionArgument
            ty: SimType
            for loc, ty in zip(cc.arg_locs(prototype), prototype.args):
                for arg in loc.get_footprint():
                    self.initialize_one_function_argument(state, func_addr, ex_loc, arg, ty)

    def initialize_one_function_argument(
        self,
        state: "ReachingDefinitionsState",
        func_addr: int,
        ex_loc: ExternalCodeLocation,
        argument_location: SimFunctionArgument,
        argument_type: SimType | None = None,
    ) -> None:
        """
        This method handles the setup for _one_ argument of a function.
        This is the main method to override for custom initialization logic.

        The default implementation initializes only the argument location itself, but the signature allows
        this to support extra logic based on the _type_ of the argument as well.

        For example if the argument is a pointer to something,
        the default implementation would only set up the register with the value TOP.

        A custom implementation could instead dedicate some memory somewhere (e.g. on the heap), setup whatever object
        is being pointed to, and then put the actual pointer to this inside the register
        """
        _ = argument_type
        if isinstance(argument_location, SimRegArg):
            self._initialize_function_argument_register(state, func_addr, ex_loc, argument_location)
        elif isinstance(argument_location, SimStackArg):
            self._initialize_function_argument_stack(state, func_addr, ex_loc, argument_location)
        else:
            raise TypeError("Unsupported parameter type %s." % type(argument_location).__name__)

    def initialize_stack_pointer(
        self, state: "ReachingDefinitionsState", _func_addr: int, ex_loc: ExternalCodeLocation
    ) -> None:
        # initialize stack pointer
        sp_atom = Register(self.arch.sp_offset, self.arch.bytes)
        sp_def = Definition(sp_atom, ex_loc, tags={InitialValueTag()})
        sp = state.annotate_with_def(state._initial_stack_pointer(), sp_def)
        state.registers.store(self.arch.sp_offset, sp)

    def initialize_architectural_state(
        self,
        state: "ReachingDefinitionsState",
        func_addr: int,
        ex_loc: ExternalCodeLocation,
        rtoc_value: int | None = None,
    ) -> None:
        """
        Some architectures require initialization that is specific to that architecture.

        Override this if you need to add support for an architecture that requires this, and isn't covered yet
        """
        if self.arch.name.startswith("PPC64"):
            if rtoc_value is None:
                raise TypeError("rtoc_value must be provided on PPC64.")
            offset, size = self.arch.registers["rtoc"]
            rtoc_atom = Register(offset, size)
            rtoc_def = Definition(rtoc_atom, ex_loc, tags={InitialValueTag()})
            state.all_definitions.add(rtoc_def)
            if state.analysis is not None:
                state.analysis.model.add_def(rtoc_def)
            rtoc = state.annotate_with_def(claripy.BVV(rtoc_value, self.arch.bits), rtoc_def)
            state.registers.store(offset, rtoc)
        elif self.arch.name.startswith("MIPS64"):
            offset, size = self.arch.registers["t9"]
            t9_atom = Register(offset, size)
            t9_def = Definition(t9_atom, ex_loc, tags={InitialValueTag()})
            state.all_definitions.add(t9_def)
            if state.analysis is not None:
                state.analysis.model.add_def(t9_def)
            t9 = state.annotate_with_def(claripy.BVV(func_addr, self.arch.bits), t9_def)
            state.registers.store(offset, t9)
        elif self.arch.name.startswith("MIPS"):
            if func_addr is None:
                l.warning("func_addr must not be None to initialize a function in mips")
            t9_offset = self.arch.registers["t9"][0]
            t9_atom = Register(t9_offset, self.arch.bytes)
            t9_def = Definition(t9_atom, ex_loc, tags={InitialValueTag()})
            state.all_definitions.add(t9_def)
            if state.analysis is not None:
                state.analysis.model.add_def(t9_def)
            t9 = state.annotate_with_def(claripy.BVV(func_addr, self.arch.bits), t9_def)
            state.registers.store(t9_offset, t9)

        # project-specific initialization
        if self.project is not None:
            if self.project.simos is not None and self.project.simos.function_initial_registers:
                for reg_name, reg_value in self.project.simos.function_initial_registers.items():
                    reg_offset = self.arch.registers[reg_name][0]
                    reg_atom = Register(reg_offset, self.arch.registers[reg_name][1])
                    reg_def = Definition(reg_atom, ex_loc, tags={InitialValueTag()})
                    state.all_definitions.add(reg_def)
                    if state.analysis is not None:
                        state.analysis.model.add_def(reg_def)
                    reg = state.annotate_with_def(claripy.BVV(reg_value, self.arch.registers[reg_name][1]), reg_def)
                    state.registers.store(reg_offset, reg)

    def _initialize_function_argument_register(
        self,
        state: "ReachingDefinitionsState",
        func_addr: int,
        ex_loc: ExternalCodeLocation,
        arg: SimRegArg,
        value: claripy.ast.Base | None = None,
    ):
        # FIXME: implement reg_offset handling in SimRegArg
        reg_offset = self.arch.registers[arg.reg_name][0]
        reg_atom = Register(reg_offset, self.arch.bytes)
        reg_def = Definition(reg_atom, ex_loc, tags={ParameterTag(function=func_addr)})
        state.all_definitions.add(reg_def)
        if state.analysis is not None:
            state.analysis.model.add_def(reg_def)
        if value is None:
            value = state.top(self.arch.bits)
        reg = state.annotate_with_def(value, reg_def)
        state.registers.store(reg_offset, reg)

    def _initialize_function_argument_stack(
        self, state: "ReachingDefinitionsState", func_addr: int, ex_loc: ExternalCodeLocation, arg: SimStackArg
    ):
        ml_atom = MemoryLocation(SpOffset(self.arch.bits, arg.stack_offset), arg.size)
        ml_def = Definition(ml_atom, ex_loc, tags={ParameterTag(function=func_addr)})
        state.all_definitions.add(ml_def)
        if state.analysis is not None:
            state.analysis.model.add_def(ml_def)
        ml = state.annotate_with_def(state.top(self.arch.bits), ml_def)
        stack_address = state.get_stack_address(state.stack_address(arg.stack_offset))
        state.stack.store(stack_address, ml, endness=self.arch.memory_endness)

    @staticmethod
    def _generate_call_string(subject: Subject, current_address: int) -> tuple[int, ...] | None:
        if isinstance(subject.content, Function):
            return (subject.content.addr,)
        elif isinstance(subject.content, CallTrace):
            if any(current_address == x.caller_func_addr for x in subject.content.callsites):
                callsites = iter(reversed([x.caller_func_addr for x in subject.content.callsites]))
                for call_addr in callsites:
                    if current_address == call_addr:
                        break
                return tuple(callsites)
            else:
                return tuple(x.caller_func_addr for x in subject.content.callsites)
        else:
            l.warning("Subject with unknown content-type")
            return None
