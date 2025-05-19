"""icicle.py: An angr engine that uses Icicle to execute code."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

import claripy
import pypcode
from archinfo import Arch, Endness

from angr.engines.failure import SimEngineFailure
from angr.engines.hook import HooksMixin
from angr.engines.successors import SuccessorsEngine
from angr.engines.syscall import SimEngineSyscall
from angr.rustylib.icicle import Icicle, VmExit, ExceptionCode
from angr.sim_state import SimState

log = logging.getLogger(__name__)


PROCESSORS_DIR = os.path.join(os.path.dirname(pypcode.__file__), "processors")


@dataclass
class IcicleStateTranslationData:
    """
    Represents the saved information needed to convert an Icicle state back
    to an angr state.
    """

    base_state: SimState
    registers: set[str]
    writable_pages: set[int]


class IcicleEngine(SuccessorsEngine):
    """
    An angr engine that uses Icicle to execute concrete states. The purpose of
    this implementation is to provide a high-performance concrete execution
    engine in angr. While historically, angr has focused on symbolic execution,
    better support for concrete execution enables new use cases such as fuzzing
    in angr. This is ideal for testing bespoke binary targets, such as
    microcontroller firmware, which may be difficult to correctly harness for
    use with traditional fuzzing engines.

    This class is the base class for the Icicle engine. It implements execution
    by creating an Icicle instance, copying the state from angr to Icicle, and then
    running the Icicle instance. The results are then copied back to the angr
    state. It is likely the case that this can be improved by re-using the Icicle
    instance across multiple runs and only copying the state when necessary.

    For a more complete implementation, use the UberIcicleEngine class, which
    intends to provide a more complete set of features, such as hooks and syscalls.
    """

    @staticmethod
    def __make_icicle_arch(arch: Arch) -> str | None:
        """
        Convert an angr architecture to an Icicle architecture. Not particularly
        accurate, just a set of heuristics to get the right architecture. When
        adding a new architecture, this function may need to be updated.
        """
        if arch.linux_name == "arm":
            return "armv7a" if arch.memory_endness == Endness.LE else "armeb"
        return arch.linux_name

    @staticmethod
    def __is_arm(icicle_arch: str) -> bool:
        """
        Check if the architecture is arm based on the address.
        """
        return icicle_arch.startswith(("arm", "thumb"))

    @staticmethod
    def __is_thumb(icicle_arch: str, addr: int) -> bool:
        """
        Check if the architecture is thumb based on the address.
        """
        return IcicleEngine.__is_arm(icicle_arch) and addr & 1 == 1

    @staticmethod
    def __get_pages(state: SimState) -> set[int]:
        """
        Unfortunately, the memory model doesn't have a way to get all pages.
        Instead, we can get all of the backers from the loader, then all of the
        pages from the PagedMemoryMixin and then do some math.
        """
        pages = set()
        page_size = state.memory.page_size

        # pages from loader segments
        proj = state.project
        if proj is not None:
            for addr, backer in proj.loader.memory.backers():
                start = addr // page_size
                end = (addr + len(backer) - 1) // page_size
                pages.update(range(start, end + 1))

        # pages from the memory model
        pages.update(state.memory._pages)

        return pages

    @staticmethod
    def __convert_angr_state_to_icicle(state: SimState) -> tuple[Icicle, IcicleStateTranslationData]:
        icicle_arch = IcicleEngine.__make_icicle_arch(state.arch)
        if icicle_arch is None:
            raise ValueError("Unsupported architecture")

        proj = state.project
        if proj is None:
            raise ValueError("IcicleEngine requires a project to be set")

        emu = Icicle(icicle_arch, PROCESSORS_DIR)

        copied_registers = set()

        # To create a state in Icicle, we need to do the following:
        # 1. Copy the register values
        for register in state.arch.register_list:
            register = register.vex_name.lower() if register.vex_name is not None else register.name
            try:
                emu.reg_write(register, state.solver.eval(state.registers.load(register), cast_to=int))
                copied_registers.add(register)
            except KeyError:
                log.debug("Register %s not found in icicle", register)

        # Unset the thumb bit if necessary
        if IcicleEngine.__is_thumb(icicle_arch, state.addr):
            emu.pc = state.addr & ~1
            emu.isa_mode = 1
        elif "arm" in icicle_arch:  # Hack to work around us calling it r15t
            emu.pc = state.addr

        # Special case for x86 gs register
        if state.arch.name == "X86":
            emu.reg_write("GS_OFFSET", state.registers.load("gs").concrete_value << 16)

        # 2. Copy the memory contents

        mapped_pages = IcicleEngine.__get_pages(state)
        writable_pages = set()
        for page_num in mapped_pages:
            addr = page_num * state.memory.page_size
            size = state.memory.page_size
            perm_bits = state.memory.permissions(addr).concrete_value
            emu.mem_map(addr, size, perm_bits)
            memory = state.memory.concrete_load(addr, size)
            emu.mem_write(addr, memory)

            if perm_bits & 2:
                writable_pages.add(page_num)

        # Add breakpoints for simprocedures
        for addr in proj._sim_procedures:
            emu.add_breakpoint(addr)

        translation_data = IcicleStateTranslationData(
            base_state=state,
            registers=copied_registers,
            writable_pages=writable_pages,
        )

        return (emu, translation_data)

    @staticmethod
    def __convert_icicle_state_to_angr(emu: Icicle, translation_data: IcicleStateTranslationData) -> SimState:
        state = translation_data.base_state.copy()

        # 1. Copy the register values
        for register in translation_data.registers:
            state.registers.store(register, emu.reg_read(register))

        if IcicleEngine.__is_arm(emu.architecture):  # Hack to work around us calling it r15t
            state.registers.store("pc", (emu.pc | 1) if emu.isa_mode == 1 else emu.pc)

        # 2. Copy the memory contents
        for page_num in translation_data.writable_pages:
            addr = page_num * state.memory.page_size
            state.memory.store(addr, emu.mem_read(addr, state.memory.page_size))

        return state

    def process_successors(self, successors, *, num_inst=0, **kwargs):
        if len(kwargs) > 0:
            log.warning("IcicleEngine.process_successors received unknown kwargs: %s", kwargs)

        emu, translation_data = self.__convert_angr_state_to_icicle(self.state)

        if num_inst > 0:
            emu.icount_limit = num_inst

        status = emu.run()  # pylint: ignore=assignment-from-no-return (pylint bug)
        exc = emu.exception_code

        if status == VmExit.UnhandledException:
            if exc in (
                ExceptionCode.ReadUnmapped,
                ExceptionCode.ReadPerm,
                ExceptionCode.WriteUnmapped,
                ExceptionCode.WritePerm,
                ExceptionCode.ExecViolation,
            ):
                jumpkind = "Ijk_SigSEGV"
            elif exc == ExceptionCode.Syscall:
                jumpkind = "Ijk_Syscall"
            elif exc == ExceptionCode.Halt:
                jumpkind = "Ijk_Exit"
            elif exc == ExceptionCode.InvalidInstruction:
                jumpkind = "Ijk_NoDecode"
            else:
                jumpkind = "Ijk_EmFail"
        else:
            jumpkind = "Ijk_Boring"

        successor_state = IcicleEngine.__convert_icicle_state_to_angr(emu, translation_data)
        successors.add_successor(successor_state, successor_state.ip, claripy.true(), jumpkind, add_guard=False)

        successors.processed = True


class UberIcicleEngine(SimEngineFailure, SimEngineSyscall, HooksMixin, IcicleEngine):
    """
    An extension of the IcicleEngine that uses mixins to add support for
    syscalls and hooks. Most users will prefer to use this engine instead of the
    IcicleEngine directly.
    """
