"""icicle.py: An angr engine that uses Icicle to execute code."""

from __future__ import annotations

import logging
import os
import typing
from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

import claripy
import pypcode
from archinfo import Arch, ArchARMCortexM, ArchPcode, Endness
from typing_extensions import override

from angr.errors import SimMemoryError
from angr.engines.failure import SimEngineFailure
from angr.engines.hook import HooksMixin
from angr.engines.successors import SimSuccessors, SuccessorsEngine
from angr.engines.syscall import SimEngineSyscall
from angr.rustylib.icicle import ExceptionCode, Icicle, VmExit
from angr.sim_state import SimState
from angr.state_plugins.edge_hitmap import SimStateEdgeHitmap
from angr.state_plugins.icicle import SimStateIcicle
from angr.state_plugins.inspect import BP_AFTER

log = logging.getLogger(__name__)


HeavyConcreteState = SimState[int, int]


PROCESSORS_DIR = os.path.join(os.path.dirname(pypcode.__file__), "processors")


def _syscall_jumpkind(arch_name: str, emu) -> str:
    """Map icicle's generic Syscall exception to the arch-specific VEX jumpkind."""
    if arch_name in ("AMD64", "X86"):
        try:
            insn = emu.mem_read(emu.pc, 2)
        except RuntimeError:
            insn = b""
        if insn == b"\xcd\x80":
            return "Ijk_Sys_int128"
        if insn == b"\x0f\x05":
            return "Ijk_Sys_syscall"
    return "Ijk_Sys_syscall"


@dataclass
class IcicleStateTranslationData:
    """
    Represents the saved information needed to convert an Icicle state back
    to an angr state.
    """

    base_state: HeavyConcreteState
    registers: set[str]
    mapped_pages: set[int]
    writable_pages: set[int]
    explicit_page_metadata: dict[int, int | None]
    initial_cpu_icount: int
    icicle_arch: str


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
    by creating an Icicle instance, copying the state from angr to Icicle, and
    then running the Icicle instance. The results are then copied back to the
    angr state. The Icicle instance is cached on the engine and reused across
    runs: the first call takes a snapshot of the fresh VM, and subsequent calls
    either continue with the cached emu (same-run successors) or restore the
    snapshot and delta-sync the input state (branches).

    For a more complete implementation, use the UberIcicleEngine class, which
    intends to provide a more complete set of features, such as hooks and syscalls.

    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cached_emu: Icicle | None = None
        self._base_translation_data: IcicleStateTranslationData | None = None
        self._run_counter: int = 0

    @staticmethod
    def __make_icicle_arch(arch: Arch) -> str | None:
        """
        Convert an angr architecture to an Icicle architecture. Not particularly
        accurate, just a set of heuristics to get the right architecture. When
        adding a new architecture, this function may need to be updated.
        """
        if isinstance(arch, ArchARMCortexM) or (isinstance(arch, ArchPcode) and arch.pcode_arch == "ARM:LE:32:Cortex"):
            return "armv7m"
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
    def __is_cortex_m(angr_arch: Arch, icicle_arch: str) -> bool:
        """
        Check if the architecture is cortex-m based on the address.
        """
        return isinstance(angr_arch, ArchARMCortexM) or icicle_arch == "armv7m"

    @staticmethod
    def __is_thumb(angr_arch: Arch, icicle_arch: str, addr: int) -> bool:
        """
        Check if the architecture is thumb based on the address.
        """
        return IcicleEngine.__is_cortex_m(angr_arch, icicle_arch) or (
            IcicleEngine.__is_arm(icicle_arch) and addr & 1 == 1
        )

    @staticmethod
    def __get_pages(state: HeavyConcreteState) -> set[int]:
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

        # The paged memory model stores explicit page overrides in _pages.
        # A None entry means the page was explicitly unmapped and must shadow
        # loader backers.
        for page_num, page in state.memory._pages.items():
            if page is None:
                pages.discard(page_num)
            else:
                pages.add(page_num)

        return pages

    @staticmethod
    def __get_explicit_page_metadata(state: HeavyConcreteState) -> dict[int, int | None]:
        """
        Return explicit page overrides from the paged memory model.
        The key is page number. Value is permission bits, or None when the page
        is explicitly unmapped.
        """
        metadata = {}
        page_size = state.memory.page_size
        for page_num, page in state.memory._pages.items():
            if page is None:
                metadata[page_num] = None
            else:
                metadata[page_num] = state.memory.permissions(page_num * page_size).concrete_value
        return metadata

    @staticmethod
    def __sync_registers(emu: Icicle, state: HeavyConcreteState, register_names: Iterable[str]) -> set[str]:
        """Copy each named register from `state` into `emu`, plus the x86/AMD64 TLS
        segment base (which icicle exposes under a different name than angr).
        Returns the subset of `register_names` that succeeded — registers icicle
        doesn't recognize are skipped (logged at DEBUG).
        """
        copied = set()
        for name in register_names:
            try:
                emu.reg_write(name, state.solver.eval(state.registers.load(name), cast_to=int))
                copied.add(name)
            except KeyError:
                log.debug("Register %s not found in icicle", name)
        # angr stores the TLS base in the segment-selector register (`fs` /
        # `gs`); icicle exposes the base directly via `FS_OFFSET` /
        # `GS_OFFSET`. SimOS guarantees a valid base is always set.
        if state.arch.name == "AMD64":
            emu.reg_write("FS_OFFSET", state.registers.load("fs").concrete_value)
        elif state.arch.name == "X86":
            emu.reg_write("GS_OFFSET", state.registers.load("gs").concrete_value << 16)
        return copied

    @staticmethod
    def __write_page(emu: Icicle, state: HeavyConcreteState, page_num: int) -> None:
        """Copy `state`'s content at `page_num` into `emu`, resolving any symbolic
        bytes through the solver.
        """
        page_size = state.memory.page_size
        addr = page_num * page_size
        memory, bitmap = state.memory.concrete_load(addr, page_size, with_bitmap=True)
        if any(bitmap):
            memory = state.solver.eval(state.memory.load(addr, page_size), cast_to=bytes)
        emu.mem_write(addr, memory)

    @staticmethod
    def __sync_edge_hitmap(emu: Icicle, state: HeavyConcreteState) -> None:
        """Copy state's edge_hitmap into emu, if the plugin is present."""
        if state.has_plugin("edge_hitmap"):
            hitmap_plugin = cast(SimStateEdgeHitmap, state.get_plugin("edge_hitmap"))
            if hitmap_plugin.edge_hitmap is not None:
                emu.edge_hitmap = hitmap_plugin.edge_hitmap

    @staticmethod
    def __build_emu_for(state: HeavyConcreteState) -> tuple[Icicle, IcicleStateTranslationData]:
        """Construct a fresh `Icicle` VM and sync `state` onto it from scratch."""
        icicle_arch = IcicleEngine.__make_icicle_arch(state.arch)
        if icicle_arch is None:
            raise ValueError("Unsupported architecture")
        if state.project is None:
            raise ValueError("IcicleEngine requires a project to be set")

        emu = Icicle(icicle_arch, PROCESSORS_DIR, True, True)
        translation_data = IcicleEngine.__sync_state_to_emu(emu, state, None, icicle_arch)
        return emu, translation_data

    @staticmethod
    def __convert_icicle_state_to_angr(
        emu: Icicle, translation_data: IcicleStateTranslationData, status: VmExit
    ) -> HeavyConcreteState:
        state = translation_data.base_state.copy()

        # 1. Copy the register values
        for register in translation_data.registers:
            state.registers.store(register, emu.reg_read(register))

        if IcicleEngine.__is_arm(emu.architecture):  # Hack to work around us calling it r15t
            state.registers.store("pc", (emu.pc | 1) if emu.isa_mode == 1 else emu.pc)

        # Restore TLS base from FS/GS_OFFSET (register copy clobbers it).
        arch_name = translation_data.base_state.arch.name
        if arch_name == "AMD64":
            state.regs.fs = emu.reg_read("FS_OFFSET")
        elif arch_name == "X86":
            state.regs.gs = emu.reg_read("GS_OFFSET") >> 16

        # 2. Copy only memory pages that were actually modified during execution
        modified_addrs = set(emu.modified_pages)
        page_size = state.memory.page_size
        for page_num in translation_data.writable_pages:
            addr = page_num * page_size
            if addr in modified_addrs:
                state.memory.store(addr, emu.mem_read(addr, page_size))

        # 3. Set history
        # 3.1 history.jumpkind
        exc = emu.exception_code
        if status == VmExit.UnhandledException:
            if exc in (
                ExceptionCode.ReadUnmapped,
                ExceptionCode.ReadPerm,
                ExceptionCode.WriteUnmapped,
                ExceptionCode.WritePerm,
                ExceptionCode.ExecViolation,
            ):
                state.history.jumpkind = "Ijk_SigSEGV"
            elif exc == ExceptionCode.Syscall:
                state.history.jumpkind = _syscall_jumpkind(arch_name, emu)
                # Icicle stops at the syscall instruction (unlike VEX
                # which computes the next IP during lifting), so we
                # advance IP using archinfo's instruction_alignment.
                # x86 (variable-length): alignment is 1, but all syscall variants are 2 bytes.
                syscall_len = translation_data.base_state.arch.instruction_alignment
                if syscall_len is None or syscall_len < 2:
                    syscall_len = 2
                state.regs.ip = emu.pc + syscall_len
            elif exc == ExceptionCode.Halt:
                state.history.jumpkind = "Ijk_Exit"
            elif exc == ExceptionCode.InvalidInstruction:
                state.history.jumpkind = "Ijk_NoDecode"
            else:
                state.history.jumpkind = "Ijk_EmFail"
        else:
            state.history.jumpkind = "Ijk_Boring"

        # 3.2 history.recent_bbl_addrs
        # Skip the last block, because it will be added by Successors
        state.history.recent_bbl_addrs.extend([b[0] for b in emu.recent_blocks][:-1])

        # 3.3. Set history.recent_instruction_count
        state.history.recent_instruction_count = emu.cpu_icount - translation_data.initial_cpu_icount

        # 3.4. Set edge hitmap in dedicated plugin if present
        if state.has_plugin("edge_hitmap"):
            hitmap_plugin = cast(SimStateEdgeHitmap, state.get_plugin("edge_hitmap"))
            hitmap_plugin.edge_hitmap = emu.edge_hitmap

        return state

    @staticmethod
    def __sync_state_to_emu(
        emu: Icicle,
        state: HeavyConcreteState,
        base: IcicleStateTranslationData | None,
        icicle_arch: str | None = None,
    ) -> IcicleStateTranslationData:
        """Sync `state` onto `emu` such that the VM matches the angr state.

        `base` represents the VM's prior translation state. Pass `None` to
        treat the VM as freshly built (full init); pass a translation_data
        to apply a delta against that baseline (e.g. after `restore_snapshot`).

        `icicle_arch` is required when `base is None`; otherwise it's read
        from `base`.
        """
        if base is None:
            assert icicle_arch is not None
            register_names: Iterable[str] = (
                r.vex_name.lower() if r.vex_name is not None else r.name for r in state.arch.register_list
            )
        else:
            icicle_arch = base.icicle_arch
            register_names = base.registers

        copied_registers = IcicleEngine.__sync_registers(emu, state, register_names)

        if IcicleEngine.__is_thumb(state.arch, icicle_arch, state.addr):
            emu.pc = state.addr & ~1
            emu.isa_mode = 1
        elif "arm" in icicle_arch:  # Hack to work around us calling it r15t
            emu.pc = state.addr

        # Sync mapping/permission deltas.
        page_size = state.memory.page_size
        explicit_page_metadata = IcicleEngine.__get_explicit_page_metadata(state)
        if base is None:
            # Empty baseline: every mapped page is "newly mapped".
            candidate_pages = IcicleEngine.__get_pages(state)
            mapped_pages: set[int] = set()
            writable_pages: set[int] = set()
            base_state_pages: dict[int, typing.Any] = {}
        else:
            base_explicit = base.explicit_page_metadata
            candidate_pages = set(base_explicit).symmetric_difference(explicit_page_metadata)
            for page_num in set(base_explicit).intersection(explicit_page_metadata):
                if base_explicit[page_num] != explicit_page_metadata[page_num]:
                    candidate_pages.add(page_num)
            mapped_pages = set(base.mapped_pages)
            writable_pages = set(base.writable_pages)
            base_state_pages = base.base_state.memory._pages

        for page_num in candidate_pages:
            addr = page_num * page_size
            old_mapped = page_num in mapped_pages

            try:
                perm_bits = state.memory.permissions(addr).concrete_value
                new_mapped = True
            except SimMemoryError:
                perm_bits = 0
                new_mapped = False

            if old_mapped and not new_mapped:
                emu.mem_unmap(addr, page_size)
                mapped_pages.remove(page_num)
                writable_pages.discard(page_num)
                continue

            if not old_mapped and new_mapped:
                emu.mem_map(addr, page_size, perm_bits)
                mapped_pages.add(page_num)
                if not perm_bits & 2:
                    # R-only pages won't be visited by the writable-page loop
                    # below, so this is the only place to seed their content.
                    IcicleEngine.__write_page(emu, state, page_num)
            elif old_mapped and new_mapped and base is not None:
                base_perm_bits = base.base_state.memory.permissions(addr).concrete_value
                if base_perm_bits != perm_bits:
                    emu.mem_protect(addr, page_size, perm_bits)

            if perm_bits & 2:
                writable_pages.add(page_num)
            else:
                writable_pages.discard(page_num)

        # Writable pages: copy those whose content differs from the baseline.
        # For full init (base is None), `base_state_pages` is empty so the
        # CoW check unconditionally writes every writable page.
        for page_num in writable_pages:
            if state.memory._pages.get(page_num) is base_state_pages.get(page_num):
                continue
            IcicleEngine.__write_page(emu, state, page_num)

        # restore_snapshot zeroes the hitmap; full init starts with no
        # hitmap. Either way we (re-)copy.
        IcicleEngine.__sync_edge_hitmap(emu, state)

        return IcicleStateTranslationData(
            base_state=state,
            registers=copied_registers if base is None else base.registers,
            mapped_pages=mapped_pages,
            writable_pages=writable_pages,
            explicit_page_metadata=explicit_page_metadata,
            initial_cpu_icount=emu.cpu_icount,
            icicle_arch=icicle_arch,
        )

    def has_snapshot(self) -> bool:
        """Check if a snapshot is available for fast restore."""
        return self._cached_emu is not None and self._cached_emu.has_snapshot()

    @staticmethod
    def _install_dirty_page_tracking(state: HeavyConcreteState) -> None:
        """Register a SimInspect callback on memory writes to record which
        pages are dirtied by hooks or syscall handlers between icicle runs.
        """
        page_size = state.memory.page_size

        def _on_mem_write(state):
            plugin = state.get_plugin("icicle") if state.has_plugin("icicle") else None
            if not isinstance(plugin, SimStateIcicle):
                return
            solver = state.solver
            addr = state.inspect.mem_write_address
            if addr is None or solver.symbolic(addr):
                return
            addr = solver.eval(addr, cast_to=int)
            # length is often None because `state.memory.store(addr, bvv)`
            # is called without an explicit size — fall back to the value's
            # bit width.
            length = state.inspect.mem_write_length
            if length is None:
                expr = state.inspect.mem_write_expr
                if expr is None:
                    return
                length = expr.size() // 8
            elif solver.symbolic(length):
                return
            else:
                length = solver.eval(length, cast_to=int)
            if length <= 0:
                return
            start_page = addr // page_size
            end_page = (addr + length - 1) // page_size
            for p in range(start_page, end_page + 1):
                plugin.dirty_pages.add(p)

        state.inspect.b("mem_write", when=BP_AFTER, action=_on_mem_write)

    @staticmethod
    def __sync_continuation(
        emu: Icicle,
        state: HeavyConcreteState,
        translation_data: IcicleStateTranslationData,
        changed_pages: list[int],
    ) -> IcicleStateTranslationData:
        """Sync only registers and changed pages to icicle (no snapshot restore)."""
        icicle_arch = translation_data.icicle_arch

        IcicleEngine.__sync_registers(emu, state, translation_data.registers)

        # Explicitly set PC (the register copy may have written it to a sub-register).
        if IcicleEngine.__is_thumb(state.arch, icicle_arch, state.addr):
            emu.pc = state.addr & ~1
            emu.isa_mode = 1
        else:
            emu.pc = state.addr

        page_size = state.memory.page_size
        mapped_pages = set(translation_data.mapped_pages)
        writable_pages = set(translation_data.writable_pages)

        for page_num in changed_pages:
            if page_num not in mapped_pages:
                addr = page_num * page_size
                try:
                    perm_bits = state.memory.permissions(addr).concrete_value
                except SimMemoryError:
                    continue
                emu.mem_map(addr, page_size, perm_bits)
                mapped_pages.add(page_num)
                if perm_bits & 2:
                    writable_pages.add(page_num)
            IcicleEngine.__write_page(emu, state, page_num)

        return IcicleStateTranslationData(
            base_state=state,
            registers=translation_data.registers,
            mapped_pages=mapped_pages,
            writable_pages=writable_pages,
            explicit_page_metadata=IcicleEngine.__get_explicit_page_metadata(state),
            initial_cpu_icount=emu.cpu_icount,
            icicle_arch=icicle_arch,
        )

    @override
    def process_successors(self, successors: SimSuccessors, *, num_inst: int | None = None, **kwargs: typing.Any):
        extra_stop_points_arg = kwargs.pop("extra_stop_points", None)
        extra_stop_points: set[int] | None = None
        if extra_stop_points_arg is not None:
            extra_stop_points = set(typing.cast(Iterable[int], extra_stop_points_arg))

        if len(kwargs) > 0:
            log.warning("IcicleEngine.process_successors received unknown kwargs: %s", kwargs)

        state = typing.cast(HeavyConcreteState, self.state)

        result = self._run_icicle(state, num_inst=num_inst, extra_stop_points=extra_stop_points)
        successors.add_successor(
            result,
            result.ip,
            claripy.true(),
            result.history.jumpkind,
            add_guard=False,
        )
        successors.processed = True

    def _run_icicle(
        self,
        state: HeavyConcreteState,
        num_inst: int | None = None,
        extra_stop_points: set[int] | None = None,
    ) -> HeavyConcreteState:
        # Check for continuation via state plugin (registered as a default).
        icicle_plugin = state.get_plugin("icicle")
        if not isinstance(icicle_plugin, SimStateIcicle):
            raise TypeError("SimStateIcicle plugin missing — is it registered as a default?")

        if (
            icicle_plugin.engine_id == id(self)
            and icicle_plugin.run_id == self._run_counter
            and self._cached_emu is not None
            and icicle_plugin.translation_data is not None
        ):
            # Continuation: sync registers + dirty pages (no snapshot restore).
            # dirty_pages includes both icicle-written pages (from emu.modified_pages)
            # and angr-written pages (from the store tracking hook).
            pages_to_sync = set(icicle_plugin.dirty_pages)
            # Pick up pages newly mapped by syscall handlers (e.g. mmap).
            for page_num, page in state.memory._pages.items():
                if page is not None and page_num not in icicle_plugin.translation_data.mapped_pages:
                    pages_to_sync.add(page_num)
            translation_data = self.__sync_continuation(
                self._cached_emu, state, icicle_plugin.translation_data, list(pages_to_sync)
            )
            # Reset the path tracer so `emu.recent_blocks` reflects only
            # blocks executed during this run, not cumulative history.
            self._cached_emu.clear_path_tracer()
            emu = self._cached_emu
        elif self._cached_emu is not None:
            # Branched from an earlier run: restore and delta-sync.
            assert self._base_translation_data is not None
            self._cached_emu.restore_snapshot()
            translation_data = self.__sync_state_to_emu(self._cached_emu, state, self._base_translation_data)
            emu = self._cached_emu
        else:
            # First run: build the VM and snapshot it for future branches.
            emu, translation_data = self.__build_emu_for(state)
            emu.save_snapshot()
            self._cached_emu = emu
            self._base_translation_data = translation_data

        # Sync simprocedure breakpoints. Simprocs can be registered
        # dynamically between runs (e.g. SimProcedure.call() makes a new
        # continuation extern), so full-init's breakpoint set is not
        # authoritative on subsequent calls. add_breakpoint is idempotent.
        proj = state.project
        if proj is not None:
            for addr in proj._sim_procedures:
                emu.add_breakpoint(addr)

        # Set extra stop points (cleaned up after the run).
        added_breakpoints = []
        is_arm = IcicleEngine.__is_arm(translation_data.icicle_arch)
        if extra_stop_points is not None:
            for addr in extra_stop_points:
                if is_arm:
                    addr = addr & ~1  # Clear thumb bit
                if emu.pc == addr:
                    continue
                bp_page = addr // state.memory.page_size
                if bp_page not in translation_data.mapped_pages:
                    log.debug("Breakpoint at %#x skipped: page not mapped.", addr)
                    continue
                if emu.add_breakpoint(addr):
                    added_breakpoints.append(addr)

        # icount_limit is absolute — offset by current cpu_icount.
        if num_inst is not None and num_inst > 0:
            emu.icount_limit = emu.cpu_icount + num_inst

        # Reset dirty page tracking so only this run's writes are recorded.
        page_size = state.memory.page_size
        emu.reset_page_modification_tracking([page_num * page_size for page_num in translation_data.writable_pages])

        # Run it
        status = emu.run()

        # Clean up extra stop points
        for addr in added_breakpoints:
            emu.remove_breakpoint(addr)

        result = IcicleEngine.__convert_icicle_state_to_angr(emu, translation_data, status)

        # Update the plugin for continuation detection on the next call.
        # Seed dirty_pages with pages icicle wrote; the SimInspect callback
        # will add any pages that angr hooks/syscalls modify before the next
        # engine call.
        page_size = state.memory.page_size
        self._run_counter += 1
        result_plugin = cast(SimStateIcicle, result.get_plugin("icicle"))
        result_plugin.engine_id = id(self)
        result_plugin.run_id = self._run_counter
        result_plugin.translation_data = translation_data
        result_plugin.dirty_pages = {addr // page_size for addr in emu.modified_pages}
        self._install_dirty_page_tracking(result)

        return result


class UberIcicleEngine(SimEngineFailure, SimEngineSyscall, HooksMixin, IcicleEngine):
    """
    An extension of the IcicleEngine that uses mixins to add support for
    syscalls and hooks. Most users will prefer to use this engine instead of the
    IcicleEngine directly.
    """
