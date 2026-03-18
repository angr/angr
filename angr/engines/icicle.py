"""icicle.py: An angr engine that uses Icicle to execute code."""

from __future__ import annotations

import logging
import os
from contextlib import suppress
from dataclasses import dataclass
from typing import cast

import pypcode
from archinfo import Arch, ArchARMCortexM, ArchPcode, Endness
from typing_extensions import override

from angr.errors import SimMemoryError
from angr.engines.concrete import ConcreteEngine, HeavyConcreteState
from angr.engines.failure import SimEngineFailure
from angr.engines.hook import HooksMixin
from angr.engines.syscall import SimEngineSyscall
from angr.rustylib.icicle import ExceptionCode, Icicle, VmExit
from angr.state_plugins.edge_hitmap import SimStateEdgeHitmap

log = logging.getLogger(__name__)


PROCESSORS_DIR = os.path.join(os.path.dirname(pypcode.__file__), "processors")

# x86/x86-64 legacy instruction prefix bytes (appear before REX + opcode)
_X86_LEGACY_PREFIXES = frozenset({0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3})

# Group 2 segment-override prefixes (only the last one in the prefix area
# is effective; earlier ones are silently overridden by the CPU).
_X86_SEGMENT_PREFIXES = frozenset({0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65})


def _effective_segment_prefix(insn_bytes) -> int | None:
    """Return the last (effective) segment-override prefix, or None."""
    last_seg = None
    for byte in insn_bytes:
        if byte in _X86_SEGMENT_PREFIXES:
            last_seg = byte
        elif byte not in _X86_LEGACY_PREFIXES:
            # REX (0x40-0x4F) or opcode — segment overrides must precede REX,
            # so the last_seg we've seen is the effective one.
            break
    return last_seg


def _is_x86_tls_gap(emu, prefix_byte: int, offset_reg: str) -> bool:
    """Return True if the faulting instruction uses a segment prefix and the base is zero."""
    try:
        if emu.reg_read(offset_reg) != 0:
            return False
    except KeyError:
        return False
    try:
        insn_bytes = emu.mem_read(emu.pc, 15)
    except RuntimeError:
        return False
    return _effective_segment_prefix(insn_bytes) == prefix_byte


def _syscall_insn_len(arch_name: str) -> int:
    """Return the byte length of the syscall instruction for the given arch."""
    # x86/x86_64: syscall (0F 05), int 0x80 (CD 80), sysenter (0F 34) are all 2 bytes.
    if arch_name in ("AMD64", "X86"):
        return 2
    # ARM/Thumb SVC is 4 bytes (ARM) or 2 bytes (Thumb), but the icicle PC
    # already accounts for the instruction, so default to 4 for ARM.
    if arch_name.startswith("ARM") or arch_name.startswith("AARCH"):
        return 4
    # MIPS syscall is 4 bytes
    if arch_name.startswith("MIPS"):
        return 4
    return 4


def _ensure_duplex_stdio(state: HeavyConcreteState) -> None:
    """Replace non-duplex stdio fds with duplex wrappers.

    Concrete code (e.g. glibc) may both read and write any stdio fd.
    angr's default setup uses a unidirectional SimFileDescriptor for
    stderr (fd 2), which crashes when the concrete code reads from it.
    Upgrade any such fds to SimFileDescriptorDuplex so both directions work.
    """
    from angr.storage.file import SimFileDescriptor, SimFileDescriptorDuplex, SimPacketsStream

    posix = state.posix
    for fd_num in (0, 1, 2):
        fd_obj = posix.fd.get(fd_num)
        if fd_obj is None or isinstance(fd_obj, SimFileDescriptorDuplex):
            continue
        if isinstance(fd_obj, SimFileDescriptor):
            orig_file = fd_obj.file
            # Create a companion stream for the missing direction
            if orig_file.write_mode:
                # write-only (e.g. stderr) — add an empty read stream
                read_file = SimPacketsStream(f"{orig_file.ident or orig_file.name}_read", write_mode=False)
                read_file.set_state(state)
                duplex = SimFileDescriptorDuplex(read_file, orig_file)
            else:
                # read-only (e.g. stdin) — add an empty write stream
                write_file = SimPacketsStream(f"{orig_file.ident or orig_file.name}_write", write_mode=True)
                write_file.set_state(state)
                duplex = SimFileDescriptorDuplex(orig_file, write_file)
            duplex.set_state(state)
            posix.fd[fd_num] = duplex


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


def _is_emulation_gap(emu, exc: ExceptionCode, arch_name: str) -> bool:
    """Determine if an unmapped-memory fault is an emulation gap, not a real crash.

    Checks for known patterns where the OS/runtime would have set up memory
    that the emulator left uninitialised.  Currently detects TLS accesses
    through segment registers on x86/x86-64 when the corresponding
    segment-base register is zero.

    The arch→prefix mapping follows Linux TLS conventions (AMD64 uses fs:,
    X86 uses gs:).  Other OS conventions can be added here.
    """
    if exc not in (ExceptionCode.ReadUnmapped, ExceptionCode.WriteUnmapped):
        return False
    if arch_name == "AMD64":
        return _is_x86_tls_gap(emu, 0x64, "FS_OFFSET")
    if arch_name == "X86":
        return _is_x86_tls_gap(emu, 0x65, "GS_OFFSET")
    return False


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


class IcicleEngine(ConcreteEngine):
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
    state. When snapshot mode is enabled, the Icicle instance is reused across
    multiple runs, restoring from a snapshot and only syncing changed state.

    For a more complete implementation, use the UberIcicleEngine class, which
    intends to provide a more complete set of features, such as hooks and syscalls.

    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cached_emu: Icicle | None = None
        self._base_translation_data: IcicleStateTranslationData | None = None
        self._snapshot_mode: bool = False

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
    def __convert_angr_state_to_icicle(state: HeavyConcreteState) -> tuple[Icicle, IcicleStateTranslationData]:
        icicle_arch = IcicleEngine.__make_icicle_arch(state.arch)
        if icicle_arch is None:
            raise ValueError("Unsupported architecture")

        proj = state.project
        if proj is None:
            raise ValueError("IcicleEngine requires a project to be set")

        emu = Icicle(icicle_arch, PROCESSORS_DIR, True, True)

        copied_registers = set()
        explicit_page_metadata = IcicleEngine.__get_explicit_page_metadata(state)

        # To create a state in Icicle, we need to do the following:
        # 1. Copy the register values
        for register in state.arch.register_list:
            register = register.vex_name.lower() if register.vex_name is not None else register.name
            try:
                emu.reg_write(
                    register,
                    state.solver.eval(state.registers.load(register), cast_to=int),
                )
                copied_registers.add(register)
            except KeyError:
                log.debug("Register %s not found in icicle", register)

        # Unset the thumb bit if necessary
        if IcicleEngine.__is_thumb(state.arch, icicle_arch, state.addr):
            emu.pc = state.addr & ~1
            emu.isa_mode = 1
        elif "arm" in icicle_arch:  # Hack to work around us calling it r15t
            emu.pc = state.addr

        # Special case for x86 segment registers used for TLS.
        # Only set segment offsets when the loader actually initialised TLS;
        # otherwise the register holds a placeholder value from archinfo.
        if proj is not None and proj.loader.tls.threads:
            if state.arch.name == "X86":
                emu.reg_write("GS_OFFSET", state.registers.load("gs").concrete_value << 16)
            elif state.arch.name == "AMD64":
                emu.reg_write("FS_OFFSET", state.registers.load("fs").concrete_value)

        # 2. Copy the memory contents

        mapped_pages = IcicleEngine.__get_pages(state)
        writable_pages = set()
        for page_num in mapped_pages:
            addr = page_num * state.memory.page_size
            size = state.memory.page_size
            perm_bits = state.memory.permissions(addr).concrete_value
            emu.mem_map(addr, size, perm_bits)
            memory, bitmap = state.memory.concrete_load(addr, size, with_bitmap=True)
            if any(bitmap):
                # Page has symbolic writes (e.g. stack argv/argc from entry_state).
                # Resolve them through the full memory system so icicle sees
                # the correct concrete values.
                memory = state.solver.eval(state.memory.load(addr, size), cast_to=bytes)
            emu.mem_write(addr, memory)

            if perm_bits & 2:
                writable_pages.add(page_num)

        # Add breakpoints for simprocedures, skipping ifunc resolvers
        # which should run natively in the concrete engine.
        from angr.procedures.linux_loader.sim_loader import IFuncResolver

        for addr, proc in proj._sim_procedures.items():
            if not isinstance(proc, IFuncResolver):
                emu.add_breakpoint(addr)

        translation_data = IcicleStateTranslationData(
            base_state=state,
            registers=copied_registers,
            mapped_pages=mapped_pages,
            writable_pages=writable_pages,
            explicit_page_metadata=explicit_page_metadata,
            initial_cpu_icount=emu.cpu_icount,
            icicle_arch=icicle_arch,
        )

        # 3. Copy edge hitmap
        if state.has_plugin("edge_hitmap"):
            hitmap_plugin = cast(SimStateEdgeHitmap, state.get_plugin("edge_hitmap"))
            if hitmap_plugin.edge_hitmap is not None:
                emu.edge_hitmap = hitmap_plugin.edge_hitmap

        return (emu, translation_data)

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

        # The register copy above clobbers angr's TLS base (fs/gs) with
        # icicle's 16-bit segment selector (0).  Restore from FS/GS_OFFSET.
        arch_name = translation_data.base_state.arch.name
        if arch_name == "AMD64":
            with suppress(KeyError):
                state.regs.fs = emu.reg_read("FS_OFFSET")
        elif arch_name == "X86":
            with suppress(KeyError):
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
            if exc in (ExceptionCode.ReadUnmapped, ExceptionCode.WriteUnmapped) and _is_emulation_gap(
                emu, exc, translation_data.base_state.arch.name
            ):
                state.history.jumpkind = "Ijk_EmFail"
            elif exc in (
                ExceptionCode.ReadUnmapped,
                ExceptionCode.ReadPerm,
                ExceptionCode.WriteUnmapped,
                ExceptionCode.WritePerm,
                ExceptionCode.ExecViolation,
            ):
                state.history.jumpkind = "Ijk_SigSEGV"
            elif exc == ExceptionCode.Syscall:
                state.history.jumpkind = _syscall_jumpkind(arch_name, emu)
                # icicle stops AT the syscall instruction; set IP to the
                # instruction *after* it so that add_successor's syscall
                # categorisation stores the correct return address into
                # ip_at_syscall before rewriting IP to the cle##kernel handler.
                state.regs.ip = emu.pc + _syscall_insn_len(arch_name)
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
    def __sync_angr_state_to_icicle(
        emu: Icicle,
        state: HeavyConcreteState,
        base_translation_data: IcicleStateTranslationData,
    ) -> IcicleStateTranslationData:
        """
        Sync only registers and writable pages from an angr state to an existing
        Icicle VM. This is much faster than a full conversion since it skips VM
        creation, memory mapping, and read-only page copies.
        """
        icicle_arch = base_translation_data.icicle_arch

        # 1. Copy register values
        for register in base_translation_data.registers:
            with suppress(KeyError):
                emu.reg_write(
                    register,
                    state.solver.eval(state.registers.load(register), cast_to=int),
                )

        # Handle thumb/ARM mode
        if IcicleEngine.__is_thumb(state.arch, icicle_arch, state.addr):
            emu.pc = state.addr & ~1
            emu.isa_mode = 1
        elif "arm" in icicle_arch:
            emu.pc = state.addr

        # Special case for x86 segment registers used for TLS.
        # Only set segment offsets when the loader actually initialised TLS;
        # otherwise the register holds a placeholder value from archinfo.
        if state.project is not None and state.project.loader.tls.threads:
            if state.arch.name == "X86":
                emu.reg_write("GS_OFFSET", state.registers.load("gs").concrete_value << 16)
            elif state.arch.name == "AMD64":
                emu.reg_write("FS_OFFSET", state.registers.load("fs").concrete_value)

        # 2. Sync only mapping/permission deltas from explicit page changes.
        page_size = state.memory.page_size
        explicit_page_metadata = IcicleEngine.__get_explicit_page_metadata(state)
        base_explicit_page_metadata = base_translation_data.explicit_page_metadata

        candidate_pages = set(base_explicit_page_metadata).symmetric_difference(explicit_page_metadata)
        for page_num in set(base_explicit_page_metadata).intersection(explicit_page_metadata):
            if base_explicit_page_metadata[page_num] != explicit_page_metadata[page_num]:
                candidate_pages.add(page_num)

        mapped_pages = set(base_translation_data.mapped_pages)
        writable_pages = set()
        writable_pages.update(base_translation_data.writable_pages)

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
            elif old_mapped and new_mapped:
                base_perm_bits = base_translation_data.base_state.memory.permissions(addr).concrete_value
                if base_perm_bits != perm_bits:
                    emu.mem_protect(addr, page_size, perm_bits)

            if perm_bits & 2:
                writable_pages.add(page_num)
            else:
                writable_pages.discard(page_num)

        # 3. Copy writable page contents.
        for page_num in writable_pages:
            addr = page_num * page_size
            memory, bitmap = state.memory.concrete_load(addr, page_size, with_bitmap=True)
            if any(bitmap):
                memory = state.solver.eval(state.memory.load(addr, page_size), cast_to=bytes)
            emu.mem_write(addr, memory)

        return IcicleStateTranslationData(
            base_state=state,
            registers=base_translation_data.registers,
            mapped_pages=mapped_pages,
            writable_pages=writable_pages,
            explicit_page_metadata=explicit_page_metadata,
            initial_cpu_icount=emu.cpu_icount,
            icicle_arch=icicle_arch,
        )

    def enable_snapshot_mode(self) -> None:
        """Enable snapshot mode for VM reuse across multiple runs."""
        self._snapshot_mode = True

    def has_snapshot(self) -> bool:
        """Check if a snapshot is available for fast restore."""
        return self._cached_emu is not None and self._cached_emu.has_snapshot()

    def restore_and_sync(self, state: HeavyConcreteState) -> None:
        """Restore the cached VM from snapshot and sync the given state to it."""
        if self._cached_emu is None or self._base_translation_data is None:
            raise ValueError("No cached emulator. Run process_concrete first with snapshot mode enabled.")
        self._cached_emu.restore_snapshot()
        self._base_translation_data = self.__sync_angr_state_to_icicle(
            self._cached_emu, state, self._base_translation_data
        )

    @override
    def process_concrete(
        self,
        state: HeavyConcreteState,
        num_inst: int | None = None,
        extra_stop_points: set[int] | None = None,
    ) -> HeavyConcreteState:
        _ensure_duplex_stdio(state)
        if self._cached_emu is not None and self._snapshot_mode:
            # Fast path: restore snapshot and sync only changed state
            if self._base_translation_data is None:
                raise ValueError("No base translation data. Run process_concrete first with snapshot mode enabled.")
            self._cached_emu.restore_snapshot()
            translation_data = self.__sync_angr_state_to_icicle(self._cached_emu, state, self._base_translation_data)
            emu = self._cached_emu
        else:
            # Full init path
            emu, translation_data = self.__convert_angr_state_to_icicle(state)
            if self._snapshot_mode and self._cached_emu is None:
                emu.save_snapshot()
                self._cached_emu = emu
                self._base_translation_data = translation_data

        # Set extra stop points, skip the current PC. Track which ones were
        # actually added so we can clean them up after the run.
        added_breakpoints = []
        if extra_stop_points is not None:
            for addr in extra_stop_points:
                addr = addr & ~1  # Clear thumb bit if set
                if emu.pc != addr and emu.add_breakpoint(addr):
                    added_breakpoints.append(addr)

        # Set the instruction count limit (icount_limit is absolute, so offset
        # by the current cpu_icount which may be non-zero after snapshot restore)
        if num_inst is not None and num_inst > 0:
            emu.icount_limit = emu.cpu_icount + num_inst

        # Reset page modification tracking so only writes during execution
        # are recorded.  This clears per-page modified flags and the global
        # modified set, allowing __convert_icicle_state_to_angr to skip
        # pages that were not touched.
        page_size = state.memory.page_size
        emu.reset_page_modification_tracking([page_num * page_size for page_num in translation_data.writable_pages])

        # Run it
        status = emu.run()

        # Remove extra stop points to prevent accumulation across runs
        for addr in added_breakpoints:
            emu.remove_breakpoint(addr)

        return IcicleEngine.__convert_icicle_state_to_angr(emu, translation_data, status)


class UberIcicleEngine(SimEngineFailure, SimEngineSyscall, HooksMixin, IcicleEngine):
    """
    An extension of the IcicleEngine that uses mixins to add support for
    syscalls and hooks. Most users will prefer to use this engine instead of the
    IcicleEngine directly.
    """
