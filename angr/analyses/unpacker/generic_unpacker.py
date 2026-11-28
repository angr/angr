from __future__ import annotations

import bisect
import logging
import re
import struct
import time
from dataclasses import dataclass, field
from typing import Literal

import capstone
import pefile

from angr.analyses.analysis import AnalysesHub, Analysis
from angr.project import Project

from .emulation import EmulationStop, SimWindowsEmulated, StopReason, UnlistedExport, WindowsEmulator
from .packer_identifier import call_target_score, entropy, section_name
from .pe_rebuilder import RecoveredImport, rebuild_pe

_l = logging.getLogger(__name__)

Engine = Literal["icicle", "unicorn"]

PAGE = 0x1000
_MIN_CODE_CALLS = 20
_MAX_WRAPPERS = 4096
_WRAPPER_BUDGET = 120.0
_DIRECT_BRANCH_RE = re.compile(rb"[\xe8\xe9]", re.DOTALL)
_SKIPPED_SECTIONS = {".rsrc", ".reloc", ".tls", ".idata", ".edata", ".pdata", ".taggant"}


@dataclass
class UnpackedLayer:
    """
    A snapshot of the image.

    We normally take a snapshot when the program first jumps into memory that the program wrote at run time.
    `oep` is None for a snapshot that we take at the end of a run in which the program never made this jump.
    """

    oep: int | None
    section: str
    blocks: int
    seconds: float
    calls: int
    entropy: float
    image: bytes
    imports: list[RecoveredImport] = field(default_factory=list)
    restored_calls: int = 0

    def rebuild(self, image_base: int) -> bytes:
        """
        This method returns a loadable PE whose entry point is the OEP of this layer and whose import table is rebuilt.
        """
        entry_rva = None if self.oep is None else self.oep - image_base
        try:
            return rebuild_pe(self.image, entry_rva=entry_rva, imports=self.imports)
        except ValueError:
            return rebuild_pe(self.image, entry_rva=entry_rva)


class GenericUnpackerCore:
    """
    This class runs a packed PE in WindowsEmulator. We take a snapshot of the image each time the program first jumps
    into a section whose bytes the program wrote at run time.
    We report the target of the last jump as the original entry point.
    """

    def __init__(
        self,
        path: str,
        watch_sections: set[int] | None = None,
        engine: Engine = "unicorn",
        icicle_jit: bool = True,
        icicle_jit_threshold: int = 32,
        icicle_thread_slice: int = 4_000_000,
        exports_dir: str | None = None,
    ):
        self.project = Project(path, auto_load_libs=False, selfmodifying_code=True, simos=SimWindowsEmulated)
        if engine == "icicle":
            from .emulation.icicle_environment import IcicleWindowsEmulator  # pylint:disable=import-outside-toplevel

            self.emu = IcicleWindowsEmulator(
                self.project,
                exports_dir=exports_dir,
                jit=icicle_jit,
                jit_threshold=icicle_jit_threshold,
                thread_slice=icicle_thread_slice,
            )
        elif engine == "unicorn":
            self.emu = WindowsEmulator(self.project, exports_dir=exports_dir)
        else:
            raise ValueError(f"Unknown emulation engine {engine!r}")
        self.layers: list[UnpackedLayer] = []
        self.stop: EmulationStop | None = None
        self._initial: dict[int, bytes] = {}
        self._sections: dict[int, pefile.SectionStructure] = {}
        self._wrappers: dict[int, int] = {}
        self._cell_of_target: dict[int, int] = {}
        self._started = 0.0
        # The watched section that holds the entry point. We only watch this section at the request of the caller.
        self._entry_section: int | None = None
        emu = self.emu
        ep_rva = emu.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for idx, section in enumerate(emu.pe.sections):
            if watch_sections is not None and idx not in watch_sections:
                continue
            size = max(section.Misc_VirtualSize, section.SizeOfRawData)
            name = section_name(section).strip().lower()
            if size == 0 or (watch_sections is None and (section.contains_rva(ep_rva) or name in _SKIPPED_SECTIONS)):
                continue
            start = emu.image_base + section.VirtualAddress
            if section.contains_rva(ep_rva):
                self._entry_section = start
            self._sections[start] = section
            self._initial[start] = emu.read(start, size)
            emu.watch_exec(start, size)

    def run(self, timeout: float = 300.0, settle_timeout: float = 20.0, max_layers: int = 8) -> None:
        """
        :param timeout:         The total time budget in seconds.
        :param settle_timeout:  The time in seconds that we keep running after we find a layer.
        """
        emu = self.emu
        self._started = time.monotonic()
        deadline = self._started + timeout
        emu.start()
        while len(self.layers) < max_layers:
            now = time.monotonic()
            budget = deadline - now
            if self.layers:
                budget = min(budget, self._started + self.layers[-1].seconds + settle_timeout - now)
            if budget <= 0:
                if not self.layers or self.stop is None:
                    self.stop = EmulationStop(StopReason.BUDGET, emu.pc)
                break
            stop = emu.run(timeout=budget)
            self.stop = stop
            if stop.reason is not StopReason.EXEC_TRAP:
                break
            region = emu.unwatch_exec(stop.addr)
            if region is None:
                continue
            start = self._section_start(stop.addr)
            if self._was_written(stop.addr, start):
                self.layers.append(self._snapshot(stop.addr, start))
            elif start == self._entry_section:
                # The program runs the entry stub of the protector in the entry section. We keep watching the rest
                # of the section, and we watch this page again after the program leaves the page.
                page = stop.addr & ~(PAGE - 1)
                if page > region[0]:
                    emu.watch_exec(region[0], page - region[0])
                if page + PAGE < region[1]:
                    emu.watch_exec(page + PAGE, region[1] - page - PAGE)
                emu.watch_page_after_leaving(page)
        if not self.layers:
            self._snapshot_unpacked_code()

    def _snapshot_unpacked_code(self) -> None:
        """
        This method handles a run that never jumped into a watched section, for example when the entry point is
        virtualized or the protector quit first. If the program filled a watched section with code anyway, we keep
        the image.
        """
        emu = self.emu
        best: UnpackedLayer | None = None
        for start in self._sections:
            if emu.read(start, len(self._initial[start])) == self._initial[start]:
                continue
            layer = self._snapshot(None, start)
            if layer.calls >= _MIN_CODE_CALLS and (best is None or layer.calls > best.calls):
                best = layer
        if best is not None:
            self.layers.append(best)

    def _section_start(self, addr: int) -> int:
        starts = sorted(self._sections)
        return starts[bisect.bisect_right(starts, addr) - 1]

    def _was_written(self, addr: int, start: int) -> bool:
        initial = self._initial[start]
        page = (addr & ~(PAGE - 1)) - start
        return self.emu.read(start + page, PAGE) != initial[page : page + PAGE].ljust(PAGE, b"\0")

    def _decodes(self, addr: int) -> bool:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if self.emu.is_64bit else capstone.CS_MODE_32)
        return len(list(md.disasm(self.emu.read(addr, 64), addr, count=6))) >= 4

    def _snapshot(self, addr: int | None, start: int) -> UnpackedLayer:
        emu = self.emu
        section = self._sections[start]
        image = bytearray(emu.read(emu.image_base, emu.image_size))
        header_size = emu.pe.OPTIONAL_HEADER.SizeOfHeaders
        image[:header_size] = emu.image_file[:header_size]
        body = bytes(image[section.VirtualAddress : section.VirtualAddress + section.Misc_VirtualSize])
        imports = self._recover_imports(image)
        restored = self._restore_calls(image)
        layer = UnpackedLayer(
            oep=addr,
            section=section_name(section),
            blocks=emu.blocks,
            seconds=time.monotonic() - self._started,
            calls=call_target_score(body, start, emu.image_base, emu.image_base + emu.image_size),
            entropy=entropy(body),
            image=bytes(image),
            imports=imports,
            restored_calls=restored,
        )
        _l.info("Layer %d: OEP %s in %s after %d blocks", len(self.layers), addr, layer.section, emu.blocks)
        return layer

    def _recover_imports(self, image: bytearray) -> list[RecoveredImport]:
        """
        This method finds the slots of the import address table. A slot is a pointer-aligned value in the image that
        is an API trap address, or that points at a wrapper outside the image that ends up in an API.
        """
        emu = self.emu
        size = emu.ptr_size
        lo = min(m.base for m in emu.module_order)
        hi = max(m.base + m.size for m in emu.module_order)
        allocations = sorted(emu.allocations.items())
        starts = [start for start, _ in allocations]
        view = memoryview(image).cast("Q" if size == 8 else "I")
        direct: dict[int, int] = {}
        wrapped: dict[int, int] = {}
        for idx, value in enumerate(view):
            if lo <= value < hi:
                if value in emu.api_slots:
                    direct[idx] = value
            elif starts and value >= starts[0]:
                pos = bisect.bisect_right(starts, value) - 1
                if value < starts[pos] + allocations[pos][1]:
                    wrapped[idx] = value
        # A wrapper sits in the table next to other imports. Any other value that points into an allocation is data.
        cells = dict(direct)
        resolved: dict[int, int | None] = {}
        deadline = time.monotonic() + _WRAPPER_BUDGET
        for idx in sorted(wrapped):
            if not any(idx + delta in direct or idx + delta in wrapped for delta in (-2, -1, 1, 2)):
                continue
            target = wrapped[idx]
            if target not in resolved:
                if len(resolved) >= _MAX_WRAPPERS or time.monotonic() > deadline:
                    break
                resolved[target] = emu.trace_to_api(target)
            api = resolved[target]
            if api is not None:
                cells[idx] = api
        self._wrappers = {target: api for target, api in resolved.items() if api is not None}
        found = []
        for idx, api in sorted(cells.items()):
            module, name = emu.api_slots[api]
            ordinal = module.unnamed_ordinal(api)
            if ordinal is None:
                found.append(RecoveredImport(idx * size, module.name, name))
            else:
                found.append(RecoveredImport(idx * size, module.name, None, ordinal))
        # A real import address table is a run of slots, so we drop every slot that has no neighbor.
        rvas = {imp.iat_rva for imp in found}
        found = [imp for imp in found if imp.iat_rva - size in rvas or imp.iat_rva + size in rvas]
        self._cell_of_target = {}
        for imp in found:
            self._cell_of_target.setdefault(view[imp.iat_rva // size], imp.iat_rva)
        return found

    def _restore_calls(self, image: bytearray) -> int:
        """
        Protectors rewrite `call/jmp [import slot]` into a direct call or jump to the target of the slot, padded with
        a nop. This method undoes the rewriting and returns the number of restored sites.
        """
        emu = self.emu
        if not self._cell_of_target:
            return 0
        restored = 0
        for start, section in self._sections.items():
            rva = section.VirtualAddress
            end = min(rva + max(section.Misc_VirtualSize, section.SizeOfRawData), len(image))
            for match in _DIRECT_BRANCH_RE.finditer(bytes(image[rva:end])):
                site = rva + match.start()
                if site + 6 > end:
                    break
                target = (start - rva + site + 5 + struct.unpack_from("<i", image, site + 1)[0]) & (
                    (1 << (8 * emu.ptr_size)) - 1
                )
                cell = self._cell_of_target.get(target)
                if cell is None:
                    continue
                # The nop follows or precedes the branch. When both nops are there, we start at the branch.
                if image[site + 5] != 0x90:
                    if site == rva or image[site - 1] != 0x90:
                        continue
                    site -= 1
                operand = cell - (site + 6) if emu.is_64bit else emu.image_base + cell
                opcode = b"\xff\x15" if match.group() == b"\xe8" else b"\xff\x25"
                image[site : site + 6] = opcode + struct.pack("<I", operand & 0xFFFFFFFF)
                restored += 1
        return restored

    @property
    def final_layer(self) -> UnpackedLayer | None:
        """
        The layer that we report.

        A later jump into written memory is often the runtime of the protector, for example a VM section that the
        program calls, so we prefer the last layer in the primary code section.
        Otherwise, we report the last layer that looks like code.
        """
        if not self.layers:
            return None
        primary = next((s for s in self.emu.pe.sections if s.Characteristics & 0x20000000), None)
        primary_name = section_name(primary) if primary is not None else None
        for candidates in (
            [layer for layer in self.layers if layer.section == primary_name],
            [layer for layer in self.layers if layer.calls >= _MIN_CODE_CALLS],
        ):
            if candidates:
                return candidates[-1]
        return self.layers[-1]


class EmulatingUnpacker(Analysis):
    """
    Base class of the unpackers that emulate the main PE object until the program jumps into code that the program
    wrote at run time.

    `unpacked` is a rebuilt PE for the reported layer, or None if the program never ran code that the program wrote.
    `oep` is the entry point of the reported layer.
    `layers` lists every layer that we saw.

    :param engine:               The emulator that runs the program, which is "icicle" or "unicorn".
    :param icicle_jit:           Whether Icicle compiles hot blocks to native code.
    :param icicle_jit_threshold: The number of times Icicle runs a block before Icicle compiles the block.
    :param icicle_thread_slice:  The number of instructions that a thread runs on Icicle before the next thread runs.
    :param exports_dir:          The directory of the export lists of the DLLs. We use the lists of angr-data by
                                 default.
    """

    def __init__(
        self,
        timeout: float = 300.0,
        settle_timeout: float = 20.0,
        engine: Engine = "unicorn",
        icicle_jit: bool = True,
        icicle_jit_threshold: int = 32,
        icicle_thread_slice: int = 4_000_000,
        exports_dir: str | None = None,
    ):
        binary = self.project.loader.main_object.binary
        if binary is None:
            raise ValueError("Unpacking requires a file-backed main object")
        self.binary: str = binary
        self.engine: Engine = engine
        self.icicle_jit = icicle_jit
        self.icicle_jit_threshold = icicle_jit_threshold
        self.icicle_thread_slice = icicle_thread_slice
        self.exports_dir = exports_dir
        with open(binary, "rb") as f:
            self.data: bytes = f.read()
        self.layers: list[UnpackedLayer] = []
        self.stop: EmulationStop | None = None
        self.oep: int | None = None
        self.unpacked: bytes | None = None
        self.core: GenericUnpackerCore | None = None
        #: The exports that the program asked for and that the export lists of the DLLs do not have.
        self.unlisted_exports: list[UnlistedExport] = []
        self._emulate(self._sections_to_watch(), timeout, settle_timeout)

    def _sections_to_watch(self) -> set[int] | None:
        """
        This method returns the indices of the sections that hold the original program, or None to watch every
        plausible section.
        """
        return None

    def _emulate(self, watch_sections: set[int] | None, timeout: float, settle_timeout: float) -> None:
        core = GenericUnpackerCore(
            self.binary,
            watch_sections,
            self.engine,
            icicle_jit=self.icicle_jit,
            icicle_jit_threshold=self.icicle_jit_threshold,
            icicle_thread_slice=self.icicle_thread_slice,
            exports_dir=self.exports_dir,
        )
        core.run(timeout=timeout, settle_timeout=settle_timeout)
        self.core = core
        self.layers = core.layers
        self.stop = core.stop
        self.unlisted_exports = core.emu.unlisted_exports
        final = core.final_layer
        if final is not None:
            self.oep = final.oep
            self.unpacked = final.rebuild(core.emu.image_base)


class GenericUnpacker(EmulatingUnpacker):
    """
    This analysis unpacks a PE without knowing which tool packed the PE.

    We watch every section except the entry section. After we find a layer, the program keeps running for
    `settle_timeout` seconds in case a deeper layer follows.
    """


AnalysesHub.register_default("GenericUnpacker", GenericUnpacker)
