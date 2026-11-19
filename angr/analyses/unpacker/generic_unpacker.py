from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

import capstone
import pefile

from angr.analyses.analysis import AnalysesHub, Analysis
from angr.project import Project

from .emulation import EmulationStop, SimWindowsEmulated, StopReason, WindowsEmulator
from .packer_identifier import call_target_score, entropy, section_name
from .pe_rebuilder import RecoveredImport, rebuild_pe

_l = logging.getLogger(__name__)

PAGE = 0x1000
_MIN_CODE_CALLS = 20
_SKIPPED_SECTIONS = {".rsrc", ".reloc", ".tls", ".idata", ".edata", ".pdata", ".taggant"}


@dataclass
class UnpackedLayer:
    """
    A snapshot of the image. Normally taken when execution first entered memory that was written at run time; `oep`
    is None for a snapshot taken at the end of a run that never showed such a transfer.
    """

    oep: int | None
    section: str
    blocks: int
    seconds: float
    calls: int
    entropy: float
    image: bytes
    imports: list[RecoveredImport] = field(default_factory=list)

    def rebuild(self, image_base: int) -> bytes:
        """
        A loadable PE whose entry point is this layer's OEP and whose import table is rebuilt.
        """
        entry_rva = None if self.oep is None else self.oep - image_base
        try:
            return rebuild_pe(self.image, entry_rva=entry_rva, imports=self.imports)
        except ValueError:
            return rebuild_pe(self.image, entry_rva=entry_rva)


class GenericUnpackerCore:
    """
    Run a packed PE under WindowsEmulator and snapshot the image each time control first reaches a section whose
    bytes were produced at run time. The last such transfer is reported as the original entry point.
    """

    def __init__(self, path: str, watch_sections: set[int] | None = None):
        self.project = Project(path, auto_load_libs=False, selfmodifying_code=True, simos=SimWindowsEmulated)
        self.emu = WindowsEmulator(self.project)
        self.layers: list[UnpackedLayer] = []
        self.stop: EmulationStop | None = None
        self._initial: dict[int, bytes] = {}
        self._sections: dict[int, pefile.SectionStructure] = {}
        self._started = 0.0
        emu = self.emu
        ep_rva = emu.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for idx, section in enumerate(emu.pe.sections):
            if watch_sections is not None and idx not in watch_sections:
                continue
            size = max(section.Misc_VirtualSize, section.SizeOfRawData)
            name = section_name(section).strip().lower()
            if size == 0 or section.contains_rva(ep_rva) or (watch_sections is None and name in _SKIPPED_SECTIONS):
                continue
            start = emu.image_base + section.VirtualAddress
            self._sections[start] = section
            self._initial[start] = emu.read(start, size)
            emu.watch_exec(start, size)

    def run(self, timeout: float = 300.0, settle_timeout: float = 20.0, max_layers: int = 8) -> None:
        """
        :param timeout:         Total wall-clock budget.
        :param settle_timeout:  How long to keep running after a layer was found, looking for a deeper one.
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
            if region is not None and self._was_written(stop.addr, region[0]):
                self.layers.append(self._snapshot(stop.addr, region[0]))
        if not self.layers:
            self._snapshot_unpacked_code()

    def _snapshot_unpacked_code(self) -> None:
        """
        Fallback for runs that never jumped into a watched section (for example when the entry point is virtualized
        or the protector quit first): if a watched section was filled with code anyway, keep that image.
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
        layer = UnpackedLayer(
            oep=addr,
            section=section_name(section),
            blocks=emu.blocks,
            seconds=time.monotonic() - self._started,
            calls=call_target_score(body, start, emu.image_base, emu.image_base + emu.image_size),
            entropy=entropy(body),
            image=bytes(image),
            imports=self._recover_imports(image),
        )
        _l.info("Layer %d: OEP %s in %s after %d blocks", len(self.layers), addr, layer.section, emu.blocks)
        return layer

    def _recover_imports(self, image: bytearray) -> list[RecoveredImport]:
        """
        Find import-address-table slots: pointer-aligned values in the image that are API trap addresses.
        """
        emu = self.emu
        size = emu.ptr_size
        lo = min(m.base for m in emu.module_order)
        hi = max(m.base + m.size for m in emu.module_order)
        found: list[RecoveredImport] = []
        view = memoryview(image).cast("Q" if size == 8 else "I")
        for idx, value in enumerate(view):
            if lo <= value < hi:
                slot = emu.api_slots.get(value)
                if slot is not None:
                    found.append(RecoveredImport(idx * size, slot[0].name, slot[1]))
        # isolated hits are usually coincidental constants; real IATs come in runs
        rvas = {imp.iat_rva for imp in found}
        return [imp for imp in found if imp.iat_rva - size in rvas or imp.iat_rva + size in rvas]

    @property
    def final_layer(self) -> UnpackedLayer | None:
        """
        The layer to report. Later transfers into written memory are often a protector's own runtime (for example a
        VM section called from the program), so the primary code section wins, then the deepest code-like layer.
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
    Base class of the unpackers that emulate the main PE object until it jumps into code it wrote at run time.

    `unpacked` is a rebuilt PE for the reported layer (None if the binary never ran written code), `oep` is its
    entry point, and `layers` lists every layer seen.
    """

    def __init__(self, timeout: float = 300.0, settle_timeout: float = 20.0):
        binary = self.project.loader.main_object.binary
        if binary is None:
            raise ValueError("Unpacking requires a file-backed main object")
        self.binary: str = binary
        with open(binary, "rb") as f:
            self.data: bytes = f.read()
        self.layers: list[UnpackedLayer] = []
        self.stop: EmulationStop | None = None
        self.oep: int | None = None
        self.unpacked: bytes | None = None
        self.core: GenericUnpackerCore | None = None
        self._emulate(self._sections_to_watch(), timeout, settle_timeout)

    def _sections_to_watch(self) -> set[int] | None:
        """
        Indices of the sections that hold the original program, or None to watch every plausible section.
        """
        return None

    def _emulate(self, watch_sections: set[int] | None, timeout: float, settle_timeout: float) -> None:
        core = GenericUnpackerCore(self.binary, watch_sections)
        core.run(timeout=timeout, settle_timeout=settle_timeout)
        self.core = core
        self.layers = core.layers
        self.stop = core.stop
        final = core.final_layer
        if final is not None:
            self.oep = final.oep
            self.unpacked = final.rebuild(core.emu.image_base)


class GenericUnpacker(EmulatingUnpacker):
    """
    Packer-agnostic unpacking: every section except the entry section is watched, and after a layer is found the
    program keeps running for settle_timeout seconds in case a deeper layer follows.
    """


AnalysesHub.register_default("GenericUnpacker", GenericUnpacker)
