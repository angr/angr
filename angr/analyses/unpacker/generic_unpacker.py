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
_SKIPPED_SECTIONS = {".rsrc", ".reloc", ".tls", ".idata", ".edata", ".pdata", ".taggant"}


@dataclass
class UnpackedLayer:
    """
    A snapshot taken when execution first entered memory that was written at run time.
    """

    oep: int
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
        try:
            return rebuild_pe(self.image, entry_rva=self.oep - image_base, imports=self.imports)
        except ValueError:
            return rebuild_pe(self.image, entry_rva=self.oep - image_base)


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
                self.stop = EmulationStop(StopReason.BUDGET, emu.pc)
                break
            stop = emu.run(timeout=budget)
            self.stop = stop
            if stop.reason is not StopReason.EXEC_TRAP:
                break
            region = emu.unwatch_exec(stop.addr)
            if region is not None and self._was_written(stop.addr, region[0]):
                self.layers.append(self._snapshot(stop.addr, region[0]))

    def _was_written(self, addr: int, start: int) -> bool:
        initial = self._initial[start]
        page = (addr & ~(PAGE - 1)) - start
        return self.emu.read(start + page, PAGE) != initial[page : page + PAGE].ljust(PAGE, b"\0")

    def _decodes(self, addr: int) -> bool:
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if self.emu.is_64bit else capstone.CS_MODE_32)
        return len(list(md.disasm(self.emu.read(addr, 64), addr, count=6))) >= 4

    def _snapshot(self, addr: int, start: int) -> UnpackedLayer:
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
        _l.info("Layer %d: OEP candidate %#x in %s after %d blocks", len(self.layers), addr, layer.section, emu.blocks)
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
        return self.layers[-1] if self.layers else None


class GenericUnpacker(Analysis):
    """
    Unpack the main PE object by emulating it until it jumps into code it wrote at run time.

    `unpacked` is a rebuilt PE for the deepest layer found (None if the binary never ran written code), `oep` is its
    entry point, and `layers` lists every intermediate layer.
    """

    def __init__(self, timeout: float = 300.0, settle_timeout: float = 20.0):
        binary = self.project.loader.main_object.binary
        if binary is None:
            raise ValueError("GenericUnpacker requires a file-backed main object")
        self.core = GenericUnpackerCore(binary)
        self.core.run(timeout=timeout, settle_timeout=settle_timeout)
        self.layers = self.core.layers
        self.stop = self.core.stop
        final = self.core.final_layer
        self.oep: int | None = final.oep if final is not None else None
        self.unpacked: bytes | None = final.rebuild(self.core.emu.image_base) if final is not None else None


AnalysesHub.register_default("GenericUnpacker", GenericUnpacker)
