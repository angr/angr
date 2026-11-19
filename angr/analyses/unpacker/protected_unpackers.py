from __future__ import annotations

import logging

import pefile

from angr.analyses.analysis import AnalysesHub

from .generic_unpacker import EmulatingUnpacker
from .packer_identifier import PackerInfo, identify_packer
from .pe_rebuilder import rebuild_pe
from .vmprotect_static import VMProtectStaticError, VMProtectStaticResult, unpack_vmprotect_static

_l = logging.getLogger(__name__)

_CODE_AND_DATA = 0x60
_LOADER_SECTION_NAMES = {".idata", ".imports", ".rsrc", ".tls", ".themida", ".boot", ".winlice", ".taggant", ".reloc"}


def _name(section: pefile.SectionStructure) -> str:
    return section.Name.split(b"\0")[0].decode("latin-1").strip().lower()


def vmprotect_original_sections(data: bytes) -> set[int] | None:
    """
    Indices of the sections of a VMProtect-protected PE that belong to the original program.
    """
    pe = pefile.PE(data=data, fast_load=True)
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    # VMProtect appends its sections; everything before the first of them belongs to the original program
    first = next(
        (
            idx
            for idx, section in enumerate(pe.sections)
            if section.contains_rva(ep)
            or _name(section).startswith(".vmp")
            or (idx > 0 and section.Characteristics & _CODE_AND_DATA == _CODE_AND_DATA)
        ),
        0,
    )
    return set(range(first)) or None


def themida_original_sections(data: bytes) -> set[int]:
    """
    Indices of the sections of a Themida-protected PE that belong to the original program.
    """
    pe = pefile.PE(data=data, fast_load=True)
    # the original sections come first; Themida's import stub, resources and engine sections follow
    first = next((idx for idx, section in enumerate(pe.sections) if _name(section) in _LOADER_SECTION_NAMES), 0)
    return set(range(first)) or {0}


class VMProtectUnpacker(EmulatingUnpacker):
    """
    Unpack a VMProtect-packed PE.

    The loader is emulated until control first reaches one of the original sections, which gives the OEP and a
    rebuilt import table. If emulation does not get that far, the static PACKER_INFO unpacker is used instead; its
    output has the original sections but keeps VMProtect's entry point and import handling.

    `method` is "emulation", "static", or None when both failed.
    """

    def __init__(self, timeout: float = 600.0, static_only: bool = False):
        self.method: str | None = None
        self.static_result: VMProtectStaticResult | None = None
        self._static_only = static_only
        super().__init__(timeout=timeout, settle_timeout=0.0)

    def _sections_to_watch(self) -> set[int] | None:
        return vmprotect_original_sections(self.data)

    def _emulate(self, watch_sections: set[int] | None, timeout: float, settle_timeout: float) -> None:
        if not self._static_only:
            super()._emulate(watch_sections, timeout, settle_timeout)
            if self.unpacked is not None:
                self.method = "emulation"
                return
        try:
            self.static_result = unpack_vmprotect_static(self.data)
        except VMProtectStaticError as ex:
            _l.info("Static VMProtect unpacking failed: %s", ex)
            return
        self.unpacked = rebuild_pe(self.static_result.image)
        self.method = "static"


class ThemidaUnpacker(EmulatingUnpacker):
    """
    Unpack a Themida/WinLicense-protected PE by emulating it until control reaches the original program's sections.

    Themida's own sections are not watched, so its long start-up (anti-debug checks, worker threads, decryption) runs
    without being mistaken for an unpacked layer.
    """

    def __init__(self, timeout: float = 1800.0):
        super().__init__(timeout=timeout, settle_timeout=0.0)

    def _sections_to_watch(self) -> set[int] | None:
        return themida_original_sections(self.data)


class Unpacker(EmulatingUnpacker):
    """
    Identify the packer of the main PE object and run the matching unpacker.

    `info` holds the identification, `unpacker` the analysis that did the work (None if the file is not packed).
    """

    def __init__(self, timeout: float | None = None):
        self.info: PackerInfo | None = None
        self.unpacker: EmulatingUnpacker | None = None
        self._timeout = timeout
        super().__init__()

    def _emulate(self, watch_sections: set[int] | None, timeout: float, settle_timeout: float) -> None:
        self.info = identify_packer(self.data)
        if self.info.packed is False:
            return
        kwargs = {} if self._timeout is None else {"timeout": self._timeout}
        if self.info.protector == "VMProtect" and self.info.outer_packer is None:
            self.unpacker = self.project.analyses.VMProtectUnpacker(**kwargs)
        elif self.info.protector in ("Themida", "Themida+VMProtect"):
            self.unpacker = self.project.analyses.ThemidaUnpacker(**kwargs)
        else:
            self.unpacker = self.project.analyses.GenericUnpacker(**kwargs)
        self.layers = self.unpacker.layers
        self.stop = self.unpacker.stop
        self.oep = self.unpacker.oep
        self.unpacked = self.unpacker.unpacked
        self.core = self.unpacker.core


AnalysesHub.register_default("VMProtectUnpacker", VMProtectUnpacker)
AnalysesHub.register_default("ThemidaUnpacker", ThemidaUnpacker)
AnalysesHub.register_default("Unpacker", Unpacker)
