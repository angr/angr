from __future__ import annotations

import logging

import pefile

from angr.analyses.analysis import AnalysesHub

from .generic_unpacker import EmulatingUnpacker, Engine
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
    This function returns the indices of the sections of a VMProtect-protected PE that belong to the original program.
    """
    pe = pefile.PE(data=data, fast_load=True)
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    # VMProtect adds new sections at the end, so every section before the first new section belongs to the original
    # program.
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
    if first == 0 and pe.sections and pe.sections[0].contains_rva(ep) and not _name(pe.sections[0]).startswith(".vmp"):
        # VMProtect leaves the entry point in the original code section when the entry function is virtualized.
        # The loader returns to the original code section after unpacking, so we watch the original code section.
        return {0}
    return set(range(first)) or None


def themida_original_sections(data: bytes) -> set[int]:
    """
    This function returns the indices of the sections of a Themida-protected PE that belong to the original program.
    """
    pe = pefile.PE(data=data, fast_load=True)
    # The original sections come first. The import stub, the resources and the engine sections of Themida follow.
    first = next((idx for idx, section in enumerate(pe.sections) if _name(section) in _LOADER_SECTION_NAMES), 0)
    return set(range(first)) or {0}


class VMProtectUnpacker(EmulatingUnpacker):
    """
    This analysis unpacks a VMProtect-packed PE.

    We emulate the loader until the program first reaches one of the original sections, which gives the OEP and a
    rebuilt import table.
    If the emulation does not reach an original section, we use the static PACKER_INFO unpacker instead. The output
    of the static unpacker has the original sections, but keeps the entry point and the import handling of VMProtect.

    `method` is "emulation", "static", or None when both failed.
    """

    def __init__(
        self,
        timeout: float = 600.0,
        static_only: bool = False,
        engine: Engine = "unicorn",
        icicle_jit: bool = True,
        icicle_jit_threshold: int = 32,
        icicle_thread_slice: int = 4_000_000,
        exports_dir: str | None = None,
    ):
        self.method: str | None = None
        self.static_result: VMProtectStaticResult | None = None
        self._static_only = static_only
        super().__init__(
            timeout=timeout,
            settle_timeout=0.0,
            engine=engine,
            icicle_jit=icicle_jit,
            icicle_jit_threshold=icicle_jit_threshold,
            icicle_thread_slice=icicle_thread_slice,
            exports_dir=exports_dir,
        )

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
    This analysis unpacks a PE protected by Themida or WinLicense. We emulate the PE until the program reaches the
    sections of the original program.

    We do not watch the sections of Themida, so we do not mistake the long start-up of Themida for an unpacked layer.
    The start-up of Themida includes anti-debug checks, worker threads and decryption.
    """

    def __init__(
        self,
        timeout: float = 1800.0,
        engine: Engine = "unicorn",
        icicle_jit: bool = True,
        icicle_jit_threshold: int = 32,
        icicle_thread_slice: int = 4_000_000,
        exports_dir: str | None = None,
    ):
        super().__init__(
            timeout=timeout,
            settle_timeout=0.0,
            engine=engine,
            icicle_jit=icicle_jit,
            icicle_jit_threshold=icicle_jit_threshold,
            icicle_thread_slice=icicle_thread_slice,
            exports_dir=exports_dir,
        )

    def _sections_to_watch(self) -> set[int] | None:
        return themida_original_sections(self.data)


class Unpacker(EmulatingUnpacker):
    """
    This analysis identifies the packer of the main PE object and runs the matching unpacker.

    `info` holds the identification.
    `unpacker` is the analysis that did the work, or None if the file is not packed.
    """

    def __init__(
        self,
        timeout: float | None = None,
        engine: Engine = "unicorn",
        icicle_jit: bool = True,
        icicle_jit_threshold: int = 32,
        icicle_thread_slice: int = 4_000_000,
        exports_dir: str | None = None,
    ):
        self.info: PackerInfo | None = None
        self.unpacker: EmulatingUnpacker | None = None
        self._timeout = timeout
        super().__init__(
            engine=engine,
            icicle_jit=icicle_jit,
            icicle_jit_threshold=icicle_jit_threshold,
            icicle_thread_slice=icicle_thread_slice,
            exports_dir=exports_dir,
        )

    def _emulate(self, watch_sections: set[int] | None, timeout: float, settle_timeout: float) -> None:
        self.info = identify_packer(self.data)
        if self.info.packed is False:
            return
        kwargs: dict[str, float | Engine | str | None] = {
            "engine": self.engine,
            "icicle_jit": self.icicle_jit,
            "icicle_jit_threshold": self.icicle_jit_threshold,
            "icicle_thread_slice": self.icicle_thread_slice,
            "exports_dir": self.exports_dir,
        }
        if self._timeout is not None:
            kwargs["timeout"] = self._timeout
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
