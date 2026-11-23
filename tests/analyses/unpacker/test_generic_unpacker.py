#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.unpacker"  # pylint:disable=redefined-builtin

import unittest

import pefile

import angr
from angr.analyses.unpacker import VMProtectUnpacker
from angr.analyses.unpacker.emulation import StopReason
from angr.analyses.unpacker.generic_unpacker import GenericUnpackerCore
from angr.analyses.unpacker.protected_unpackers import vmprotect_original_sections

from .samples import IMAGE_BASE, sample, sample_path
from .test_vmprotect_static import CODE

TEXT_RVA, STUB_RVA = 0x1000, 0x3000
OEP_RVA = TEXT_RVA + 0x800
XOR_KEY = 0x5A


def xor_packed_code(name: str) -> bytes:
    """
    The code that the XOR-packed sample holds encrypted in its .text section.
    """
    return bytes(b ^ XOR_KEY for b in pefile.PE(data=sample(name)).sections[0].get_data()[:0x1000])


class TestGenericUnpacker(unittest.TestCase):
    def test_xor_packed(self):
        # .text is XOR-encrypted on disk; the entry stub decrypts it in place and jumps to the OEP
        self._check("xor_packed.exe")

    def test_xor_packed_with_seh(self):
        # the stub first faults on purpose and relies on its SEH handler to skip the faulting instruction
        self._check("xor_packed_seh.exe")

    def _check(self, name: str):
        code = xor_packed_code(name)
        proj = angr.Project(sample_path(name), auto_load_libs=False)
        unpacker = proj.analyses.GenericUnpacker(timeout=30, settle_timeout=5)

        assert unpacker.oep == IMAGE_BASE + OEP_RVA
        assert len(unpacker.layers) == 1
        assert unpacker.stop is not None
        assert unpacker.stop.reason is StopReason.RETURNED
        assert unpacker.unpacked is not None
        pe = pefile.PE(data=unpacker.unpacked)
        assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == OEP_RVA
        assert pe.sections[0].get_data()[: len(code)] == code

    def test_entry_point_in_packed_section(self):
        # the entry stub sits inside the packed .text; the loader decrypts .text, restores the original entry code,
        # calls an API and jumps back to the entry point
        name = "xor_packed_entry_in_text.exe"
        cell = IMAGE_BASE + STUB_RVA + 0x100
        oep = IMAGE_BASE + OEP_RVA
        assert vmprotect_original_sections(sample(name)) == {0}
        core = GenericUnpackerCore(sample_path(name), {0})
        api = core.emu.resolve_export(core.emu.load_module("kernel32.dll"), "GetTickCount")
        assert api is not None
        core.emu.write_u32(cell, api)
        core.run(timeout=30, settle_timeout=0)
        assert [layer.oep for layer in core.layers] == [oep]

    def test_snapshot_without_transfer(self):
        # the stub decrypts .text but returns instead of jumping to the OEP
        name = "xor_packed_no_transfer.exe"
        code = xor_packed_code(name)
        unpacker = angr.Project(sample_path(name), auto_load_libs=False).analyses.GenericUnpacker(timeout=30)
        assert unpacker.oep is None
        assert unpacker.unpacked is not None
        pe = pefile.PE(data=unpacker.unpacked)
        assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == STUB_RVA
        assert pe.sections[0].get_data()[: len(code)] == code


class TestUnpackerFacade(unittest.TestCase):
    def _project(self, name: str) -> angr.Project:
        return angr.Project(sample_path(name), auto_load_libs=False)

    def test_generic(self):
        unpacker = self._project("xor_packed.exe").analyses.Unpacker(timeout=30)
        assert unpacker.info is not None
        assert unpacker.info.protector is None
        assert unpacker.oep == IMAGE_BASE + OEP_RVA

    def test_vmprotect_falls_back_to_static(self):
        # the synthetic loader stub cannot run, so only the static unpacker can succeed
        unpacker = self._project("vmprotect_like_plain_table.exe").analyses.Unpacker(timeout=30)
        assert unpacker.info is not None
        assert unpacker.info.protector == "VMProtect"
        assert isinstance(unpacker.unpacker, VMProtectUnpacker)
        assert unpacker.unpacker.method == "static"
        assert unpacker.unpacked is not None
        assert pefile.PE(data=unpacker.unpacked).sections[0].get_data()[: len(CODE)] == CODE

    def test_not_packed(self):
        unpacker = self._project("not_packed.exe").analyses.Unpacker()
        assert unpacker.unpacker is None
        assert unpacker.unpacked is None


if __name__ == "__main__":
    unittest.main()
