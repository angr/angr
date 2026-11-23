#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.unpacker"  # pylint:disable=redefined-builtin

import os
import unittest

import pefile

import angr
from angr.analyses.unpacker import VMProtectUnpacker
from angr.analyses.unpacker.emulation import StopReason
from angr.analyses.unpacker.generic_unpacker import GenericUnpackerCore
from angr.analyses.unpacker.protected_unpackers import vmprotect_original_sections
from tests.common import bin_location

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


class TestVirtualizedProgram(unittest.TestCase):
    """
    A program that VMProtect virtualized without packing it: the entry point is in .vmp1, the original sections are
    readable on disk.
    """

    PATH = os.path.join(bin_location, "tests", "x86_64", "windows", "Project1.vmp.exe")

    def test_nothing_to_unpack(self):
        unpacker = angr.Project(self.PATH, auto_load_libs=False).analyses.Unpacker()
        assert unpacker.info is not None
        assert unpacker.info.protector == "VMProtect"
        assert unpacker.info.packed is False
        assert unpacker.unpacker is None
        assert unpacker.unpacked is None

    def test_runs_to_its_exit(self):
        # VMProtect's start-up and the virtualized code run until the program shows its dialog and exits
        with open(self.PATH, "rb") as f:
            watch = vmprotect_original_sections(f.read())
        core = GenericUnpackerCore(self.PATH, watch)
        core.run(timeout=60, settle_timeout=0)
        assert core.stop is not None
        assert core.stop.reason is StopReason.EXITED
        assert core.stop.detail == "ExitProcess(0x0)"
        emu = core.emu
        assert emu.exceptions.count == 0
        # the start-up makes .rdata writable with system calls of its own, not through ntdll
        assert emu.api_counts["NtProtectVirtualMemory"] == 6
        # WinMain: DialogBoxParamA(hInstance, 101, NULL, DialogProc, 0)
        dialogs = [args for name, _, args in emu.api_trace if name == "DialogBoxParamA"]
        assert dialogs == [(IMAGE_BASE, 101, 0, IMAGE_BASE + 0x1000, 0)]
        # no section was written and then run: there is no unpacked layer
        assert core.layers == []


if __name__ == "__main__":
    unittest.main()
