#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.unpacker"  # pylint:disable=redefined-builtin

import os
import unittest

import pefile

import angr
from angr.analyses.unpacker.packer_identifier import identify_packer
from angr.analyses.unpacker.pe_rebuilder import RecoveredImport, rebuild_pe
from angr.analyses.unpacker.vmprotect_static import VMProtectStaticError, unpack_vmprotect_static
from tests.common import bin_location

from .samples import IMAGE_BASE, sample

TEXT_RVA, RDATA_RVA = 0x1000, 0x3000
# The VMProtect-like samples hold these .text, .rdata and .vmp0 compressed. The .text comes from not_packed.exe.
CODE = pefile.PE(data=sample("not_packed.exe")).sections[0].get_data()[:0x1800]
RDATA = b"imported strings and constants " * 64
VMP0 = bytes(range(256)) * 4


class TestVMProtectStatic(unittest.TestCase):
    def _check(self, kind: str):
        # The sample has the layout of a VMProtect-packed file. The original sections are empty, and .vmp1 holds the
        # compressed blocks and PACKER_INFO.
        packed = sample(f"vmprotect_like_{kind}_table.exe")
        info = identify_packer(packed)
        assert info.protector == "VMProtect"
        assert info.packed is True

        result = unpack_vmprotect_static(packed)
        assert result.table_kind == kind
        assert result.blocks == {".text": len(CODE), ".rdata": len(RDATA), ".vmp0": len(VMP0)}
        assert result.image[TEXT_RVA : TEXT_RVA + len(CODE)] == CODE
        assert result.image[RDATA_RVA : RDATA_RVA + len(RDATA)] == RDATA

        rebuilt = rebuild_pe(result.image)
        pe = pefile.PE(data=rebuilt)
        assert pe.sections[0].get_data()[: len(CODE)] == CODE
        assert identify_packer(rebuilt).packed is False

    def test_plain_table(self):
        self._check("plain")

    def test_encrypted_table(self):
        self._check("encrypted")

    def test_not_packed(self):
        plain = sample("not_packed.exe")
        assert identify_packer(plain).protector is None
        with self.assertRaises(VMProtectStaticError):
            unpack_vmprotect_static(plain)

    def test_packed_driver(self):
        path = os.path.join(
            bin_location,
            "tests",
            "x86_64",
            "windows",
            "444a401b900eb825f216e95111dcb6ef94b01a81fc7b88a48599867db8c50365.sys",
        )
        proj = angr.Project(path, auto_load_libs=False)
        identifier = proj.analyses.PackerIdentifier()
        assert identifier.protector == "VMProtect"
        assert identifier.packed is True

        unpacker = proj.analyses.VMProtectStaticUnpacker()
        assert unpacker.result.table_kind == "plain"
        assert unpacker.result.blocks[".text"] == 0x1FC00
        assert identify_packer(unpacker.unpacked).packed is False


class TestPERebuilder(unittest.TestCase):
    def test_import_section(self):
        image = bytearray(0x3000)
        plain = sample("not_packed_0x2000.exe")
        image[:0x400] = plain[:0x400]
        image[TEXT_RVA : TEXT_RVA + len(CODE)] = CODE
        imports = [
            RecoveredImport(0x2800, "kernel32.dll", "VirtualAlloc"),
            RecoveredImport(0x2804, "kernel32.dll", "ExitProcess"),
            RecoveredImport(0x280C, "user32.dll", None, 42),
        ]
        pe = pefile.PE(data=rebuild_pe(bytes(image), entry_rva=0x1234, imports=imports))
        assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0x1234
        recovered = {
            (entry.dll, imp.name, imp.ordinal if imp.name is None else None, imp.address - IMAGE_BASE)
            for entry in pe.DIRECTORY_ENTRY_IMPORT
            for imp in entry.imports
        }
        assert recovered == {
            (b"kernel32.dll", b"VirtualAlloc", None, 0x2800),
            (b"kernel32.dll", b"ExitProcess", None, 0x2804),
            (b"user32.dll", None, 42, 0x280C),
        }


if __name__ == "__main__":
    unittest.main()
