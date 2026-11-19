#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.unpacker"  # pylint:disable=redefined-builtin

import lzma
import os
import struct
import unittest

import pefile

import angr
from angr.analyses.unpacker.packer_identifier import identify_packer
from angr.analyses.unpacker.pe_rebuilder import RecoveredImport, rebuild_pe
from angr.analyses.unpacker.vmprotect_static import VMProtectStaticError, unpack_vmprotect_static
from tests.common import bin_location

from .pe_builder import IMAGE_BASE, build_pe, fake_code

LZMA_PROPS = bytes([0x5D, 0x00, 0x00, 0x00, 0x04])
TEXT_RVA, RDATA_RVA, VMP0_RVA, VMP1_RVA = 0x1000, 0x3000, 0x4000, 0x5000
CODE = fake_code(0x1800, IMAGE_BASE + TEXT_RVA)
RDATA = b"imported strings and constants " * 64
VMP0 = bytes(range(256)) * 4


def _compress(data: bytes) -> bytes:
    filters = [{"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2, "dict_size": 1 << 26}]
    compressor = lzma.LZMACompressor(lzma.FORMAT_RAW, filters=filters)
    return compressor.compress(data) + compressor.flush()


def _rol32(value: int, count: int) -> int:
    count &= 31
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def build_vmprotect_like(encrypted_table: bool) -> bytes:
    """
    A PE laid out like a VMProtect-packed file: empty original sections, compressed blocks and PACKER_INFO in .vmp1.
    """
    blocks = [(TEXT_RVA, _compress(CODE)), (RDATA_RVA, _compress(RDATA)), (VMP0_RVA, _compress(VMP0))]
    table_size = 8 * (len(blocks) + 1)
    loader = b"\x68\x78\x56\x34\x12\xe8\x00\x00\x00\x00".ljust(0x20, b"\xcc")
    payload_off = len(loader) + len(LZMA_PROPS) + table_size
    table = struct.pack("<II", VMP1_RVA + len(loader), 0)
    stream = bytearray()
    key = 0x5A17C3D9
    for idx, (dst, block) in enumerate(blocks):
        stored = dst ^ _rol32(key, 7 * idx) if encrypted_table else dst
        table += struct.pack("<II", VMP1_RVA + payload_off + len(stream), stored)
        stream += block
    vmp1 = loader + LZMA_PROPS + table + bytes(stream)
    return build_pe(
        [
            (b".text", TEXT_RVA, 0x1800, b"", 0x60000020),
            (b".rdata", RDATA_RVA, len(RDATA), b"", 0x40000040),
            (b".vmp0", VMP0_RVA, len(VMP0), b"", 0x60000060),
            (b".vmp1", VMP1_RVA, len(vmp1), vmp1, 0xE0000060),
        ],
        entry_rva=VMP1_RVA,
    )


class TestVMProtectStatic(unittest.TestCase):
    def _check(self, encrypted_table: bool, kind: str):
        packed = build_vmprotect_like(encrypted_table)
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
        self._check(False, "plain")

    def test_encrypted_table(self):
        self._check(True, "encrypted")

    def test_not_packed(self):
        plain = build_pe([(b".text", TEXT_RVA, len(CODE), CODE, 0x60000020)], entry_rva=TEXT_RVA)
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
        plain = build_pe([(b".text", TEXT_RVA, 0x2000, CODE, 0x60000020)], entry_rva=TEXT_RVA)
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
