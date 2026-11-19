#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.unpacker"  # pylint:disable=redefined-builtin

import os
import struct
import tempfile
import unittest

import pefile

import angr
from angr.analyses.unpacker import VMProtectUnpacker
from angr.analyses.unpacker.emulation import StopReason

from .pe_builder import IMAGE_BASE, build_pe, fake_code
from .test_vmprotect_static import CODE, build_vmprotect_like

TEXT_RVA, STUB_RVA = 0x1000, 0x3000
OEP_RVA = TEXT_RVA + 0x800
XOR_KEY = 0x5A


def build_xor_packed(use_seh: bool = False) -> tuple[bytes, bytes]:
    """
    A PE whose .text is XOR-encrypted on disk; the entry stub decrypts it in place and jumps to the OEP.

    With use_seh, the stub first faults on purpose and relies on its SEH handler to skip the faulting instruction.
    """
    code = bytearray(fake_code(0x1000, IMAGE_BASE + TEXT_RVA))
    code[OEP_RVA - TEXT_RVA : OEP_RVA - TEXT_RVA + 3] = b"\x31\xc0\xc3"  # xor eax, eax; ret
    encrypted = bytes(b ^ XOR_KEY for b in code)
    stub = b""
    if use_seh:
        handler_rva = STUB_RVA + 0x80
        stub += b"\x68" + struct.pack("<I", IMAGE_BASE + handler_rva)  # push handler
        stub += bytes.fromhex("64ff3500000000 64892500000000")  # push fs:[0]; mov fs:[0], esp
        stub += bytes.fromhex("31c0 8900")  # xor eax, eax; mov [eax], eax
        stub += bytes.fromhex("648f0500000000 83c404")  # pop fs:[0]; add esp, 4
    stub += b"\xbe" + struct.pack("<I", IMAGE_BASE + TEXT_RVA)  # mov esi, .text
    stub += b"\xb9" + struct.pack("<I", len(code))  # mov ecx, size
    stub += bytes([0x80, 0x36, XOR_KEY, 0x46, 0xE2, 0xFA])  # xor byte [esi], key; inc esi; loop
    stub += b"\xe9" + struct.pack("<i", OEP_RVA - (STUB_RVA + len(stub) + 5))  # jmp OEP
    if use_seh:
        # handler: ctx = [esp+0xc]; ctx->Eip += 2; return ExceptionContinueExecution
        stub = stub.ljust(0x80, b"\xcc") + bytes.fromhex("8b44240c 8380b800000002 31c0 c3")
    packed = build_pe(
        [
            (b".text", TEXT_RVA, len(code), encrypted, 0xE0000020),
            (b".stub", STUB_RVA, len(stub), stub, 0x60000020),
        ],
        entry_rva=STUB_RVA,
    )
    return packed, bytes(code)


class TestGenericUnpacker(unittest.TestCase):
    def test_xor_packed(self):
        self._check(use_seh=False)

    def test_xor_packed_with_seh(self):
        self._check(use_seh=True)

    def _check(self, use_seh: bool):
        packed, code = build_xor_packed(use_seh)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "packed.exe")
            with open(path, "wb") as f:
                f.write(packed)
            proj = angr.Project(path, auto_load_libs=False)
            unpacker = proj.analyses.GenericUnpacker(timeout=30, settle_timeout=5)

        assert unpacker.oep == IMAGE_BASE + OEP_RVA
        assert len(unpacker.layers) == 1
        assert unpacker.stop is not None
        assert unpacker.stop.reason is StopReason.RETURNED
        assert unpacker.unpacked is not None
        pe = pefile.PE(data=unpacker.unpacked)
        assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == OEP_RVA
        assert pe.sections[0].get_data()[: len(code)] == code


class TestUnpackerFacade(unittest.TestCase):
    def _project(self, tmpdir: str, data: bytes) -> angr.Project:
        path = os.path.join(tmpdir, "sample.exe")
        with open(path, "wb") as f:
            f.write(data)
        return angr.Project(path, auto_load_libs=False)

    def test_generic(self):
        packed, _ = build_xor_packed()
        with tempfile.TemporaryDirectory() as tmpdir:
            unpacker = self._project(tmpdir, packed).analyses.Unpacker(timeout=30)
        assert unpacker.info is not None
        assert unpacker.info.protector is None
        assert unpacker.oep == IMAGE_BASE + OEP_RVA

    def test_vmprotect_falls_back_to_static(self):
        # the synthetic loader stub cannot run, so only the static unpacker can succeed
        packed = build_vmprotect_like(encrypted_table=False)
        with tempfile.TemporaryDirectory() as tmpdir:
            unpacker = self._project(tmpdir, packed).analyses.Unpacker(timeout=30)
        assert unpacker.info is not None
        assert unpacker.info.protector == "VMProtect"
        assert isinstance(unpacker.unpacker, VMProtectUnpacker)
        assert unpacker.unpacker.method == "static"
        assert unpacker.unpacked is not None
        assert pefile.PE(data=unpacker.unpacked).sections[0].get_data()[: len(CODE)] == CODE

    def test_not_packed(self):
        plain = build_pe([(b".text", TEXT_RVA, len(CODE), CODE, 0x60000020)], entry_rva=TEXT_RVA)
        with tempfile.TemporaryDirectory() as tmpdir:
            unpacker = self._project(tmpdir, plain).analyses.Unpacker()
        assert unpacker.unpacker is None
        assert unpacker.unpacked is None


if __name__ == "__main__":
    unittest.main()
