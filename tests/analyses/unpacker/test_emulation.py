#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.unpacker"  # pylint:disable=redefined-builtin

import os
import struct
import tempfile
import unittest

from angr.analyses.unpacker.emulation import StopReason
from angr.analyses.unpacker.generic_unpacker import GenericUnpackerCore

from .pe_builder import IMAGE_BASE, build_pe

CODE_RVA = 0x1000
HANDLE = 0x1234


class TestSystemCallStubs(unittest.TestCase):
    def test_x86_stub_called_past_its_first_instruction(self):
        # entry: mov eax, [ZwClose + 1]; push HANDLE; call rest; ret
        # rest:  mov edx, 0x7ffe0300; call [edx]; ret 4          (a copy of the stub minus its first instruction)
        code = bytearray(b"\xa1\0\0\0\0\x68" + struct.pack("<I", HANDLE) + b"\xe8\x01\0\0\0\xc3")
        code += bytes.fromhex("ba0003fe7f ff12 c20400")
        packed = build_pe([(b".text", CODE_RVA, 0x1000, bytes(code), 0x60000020)], entry_rva=CODE_RVA)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "syscall.exe")
            with open(path, "wb") as f:
                f.write(packed)
            emu = GenericUnpackerCore(path, watch_sections=set()).emu
        ntdll = emu.load_module("ntdll.dll")
        close, query = ntdll.resolve("ZwClose"), ntdll.resolve("NtQueryInformationProcess")
        assert close is not None and query is not None
        stub, other = emu.read(close, 16), emu.read(query, 16)
        # mov eax, number; mov edx, 0x7ffe0300; call [edx]; ret 4
        assert stub[0] == 0xB8 and stub[5:15] == bytes.fromhex("ba0003fe7f ff12 c20400")
        assert other[0] == 0xB8 and other[1:5] != stub[1:5] and other[5:12] == stub[5:12]

        emu.write(IMAGE_BASE + CODE_RVA + 1, struct.pack("<I", close + 1))
        emu.start()
        stop = emu.run(timeout=20)
        assert stop.reason is StopReason.RETURNED
        assert ("NtClose", (HANDLE,)) in [(name, args) for name, _, args in emu.api_trace]


if __name__ == "__main__":
    unittest.main()
