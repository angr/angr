#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.unpacker"  # pylint:disable=redefined-builtin

import os
import struct
import tempfile
import unittest

import pefile

from angr.analyses.unpacker.emulation import StopReason
from angr.analyses.unpacker.emulation.apis import API_HANDLERS
from angr.analyses.unpacker.emulation.modules import FakeModule
from angr.analyses.unpacker.generic_unpacker import GenericUnpackerCore

from .pe_builder import IMAGE_BASE, build_pe

CODE_RVA = 0x1000
HANDLE = 0x1234


def emulator(code: bytes):
    packed = build_pe([(b".text", CODE_RVA, 0x1000, code, 0x60000020)], entry_rva=CODE_RVA)
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "sample.exe")
        with open(path, "wb") as f:
            f.write(packed)
        return GenericUnpackerCore(path, watch_sections=set()).emu


class TestApiHandlers(unittest.TestCase):
    def test_wvsprintf(self):
        emu = emulator(b"\xc3")
        buf = emu.alloc(0x1000)
        emu.write(buf, b"%s=%d %05u 0x%08X %c%% %-4sx %ls\0")
        emu.write(buf + 0x100, b"key\0ab\0" + "wide".encode("utf-16-le") + b"\0\0")
        values = (buf + 0x100, 0xFFFFFFFE, 42, 0xBEEF, ord("z"), buf + 0x104, buf + 0x107)
        emu.write(buf + 0x200, struct.pack("<7I", *values))
        length = API_HANDLERS["wvsprintfA"].func(emu, [buf + 0x400, buf, buf + 0x200])
        expected = "key=-2 00042 0x0000BEEF z% ab  x wide"
        assert length == len(expected)
        assert emu.read_cstr(buf + 0x400) == expected


class TestImportWrappers(unittest.TestCase):
    def test_trace_to_api(self):
        emu = emulator(b"\xc3")
        emu.start()
        sleep = emu.resolve_export(emu.load_module("kernel32.dll"), "Sleep")
        assert sleep is not None
        wrapper = emu.alloc(0x1000)
        # a relocated copy of the API's first instructions, as import wrappers carry
        emu.write(wrapper, b"\x50\x58" + emu.read(sleep, 12))
        # junk, then a jump past the API's first instruction
        emu.write(wrapper + 0x100, b"\x8b\xff\x90\xe9" + struct.pack("<i", sleep + 2 - (wrapper + 0x108)))
        emu.write(wrapper + 0x200, b"\x31\xc0\xc3")
        pc = emu.pc
        assert emu.trace_to_api(wrapper) == sleep
        assert emu.trace_to_api(wrapper + 0x100) == sleep
        assert emu.trace_to_api(wrapper + 0x200) is None
        assert emu.pc == pc


class TestImportRecovery(unittest.TestCase):
    def test_wrapped_imports_and_rewritten_calls(self):
        sections = [
            (b".text", CODE_RVA, 0x1000, bytes(0x1000), 0xE0000020),
            (b".stub", 0x3000, 0x10, b"\xc3", 0x60000020),
        ]
        packed = build_pe(sections, entry_rva=0x3000)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "sample.exe")
            with open(path, "wb") as f:
                f.write(packed)
            core = GenericUnpackerCore(path)
        emu = core.emu
        emu.start()
        kernel32 = emu.load_module("kernel32.dll")
        sleep, close = emu.resolve_export(kernel32, "Sleep"), emu.resolve_export(kernel32, "CloseHandle")
        assert sleep is not None and close is not None
        wrapper = emu.alloc(0x1000)
        emu.write(wrapper, emu.read(close, 12))
        text = IMAGE_BASE + CODE_RVA
        iat = text + 0x800
        emu.write(iat, struct.pack("<II", sleep, wrapper))
        # call Sleep; nop   /   nop; jmp wrapper   /   an ordinary call inside the section
        emu.write(text, b"\xe8" + struct.pack("<i", sleep - (text + 5)) + b"\x90")
        emu.write(text + 0x10, b"\x90\xe9" + struct.pack("<i", wrapper - (text + 0x16)))
        emu.write(text + 0x20, b"\xe8" + struct.pack("<i", 0x100) + b"\x90")

        layer = core._snapshot(None, text)  # pylint:disable=protected-access
        assert [(imp.iat_rva, imp.dll, imp.name) for imp in layer.imports] == [
            (CODE_RVA + 0x800, "kernel32.dll", "Sleep"),
            (CODE_RVA + 0x804, "kernel32.dll", "CloseHandle"),
        ]
        assert layer.restored_calls == 2
        code = layer.image[CODE_RVA : CODE_RVA + 0x30]
        assert code[:6] == b"\xff\x15" + struct.pack("<I", iat)
        assert code[0x10:0x16] == b"\xff\x25" + struct.pack("<I", iat + 4)
        assert code[0x20] == 0xE8


class TestFakeModule(unittest.TestCase):
    def test_export_ordinals(self):
        base = 0x10000000
        module = FakeModule("demo.dll", base, ["Alpha", "Beta"], False, {100: "Beta", 105: None})
        assert module.resolve_ordinal(100) == module.exports["Beta"]
        unnamed = module.resolve_ordinal(105)
        assert unnamed is not None and module.unnamed_ordinal(unnamed) == 105
        assert module.unnamed_ordinal(module.exports["Alpha"]) is None
        # the export directory says the same to code that walks it
        pe = pefile.PE(data=module.image)
        exports = {(sym.ordinal, sym.name, base + sym.address) for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols}
        assert exports == {
            (100, b"Beta", module.exports["Beta"]),
            (105, None, unnamed),
            (106, b"Alpha", module.exports["Alpha"]),
        }


class TestSystemCallStubs(unittest.TestCase):
    def test_x86_stub_called_past_its_first_instruction(self):
        # entry: mov eax, [ZwClose + 1]; push HANDLE; call rest; ret
        # rest:  mov edx, 0x7ffe0300; call [edx]; ret 4          (a copy of the stub minus its first instruction)
        code = bytearray(b"\xa1\0\0\0\0\x68" + struct.pack("<I", HANDLE) + b"\xe8\x01\0\0\0\xc3")
        code += bytes.fromhex("ba0003fe7f ff12 c20400")
        emu = emulator(bytes(code))
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
