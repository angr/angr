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

from .pe_builder import IMAGE_BASE, IMAGE_BASE_64, build_pe

CODE_RVA = 0x1000
HANDLE = 0x1234


def emulator(code: bytes, is_64bit: bool = False, directories: dict[int, tuple[int, int]] | None = None):
    sections = [(b".text", CODE_RVA, 0x1000, code, 0xE0000020)]
    packed = build_pe(sections, entry_rva=CODE_RVA, is_64bit=is_64bit, directories=directories)
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

    def test_memory_queries(self):
        emu = emulator(b"\xc3")
        buf = emu.alloc(0x1000)
        ntdll = emu.load_module("ntdll.dll")
        query = API_HANDLERS["VirtualQuery"].func
        assert query(emu, [ntdll.base + 0x1234, buf, 28]) == 28
        base, allocation_base, _, _, state, _, kind = struct.unpack("<7I", emu.read(buf, 28))
        assert (base, allocation_base, state, kind) == (ntdll.base + 0x1000, ntdll.base, 0x1000, 0x1000000)
        # free memory is reported up to the next region
        free = buf + 0x1000
        assert query(emu, [free, buf, 28]) == 28
        base, _, _, size, state, _, _ = struct.unpack("<7I", emu.read(buf, 28))
        assert (base, state) == (free, 0x10000)
        assert base + size == emu.space.next_start(free)
        # a loaded DLL is not free memory
        assert API_HANDLERS["VirtualAlloc"].func(emu, [ntdll.base + 0x2000, 0x1000, 0x3000, 0x40]) == 0
        # patching code in a DLL, as hook installers do
        target = ntdll.exports["NtClose"]
        emu.write(buf, b"\xe9\x11\x22")
        assert API_HANDLERS["WriteProcessMemory"].func(emu, [0xFFFFFFFF, target, buf, 3, buf + 0x10]) == 1
        assert emu.read(target, 3) == b"\xe9\x11\x22"
        assert emu.read_u32(buf + 0x10) == 3

    def test_native_file_mapping(self):
        emu = emulator(b"\xc3")
        buf = emu.alloc(0x1000)
        path = ("\\??\\" + emu.image_path).encode("utf-16-le")
        emu.write(buf + 0x100, path)
        # UNICODE_STRING, then OBJECT_ATTRIBUTES pointing at it
        emu.write(buf + 0x40, struct.pack("<HHI", len(path), len(path), buf + 0x100))
        emu.write(buf + 0x60, struct.pack("<III", 24, 0, buf + 0x40))
        call = lambda name, *args: API_HANDLERS[name].func(emu, list(args))
        assert call("NtOpenFile", buf, 0x80100080, buf + 0x60, buf + 0x10, 3, 0x60) == 0
        file_handle = emu.read_u32(buf)
        assert call("NtCreateSection", buf + 4, 4, 0, 0, 2, 0x8000000, file_handle) == 0
        assert call("NtMapViewOfSection", emu.read_u32(buf + 4), 0xFFFFFFFF, buf + 8, 0, 0, 0, 0, 1, 0, 2) == 0
        view = emu.read_u32(buf + 8)
        assert emu.read(view, len(emu.image_file)) == emu.image_file
        assert API_HANDLERS["VirtualQuery"].func(emu, [view, buf + 0x200, 28]) == 28
        assert emu.read_u32(buf + 0x200 + 24) == 0x40000  # MEM_MAPPED
        emu.write(buf + 0x60, struct.pack("<III", 24, 0, 0))
        assert call("NtOpenFile", buf, 0x80100080, buf + 0x60, buf + 0x10, 3, 0x60) == 0xC0000034

    def test_toolhelp_threads_and_affinity(self):
        emu = emulator(b"\xc3")
        buf = emu.alloc(0x1000)
        call = lambda name, *args: API_HANDLERS[name].func(emu, list(args))
        snapshot = call("CreateToolhelp32Snapshot", 4, 0)  # TH32CS_SNAPTHREAD
        assert snapshot not in (0, 0xFFFFFFFF)
        emu.write_u32(buf, 0x1C)
        assert call("Thread32First", snapshot, buf) == 1
        _, _, tid, pid = struct.unpack("<4I", emu.read(buf, 16))
        assert (tid, pid) == (emu.thread.tid, emu.PID)
        assert call("Thread32Next", snapshot, buf) == 0
        assert call("GetLastError") == 0x12  # ERROR_NO_MORE_FILES
        assert call("CloseHandle", snapshot) == 1
        assert call("Thread32First", snapshot, buf) == 0
        assert call("GetProcessAffinityMask", 0xFFFFFFFF, buf, buf + 4) == 1
        assert struct.unpack("<II", emu.read(buf, 8)) == (0xF, 0xF)


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
    def test_scan_for_dos_stub(self):
        # packers find kernel32 by walking down from an address inside it until the DOS stub's text shows at 0x4E:
        # and ebx, ~0xfff; again: cmp dword [ebx + 0x4e], "This"; je done; sub ebx, 0x100; jmp again; done: ret
        emu = emulator(bytes.fromhex("81e300f0ffff 817b4e54686973 7408 81eb00010000 ebef c3"))
        kernel32 = emu.load_module("kernel32.dll")
        emu.start()
        emu.set_reg("ebx", kernel32.exports["GetProcAddress"])
        assert emu.run(max_blocks=10000).reason is StopReason.RETURNED
        assert emu.reg("ebx") == kernel32.base
        assert pefile.PE(data=kernel32.image).DOS_HEADER.e_lfanew == 0x80

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


class TestExceptions(unittest.TestCase):
    def _single_step(self, stepped: str):
        code = bytearray(0x200)
        main = bytes.fromhex(
            "b9 e8 03 00 00 49 75 fd"  # spin, so the rest runs natively
            "9c 81 0c 24 00 01 00 00 9d" + stepped + "90 c3"  # pushfd; or dword [esp], 0x100; popfd
        )
        code[: len(main)] = main
        cell = IMAGE_BASE + CODE_RVA + 0x100
        # vectored handler: store the exception code and address, continue execution
        code[0x80:0x9E] = (
            bytes.fromhex("8b 44 24 04 8b 08 8b 11 89 15")
            + struct.pack("<I", cell)
            + bytes.fromhex("8b 51 0c 89 15")
            + struct.pack("<I", cell + 4)
            + bytes.fromhex("83 c8 ff c2 04 00")
        ).ljust(0x1E, b"\x90")
        emu = emulator(bytes(code))
        emu.exceptions.vectored.append(IMAGE_BASE + CODE_RVA + 0x80)
        emu.start()
        stop = emu.run(max_blocks=100000)
        assert stop.reason is StopReason.RETURNED
        assert emu.exceptions.count == 1
        assert emu.read_u32(cell) == 0x80000004
        # the trap is taken after the instruction that follows popfd
        assert emu.read_u32(cell + 4) == IMAGE_BASE + CODE_RVA + len(main) - 2

    def test_trap_flag_single_step(self):
        self._single_step("90")

    def test_trap_flag_single_step_over_cpuid(self):
        # protectors time the trap against cpuid, which the native engine does not execute itself
        self._single_step("0f a2")

    def test_x64_try_except(self):
        code = bytearray(0x400)

        def put(offset: int, data: str | bytes) -> None:
            data = bytes.fromhex(data) if isinstance(data, str) else data
            code[offset : offset + len(data)] = data

        # main: sub rsp, 0x28; mov rbx, 0x7777; call faulting; nop; xor eax, eax; add rsp, 0x28; ret
        put(0x00, "48 83 ec 28 48 c7 c3 77 77 00 00 e8 20 00 00 00 90 31 c0 48 83 c4 28 c3")
        # __except block: mov [code], eax; mov [saved_rbx], rbx; add rsp, 0x28; ret
        put(0x18, "89 05 ea 00 00 00 48 89 1d eb 00 00 00 48 83 c4 28 c3")
        # faulting: push rbx; sub rsp, 0x20; mov rbx, 0x1111; xor eax, eax; mov [rax], eax; add rsp, 0x20; pop rbx; ret
        put(0x30, "53 48 83 ec 20 48 c7 c3 11 11 00 00 31 c0 89 00 48 83 c4 20 5b c3")
        put(0x50, "b8 01 00 00 00 c3")  # filter: EXCEPTION_EXECUTE_HANDLER
        put(0x60, "ff 25 9a 00 00 00")  # jmp [__imp___C_specific_handler]
        rva = CODE_RVA
        put(0x200, struct.pack("<6I", rva, rva + 0x2A, rva + 0x300, rva + 0x30, rva + 0x46, rva + 0x340))
        # main: handler flag, sub rsp 0x28; one scope around the call, with a filter
        put(0x300, bytes.fromhex("09 04 01 00 04 42 00 00"))
        put(0x308, struct.pack("<6I", rva + 0x60, 1, rva + 0x0B, rva + 0x11, rva + 0x50, rva + 0x18))
        # faulting: sub rsp 0x20, push rbx
        put(0x340, bytes.fromhex("01 05 02 00 05 32 01 30"))
        emu = emulator(bytes(code), is_64bit=True, directories={3: (rva + 0x200, 24)})
        handler = emu.resolve_export(emu.load_module("ntdll.dll"), "__C_specific_handler")
        assert handler is not None
        base = IMAGE_BASE_64 + rva
        emu.write_ptr(base + 0x100, handler)
        emu.start()
        stop = emu.run(max_blocks=100000)
        assert stop.reason is StopReason.RETURNED
        assert emu.read_u32(base + 0x108) == 0xC0000005
        assert emu.read_ptr(base + 0x110) == 0x7777


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
