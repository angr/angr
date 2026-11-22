#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.unpacker"  # pylint:disable=redefined-builtin

import json
import os
import struct
import tempfile
import unittest
from unittest import mock

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

    def test_current_directory(self):
        emu = emulator(b"\xc3")
        buf = emu.alloc(0x1000)
        call = lambda name, *args: API_HANDLERS[name].func(emu, list(args))
        desktop = "C:\\Users\\admin\\Desktop"
        assert call("GetCurrentDirectoryA", 0x100, buf) == len(desktop)
        assert emu.read_cstr(buf) == desktop
        # too small: the size needed, terminator included
        assert call("GetCurrentDirectoryW", 4, buf) == len(desktop) + 1
        assert call("SetCurrentDirectoryA", emu.alloc_cstr("C:\\Windows\\Temp\\")) == 1
        assert call("SetCurrentDirectoryW", emu.alloc_cstr("..\\System32", wide=True)) == 1
        assert call("GetCurrentDirectoryW", 0x100, buf) == len("C:\\Windows\\System32")
        assert emu.read_wstr(buf) == "C:\\Windows\\System32"
        # the process parameters in the PEB say the same
        for emu64 in (emu, emulator(b"\xc3", True)):
            assert API_HANDLERS["SetCurrentDirectoryA"].func(emu64, [emu64.alloc_cstr("C:\\Windows\\System32")]) == 1
            params = emu64.read_ptr(emu64.peb + (0x20 if emu64.is_64bit else 0x10))
            dos_path = params + (0x38 if emu64.is_64bit else 0x24)
            length, capacity = struct.unpack("<HH", emu64.read(dos_path, 4))
            text = emu64.read(emu64.read_ptr(dos_path + emu64.ptr_size), length).decode("utf-16-le")
            assert (text, capacity) == ("C:\\Windows\\System32\\", 0x208)
        assert call("SetCurrentDirectoryA", emu.alloc_cstr("")) == 0
        assert call("GetLastError") == 123  # ERROR_INVALID_NAME
        length = call("GetTempPathA", 0x100, buf)
        assert length == len(emu.read_cstr(buf)) and emu.read_cstr(buf).endswith("\\Temp\\")

    def test_created_files_read_back(self):
        emu = emulator(b"\xc3")
        buf = emu.alloc(0x1000)
        call = lambda name, *args: API_HANDLERS[name].func(emu, list(args))
        invalid = -1
        create_new, create_always, open_existing = 1, 2, 3
        path = emu.alloc_cstr("C:\\Users\\admin\\AppData\\Local\\Temp\\drop\\Payload.bin")
        assert call("GetFileAttributesA", path) == invalid
        assert call("CreateFileA", path, 0x80000000, 0, 0, open_existing, 0, 0) == invalid
        assert call("GetLastError") == 2  # ERROR_FILE_NOT_FOUND
        assert call("CreateDirectoryA", emu.alloc_cstr("C:\\Users\\admin\\AppData\\Local\\Temp\\drop"), 0) == 1
        assert call("CreateDirectoryA", emu.alloc_cstr("C:\\Users\\admin\\AppData\\Local\\Temp\\drop"), 0) == 0
        assert call("GetLastError") == 183  # ERROR_ALREADY_EXISTS
        handle = call("CreateFileA", path, 0x40000000, 0, 0, create_always, 0, 0)
        assert handle != invalid
        emu.write(buf, b"hello, world")
        assert call("WriteFile", handle, buf, 12, buf + 0x100, 0) == 1
        assert emu.read_u32(buf + 0x100) == 12
        assert call("CloseHandle", handle) == 1
        assert call("CreateFileA", path, 0x40000000, 0, 0, create_new, 0, 0) == invalid
        assert call("GetLastError") == 80  # ERROR_FILE_EXISTS
        # reopened through a relative, differently-cased name
        assert call("SetCurrentDirectoryA", emu.alloc_cstr("C:\\Users\\admin\\AppData\\Local\\Temp")) == 1
        handle = call(
            "CreateFileW", emu.alloc_cstr("drop\\payload.BIN", wide=True), 0x80000000, 0, 0, open_existing, 0, 0
        )
        assert handle != invalid
        assert call("GetFileSize", handle, 0) == 12
        assert call("SetFilePointer", handle, 7, 0, 0) == 7
        assert call("ReadFile", handle, buf + 0x200, 0x100, buf + 0x100, 0) == 1
        assert emu.read(buf + 0x200, emu.read_u32(buf + 0x100)) == b"world"
        assert call("GetFileAttributesA", path) == 0x20
        assert call("GetFileAttributesA", emu.alloc_cstr("drop")) == 0x10
        assert call("GetFileAttributesExA", path, 0, buf) == 1
        assert emu.read_u32(buf + 32) == 12
        # the image itself stays read-only; devices do not appear by being opened
        image = call("CreateFileA", emu.alloc_cstr(emu.image_path), 0xC0000000, 0, 0, open_existing, 0, 0)
        assert call("WriteFile", image, buf, 4, buf + 0x100, 0) == 0
        assert call("CreateFileA", emu.alloc_cstr("\\\\.\\SICE"), 0xC0000000, 0, 0, create_always, 0, 0) == invalid
        # console output succeeds
        assert call("WriteFile", call("GetStdHandle", 0xFFFFFFF5), buf, 5, buf + 0x100, 0) == 1
        assert call("DeleteFileA", path) == 1
        assert call("DeleteFileA", path) == 0
        assert call("GetFileAttributesA", path) == invalid

    def test_native_created_files(self):
        emu = emulator(b"\xc3")
        buf = emu.alloc(0x1000)
        call = lambda name, *args: API_HANDLERS[name].func(emu, list(args))
        name = "\\??\\C:\\Windows\\Temp\\a.tmp".encode("utf-16-le")
        emu.write(buf + 0x100, name)
        emu.write(buf + 0x40, struct.pack("<HHI", len(name), len(name), buf + 0x100))  # UNICODE_STRING
        emu.write(buf, struct.pack("<IIII", 24, 0, buf + 0x40, 0x40))  # OBJECT_ATTRIBUTES
        handle_ptr, io_status, data = buf + 0x80, buf + 0x88, buf + 0x200
        open_args = (handle_ptr, 0x120116, buf, io_status, 0, 0x80, 0, 1, 0x20, 0, 0)  # FILE_OPEN
        assert call("NtCreateFile", *open_args) == 0xC0000034  # STATUS_OBJECT_NAME_NOT_FOUND
        assert call("NtCreateFile", *open_args[:7], 2, *open_args[8:]) == 0  # FILE_CREATE
        assert emu.read_u32(io_status + 4) == 2  # FILE_CREATED
        emu.write(data, b"abcd")
        assert call("NtWriteFile", emu.read_u32(handle_ptr), 0, 0, 0, io_status, data, 4, 0, 0) == 0
        assert call("NtCreateFile", *open_args[:7], 2, *open_args[8:]) == 0xC0000035  # STATUS_OBJECT_NAME_COLLISION
        assert call("NtCreateFile", *open_args) == 0
        assert emu.read_u32(io_status + 4) == 1  # FILE_OPENED
        assert call("NtReadFile", emu.read_u32(handle_ptr), 0, 0, 0, io_status, data + 0x10, 4, 0, 0) == 0
        assert emu.read(data + 0x10, 4) == b"abcd"

    def test_find_files(self):
        emu = emulator(b"\xc3")
        buf = emu.alloc(0x1000)
        call = lambda name, *args: API_HANDLERS[name].func(emu, list(args))
        # nothing found is INVALID_HANDLE_VALUE, not NULL
        assert call("FindFirstFileA", emu.alloc_cstr("C:\\Windows\\System32\\drivers\\vm*.sys"), buf) == -1
        assert call("GetLastError") == 2
        for name in ("a.dat", "B.DAT", "c.txt"):
            handle = call("CreateFileA", emu.alloc_cstr("C:\\Temp\\" + name), 0x40000000, 0, 0, 2, 0, 0)
            assert call("WriteFile", handle, buf, len(name), 0, 0) == 1
        find = call("FindFirstFileW", emu.alloc_cstr("c:\\temp\\*.dat", wide=True), buf)
        assert find != -1
        attributes, size = emu.read_u32(buf), emu.read_u32(buf + 32)
        assert (attributes, size, emu.read_wstr(buf + 44)) == (0x20, 5, "a.dat")
        assert call("FindNextFileW", find, buf) == 1
        assert emu.read_wstr(buf + 44) == "B.DAT"
        assert call("FindNextFileW", find, buf) == 0
        assert call("GetLastError") == 0x12  # ERROR_NO_MORE_FILES
        assert call("FindClose", find) == 1
        # the sample finds itself
        assert call("FindFirstFileA", emu.alloc_cstr(emu.image_path), buf) != -1
        assert emu.read_cstr(buf + 44) == "sample.exe"

    def test_values_that_are_not_zero(self):
        emu = emulator(b"\xc3")
        buf = emu.alloc(0x1000)
        call = lambda name, *args: API_HANDLERS[name].func(emu, list(args))
        assert call("GetUserDefaultUILanguage") == 0x409
        assert call("RtlGetCurrentPeb") == emu.peb
        assert call("GetAdaptersInfo", buf, buf + 0x800) == 232  # ERROR_NO_DATA
        assert call("SHGetSpecialFolderPathA", 0, buf, 0x1A, 0) == 1
        assert emu.read_cstr(buf) == "C:\\Users\\admin\\AppData\\Roaming"
        assert call("SHGetFolderPathW", 0, 0x8024, 0, 0, buf) == 0  # CSIDL_WINDOWS | CSIDL_FLAG_CREATE
        assert emu.read_wstr(buf) == "C:\\Windows"
        assert call("SHGetFolderPathW", 0, 0xEE, 0, 0, buf) == 0x80070057
        # string functions return their destination
        text = emu.alloc_cstr("abcdefgh")
        assert call("lstrcpynA", buf, text, 4) == buf
        assert emu.read(buf, 4) == b"abc\0"
        assert call("lstrcatA", buf, text) == buf
        assert emu.read_cstr(buf) == "abcabcdefgh"
        wide = emu.alloc_cstr("xyz", wide=True)
        assert call("lstrcpyW", buf, wide) == buf and call("lstrcatW", buf, wide) == buf
        assert emu.read_wstr(buf) == "xyzxyz"
        assert call("lstrcpynW", buf, wide, 3) == buf
        assert emu.read_wstr(buf) == "xy"

    def test_environment_variables(self):
        emu = emulator(b"\xc3")
        buf = emu.alloc(0x1000)
        call = lambda name, *args: API_HANDLERS[name].func(emu, list(args))
        name, value = emu.alloc_cstr("WLNumDLLsProt"), emu.alloc_cstr("3")
        assert call("GetEnvironmentVariableA", name, buf, 0x100) == 0
        assert call("GetLastError") == 203  # ERROR_ENVVAR_NOT_FOUND
        assert call("SetEnvironmentVariableA", name, value) == 1
        assert call("GetEnvironmentVariableW", emu.alloc_cstr("wlnumdllsprot", wide=True), buf, 0x100) == 1
        assert emu.read_wstr(buf) == "3"
        # too small: the size needed, terminator included
        assert call("GetEnvironmentVariableA", emu.alloc_cstr("SystemRoot"), buf, 4) == len("C:\\Windows") + 1
        text = "%systemroot%\\x %WLNumDLLsProt% %nothing% 100%"
        expanded = "C:\\Windows\\x 3 %nothing% 100%"
        assert call("ExpandEnvironmentStringsA", emu.alloc_cstr(text), buf, 0x100) == len(expanded) + 1
        assert emu.read_cstr(buf) == expanded
        block = emu.read(call("GetEnvironmentStringsW"), 0x1000).decode("utf-16-le").split("\0\0")[0].split("\0")
        assert "WLNumDLLsProt=3" in block and "SystemRoot=C:\\Windows" in block
        assert call("SetEnvironmentVariableA", name, 0) == 1
        assert call("GetEnvironmentVariableA", name, buf, 0x100) == 0
        assert b"WLNumDLLsProt" not in emu.read(call("GetEnvironmentStrings"), 0x800)

    def test_legacy_file_calls_and_sockets(self):
        emu = emulator(b"\xc3")
        buf = emu.alloc(0x1000)
        call = lambda name, *args: API_HANDLERS[name].func(emu, list(args))
        hfile_error = -1
        missing, own = emu.alloc_cstr("C:\\Temp\\old.dat"), emu.alloc_cstr(emu.image_path)
        assert call("_lopen", missing, 0) == hfile_error
        assert call("OpenFile", missing, buf, 0x4000) == hfile_error  # OF_EXIST
        assert struct.unpack("<H", emu.read(buf + 2, 2))[0] == 2  # nErrCode: ERROR_FILE_NOT_FOUND
        handle = call("_lcreat", missing, 0)
        assert handle != hfile_error
        emu.write(buf, b"0123456789")
        assert call("_lwrite", handle, buf, 10) == 10
        assert call("_llseek", handle, 0xFFFFFFFC, 2) == 6
        assert call("_lread", handle, buf + 0x100, 0x20) == 4
        assert emu.read(buf + 0x100, 4) == b"6789"
        assert call("_lclose", handle) == 0 and call("_lclose", handle) == hfile_error
        assert call("OpenFile", missing, buf, 0x4000) != hfile_error
        assert emu.read_cstr(buf + 8) == "C:\\Temp\\old.dat"
        # the sample opens itself the old way
        handle = call("OpenFile", own, buf, 0)
        assert call("_lread", handle, buf + 0x100, 2) == 2 and emu.read(buf + 0x100, 2) == b"MZ"
        assert call("socket", 2, 1, 6) == -1  # INVALID_SOCKET
        assert call("WSAGetLastError") == 10050

    def test_global_memory_handles(self):
        # GlobalAlloc/LocalAlloc hand out the block's address as its handle; locking it yields the same address
        emu = emulator(b"\xc3")
        handle = API_HANDLERS["GlobalAlloc"].func(emu, [0x2002, 0x100])
        assert handle
        assert API_HANDLERS["GlobalLock"].func(emu, [handle]) == handle
        assert API_HANDLERS["GlobalHandle"].func(emu, [handle]) == handle
        assert API_HANDLERS["GlobalSize"].func(emu, [handle]) >= 0x100
        emu.write(handle, b"data")
        bigger = API_HANDLERS["GlobalReAlloc"].func(emu, [handle, 0x3000, 2])
        assert emu.read(bigger, 4) == b"data"

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

    def test_entry_point_stack(self):
        # the entry point returns into kernel32 and finds BaseThreadInitThunk's frame and arguments where Windows 7
        # puts them: edx = [ebp + 0x60] = entry, [ebp + 8] = PEB
        emu = emulator(b"\xc3")
        emu.start()
        entry = IMAGE_BASE + CODE_RVA
        kernel32 = emu.load_module("kernel32.dll")
        assert kernel32.base < emu.read_u32(emu.sp) < kernel32.base + kernel32.size
        ebp = emu.reg("ebp")
        assert ebp == emu.sp + 8
        assert (emu.reg("edx"), emu.read_u32(ebp + 0x60), emu.read_u32(ebp + 8)) == (entry, entry, emu.peb)
        assert emu.run(max_blocks=1000).reason is StopReason.RETURNED

    def test_stdcall_handlers_pop_their_arguments(self):
        # a handler popping the wrong number of bytes shifts the caller's saved registers
        emu = emulator(b"\xc3")
        for dll, name, nargs in (
            ("kernel32.dll", "SetHandleCount", 1),
            ("kernel32.dll", "HeapDestroy", 1),
            ("kernel32.dll", "VirtualLock", 2),
            ("kernel32.dll", "VirtualUnlock", 2),
            ("user32.dll", "GetLastActivePopup", 1),
        ):
            addr = emu.resolve_export(emu.load_module(dll), name)
            assert addr is not None
            sp = emu.sp
            frame = sp - 4 * (nargs + 1)
            emu.write(frame, struct.pack(f"<{nargs + 1}I", 0x401000, *([0x20] * nargs)))
            emu._set_sp(frame)
            emu._dispatch_api(addr)
            assert emu.sp == sp, name
        assert emu.reg("eax") == 0  # GetLastActivePopup

    def test_stack_pointer_before_start(self):
        # both engines: the main thread is on its own stack as soon as the process exists
        for is_64bit in (False, True):
            emu = emulator(b"\xc3", is_64bit)
            sp = emu.sp
            assert sp == emu.thread.stack_base - 0x2000
            assert emu.space.find(sp) == (emu.thread.stack_base - emu.STACK_SIZE, emu.thread.stack_base)
            emu.write_ptr(sp - emu.ptr_size, 0x1234)
            assert emu.read_ptr(sp - emu.ptr_size) == 0x1234
            emu.start()
            assert sp - 0x80 <= emu.sp < sp

    def test_static_dll_dependencies(self):
        emu = emulator(b"\xc3")
        emu.load_module("shell32.dll")
        assert {"user32.dll", "gdi32.dll", "shlwapi.dll"} <= set(emu.modules)

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


class TestThreads(unittest.TestCase):
    def test_sleep_poll_next_to_a_long_sleeper(self):
        # main: CreateThread(worker); 3 x Sleep(50); cell[1] = GetTickCount(); Sleep(60000); ret
        # worker: Sleep(60000); cell[0] = 1; ret 4
        base = IMAGE_BASE + CODE_RVA
        iat, cell, worker = base + 0x200, base + 0x300, base + 0x80
        p32 = lambda value: struct.pack("<I", value)
        call = lambda idx: b"\xff\x15" + p32(iat + 4 * idx)
        sleep_60s = b"\x68" + p32(60000) + call(0)
        main = (
            b"\x6a\x00\x6a\x00\x6a\x00\x68" + p32(worker) + b"\x6a\x00\x6a\x00" + call(1)
            + b"\xbe" + p32(3) + b"\x6a\x32" + call(0) + b"\x4e\x75\xf5"
            + call(2) + b"\xa3" + p32(cell + 4) + sleep_60s + b"\xc3"
        )  # fmt: skip
        code = bytearray(0x400)
        code[: len(main)] = main
        body = sleep_60s + b"\xc7\x05" + p32(cell) + p32(1) + b"\xc2\x04\x00"
        code[0x80 : 0x80 + len(body)] = body
        emu = emulator(bytes(code))
        kernel32 = emu.load_module("kernel32.dll")
        for idx, name in enumerate(("Sleep", "CreateThread", "GetTickCount")):
            addr = emu.resolve_export(kernel32, name)
            assert addr is not None
            emu.write_u32(iat + 4 * idx, addr)
        start = emu.tick
        emu.start()
        assert emu.run(max_blocks=100000).reason is StopReason.RETURNED
        # each poll takes 50 ms, although the only other thread wakes much later
        assert emu.read_u32(cell + 4) - start == 150 + 16
        # the longer sleep lets the worker wake first, at its own time
        assert emu.read_u32(cell) == 1
        assert emu.tick - start == 150 + 16 + 60000

    def test_timed_wait_takes_its_timeout(self):
        # main: CreateThread(worker); cell[0] = WaitForSingleObject(event, 5000); cell[1] = GetTickCount(); ret
        base = IMAGE_BASE + CODE_RVA
        iat, cell, worker = base + 0x200, base + 0x300, base + 0x80
        p32 = lambda value: struct.pack("<I", value)
        call = lambda idx: b"\xff\x15" + p32(iat + 4 * idx)
        # the worker sleeps past the timeout, or signals the event after 100 ms
        for signals, result, low, high in ((False, 0x102, 5000, 5100), (True, 0, 100, 200)):
            emu = emulator(bytes(0x400))
            event = API_HANDLERS["CreateEventA"].func(emu, [0, 0, 0, 0])
            assert event is not None
            main = (
                b"\x6a\x00\x6a\x00\x6a\x00\x68" + p32(worker) + b"\x6a\x00\x6a\x00" + call(1)
                + b"\x68" + p32(5000) + b"\x68" + p32(event) + call(3) + b"\xa3" + p32(cell)
                + call(2) + b"\xa3" + p32(cell + 4) + b"\xc3"
            )  # fmt: skip
            if signals:
                body = b"\x6a\x64" + call(0) + b"\x68" + p32(event) + call(4) + b"\xc2\x04\x00"
            else:
                body = b"\x68" + p32(60000) + call(0) + b"\xc2\x04\x00"
            emu.write(base, main)
            emu.write(worker, body)
            kernel32 = emu.load_module("kernel32.dll")
            for idx, name in enumerate(("Sleep", "CreateThread", "GetTickCount", "WaitForSingleObject", "SetEvent")):
                addr = emu.resolve_export(kernel32, name)
                assert addr is not None
                emu.write_u32(iat + 4 * idx, addr)
            start = emu.tick
            emu.start()
            assert emu.run(max_blocks=100000).reason is StopReason.RETURNED
            assert emu.read_u32(cell) == result
            assert low <= emu.read_u32(cell + 4) - start < high
        # alone: the wait elapses at once, and the clock shows it
        emu = emulator(b"\xc3")
        event = API_HANDLERS["CreateEventA"].func(emu, [0, 0, 0, 0])
        start = emu.tick
        assert API_HANDLERS["WaitForSingleObject"].func(emu, [event, 3000]) == 0x102
        assert 3000 <= emu.tick - start < 3010
        assert API_HANDLERS["WaitForSingleObject"].func(emu, [event, 0]) == 0x102
        assert emu.tick - start < 3010

    def test_shared_data_time_follows_the_clock(self):
        # 2 x GetTickCount, then copy KUSER_SHARED_DATA's TickCount, InterruptTime and SystemTime (low parts)
        base = IMAGE_BASE + CODE_RVA
        iat, cell = base + 0x200, base + 0x300
        p32 = lambda value: struct.pack("<I", value)
        main = (b"\xff\x15" + p32(iat)) * 2
        for idx, offset in enumerate((0x320, 0x08, 0x14, 0x04)):
            main += b"\xa1" + p32(0x7FFE0000 + offset) + b"\xa3" + p32(cell + 4 * idx)
        emu = emulator(main + b"\xc3")
        addr = emu.resolve_export(emu.load_module("kernel32.dll"), "GetTickCount")
        assert addr is not None
        emu.write_u32(iat, addr)
        assert emu.read_u32(0x7FFE0008) == (emu.tick * 10000) & 0xFFFFFFFF
        start = emu.tick
        emu.start()
        assert emu.run(max_blocks=10000).reason is StopReason.RETURNED
        assert emu.tick == start + 32
        tick_count, interrupt_time, system_time, multiplier = struct.unpack("<4I", emu.read(cell, 16))
        # what a program computes for GetTickCount, in 15.625 ms steps
        assert 0 <= emu.tick - (tick_count * multiplier >> 24) < 16
        assert interrupt_time == (emu.tick * 10000) & 0xFFFFFFFF
        assert system_time == (0x01DB3A0000000000 + emu.tick * 10000) & 0xFFFFFFFF


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

    def test_ntdll_c_runtime_exports(self):
        # ntdll's C runtime exports live in a list of their own
        with tempfile.TemporaryDirectory() as tmpdir:
            for stem, names in (("ntdll", ["NtClose"]), ("ntdllcrt", ["strcspn"])):
                with open(os.path.join(tmpdir, stem + ".json"), "w", encoding="ascii") as f:
                    json.dump(dict.fromkeys(names), f)
            with mock.patch.dict(os.environ, {"ANGR_UNPACKER_EXPORTS": tmpdir}):
                emu = emulator(b"\xc3")
            ntdll = emu.load_module("ntdll.dll")
        pe = pefile.PE(data=ntdll.image)
        names = {sym.name for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols}
        assert {b"NtClose", b"strcspn"} <= names

    def test_handler_names_stay_in_their_own_dll(self):
        export_names = lambda module: {sym.name for sym in pefile.PE(data=module.image).DIRECTORY_ENTRY_EXPORT.symbols}
        lists = {
            "kernel32": {"Sleep": 1, "RegCloseKey": 1},
            "ntdll": {"NtClose": 1},
            "user32": {"MessageBoxA": 4},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            for stem, names in lists.items():
                with open(os.path.join(tmpdir, stem + ".json"), "w", encoding="ascii") as f:
                    json.dump(names, f)
            with mock.patch.dict(os.environ, {"ANGR_UNPACKER_EXPORTS": tmpdir}):
                emu = emulator(b"\xc3")
            kernel32, ntdll = emu.load_module("kernel32.dll"), emu.load_module("ntdll.dll")
            # a DLL with an export list exports that list, not every handler
            assert {b"Sleep", b"RegCloseKey"} <= export_names(kernel32)
            assert not {b"MessageBoxA", b"wsprintfA", b"RegOpenKeyA", b"NtClose"} & export_names(kernel32)
            assert b"NtClose" in export_names(ntdll)
            assert not {b"malloc", b"timeGetTime", b"Sleep"} & export_names(ntdll)
            assert b"MessageBoxA" in export_names(emu.load_module("user32.dll"))
            # kernelbase has no list here, so the handlers still stand in for one
            assert {b"VirtualAlloc", b"MessageBoxA"} <= export_names(emu.load_module("kernelbase.dll"))
        # no export data at all: the handlers are split between ntdll and kernel32, as before
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch.dict(os.environ, {"ANGR_UNPACKER_EXPORTS": tmpdir}):
            emu = emulator(b"\xc3")
        kernel32, ntdll = emu.load_module("kernel32.dll"), emu.load_module("ntdll.dll")
        assert {b"VirtualAlloc", b"Sleep", b"MessageBoxA", b"lstrlenA"} <= export_names(kernel32)
        assert {b"NtClose", b"RtlAllocateHeap", b"memcpy"} <= export_names(ntdll)
        assert b"NtClose" not in export_names(kernel32)

    def test_export_list_file_names(self):
        # a DLL's list is <name without extension>.json, whatever the name looks like
        with tempfile.TemporaryDirectory() as tmpdir:
            for stem, name in (("libwinpthread-1", "pthread_create"), ("pthread.dll", "unreachable")):
                with open(os.path.join(tmpdir, stem + ".json"), "w", encoding="ascii") as f:
                    json.dump({name: None}, f)
            with mock.patch.dict(os.environ, {"ANGR_UNPACKER_EXPORTS": tmpdir}):
                emu = emulator(b"\xc3")
            assert "pthread_create" in emu.load_module("LIBWINPTHREAD-1.DLL").exports
            assert "unreachable" not in emu.load_module("pthread.dll").exports

    def test_shipped_export_lists_are_reachable(self):
        directory = emulator(b"\xc3")._export_db_dir  # pylint:disable=protected-access
        if not os.path.isdir(directory):
            self.skipTest("no export lists installed")
        extensions = (".dll", ".exe", ".sys", ".drv", ".ocx", ".cpl")
        for file_name in os.listdir(directory):
            stem, ext = os.path.splitext(file_name)
            assert ext == ".json", file_name
            stem = stem.removesuffix(".ordinals")
            # the stem is a lower-case module name without its extension, and not an API set (those are redirected)
            assert stem == stem.lower() and not stem.endswith(extensions), file_name
            assert not stem.startswith(("api-ms-", "ext-ms-")), file_name

    def test_static_imports_are_exported(self):
        # a third-party DLL without an export list still exports what the image's import directory names
        idata = bytearray(0x200)
        struct.pack_into("<5I", idata, 0, 0x2080, 0, 0, 0x2100, 0x2080)  # descriptor: ILT = IAT, DLL name
        struct.pack_into("<I", idata, 0x80, 0x20C0)  # ILT entry -> hint/name
        idata[0xC2:0xCF] = b"ThirdParty@@\0"
        idata[0x100:0x10F] = b"thirdparty.dll\0"
        sections = [
            (b".text", CODE_RVA, 0x1000, b"\xc3", 0x60000020),
            (b".idata", 0x2000, 0x200, bytes(idata), 0xC0000040),
        ]
        packed = build_pe(sections, entry_rva=CODE_RVA, directories={1: (0x2000, 0x28)})
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "sample.exe")
            with open(path, "wb") as f:
                f.write(packed)
            emu = GenericUnpackerCore(path, watch_sections=set()).emu
        module = emu.load_module("thirdparty.dll")
        names = {sym.name for sym in pefile.PE(data=module.image).DIRECTORY_ENTRY_EXPORT.symbols}
        assert b"ThirdParty@@" in names


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

    def test_unhandled_exception_filter(self):
        # entry: push 0x1234; call [UnhandledExceptionFilter]; ret
        slot = IMAGE_BASE + CODE_RVA + 0x100
        code = bytearray(0x200)
        code[:12] = b"\x68" + struct.pack("<I", 0x1234) + b"\xff\x15" + struct.pack("<I", slot) + b"\xc3"
        # top-level filter: mov [cell], arg; mov eax, -1 (EXCEPTION_CONTINUE_EXECUTION); ret 4
        cell = slot + 4
        code[0x80:0x92] = bytes.fromhex("8b442404 a3") + struct.pack("<I", cell) + bytes.fromhex("b8ffffffff c20400")
        for top_level, expected in ((0, 1), (IMAGE_BASE + CODE_RVA + 0x80, 0xFFFFFFFF)):
            emu = emulator(bytes(code))
            api = emu.resolve_export(emu.load_module("kernel32.dll"), "UnhandledExceptionFilter")
            assert api is not None
            emu.write_u32(slot, api)
            emu.exceptions.unhandled_filter = top_level
            emu.start()
            assert emu.run(max_blocks=10000).reason is StopReason.RETURNED
            # without a top-level filter: EXCEPTION_EXECUTE_HANDLER; otherwise the filter's verdict
            assert emu.reg("eax") == expected
            assert emu.read_u32(cell) == (0x1234 if top_level else 0)

    def test_trap_flag_single_step(self):
        self._single_step("90")

    def test_trap_flag_single_step_over_cpuid(self):
        # protectors time the trap against cpuid, which the native engine does not execute itself
        self._single_step("0f a2")

    def test_x86_rtl_unwind(self):
        base = IMAGE_BASE + CODE_RVA
        cell, slot, handler_a, handler_b = base + 0x300, base + 0x2F0, base + 0x100, base + 0x120
        p32 = lambda value: struct.pack("<I", value)
        push_frame = lambda handler: b"\x68" + p32(handler) + bytes.fromhex("64ff3500000000 64892500000000")
        main = (
            push_frame(handler_a)
            + bytes.fromhex("89e3")  # mov ebx, esp: the target frame
            + push_frame(handler_b)
            + bytes.fromhex("6a55 6a00")  # ReturnValue, ExceptionRecord
        )
        after = base + len(main) + 1 + 4 + 1 + 6
        main += b"\x68" + p32(after) + b"\x53" + b"\xff\x15" + p32(slot)  # TargetIp, TargetFrame; call [RtlUnwind]
        main += (
            b"\xa3" + p32(cell + 8)  # mov [cell+8], eax
            + bytes.fromhex("64a100000000")  # mov eax, fs:[0]
            + b"\xa3" + p32(cell + 4)
            + b"\x89\x1d" + p32(cell + 16)  # mov [cell+16], ebx
            + bytes.fromhex("8b03 64a300000000 8d6308 c3")  # pop frame A, restore esp, ret
        )  # fmt: skip
        code = bytearray(0x400)
        code[: len(main)] = main
        code[0x100:0x106] = bytes.fromhex("b801000000c3")
        # handler B: record the ExceptionFlags and the call count, return ExceptionContinueSearch
        code[0x120:0x13A] = (
            bytes.fromhex("8b442404 8b4004") + b"\xa3" + p32(cell) + b"\xff\x05" + p32(cell + 12)
            + bytes.fromhex("b801000000 c3")
        )  # fmt: skip
        emu = emulator(bytes(code))
        unwind = emu.resolve_export(emu.load_module("ntdll.dll"), "RtlUnwind")
        assert unwind is not None
        emu.write_ptr(slot, unwind)
        emu.start()
        stop = emu.run(max_blocks=100000)
        assert stop.reason is StopReason.RETURNED
        assert emu.read_u32(cell) & 2  # EXCEPTION_UNWINDING
        assert emu.read_u32(cell + 12) == 1  # only the frame above the target
        assert emu.read_u32(cell + 8) == 0x55
        # the chain now starts at the target frame
        assert emu.read_u32(cell + 4) == emu.read_u32(cell + 16)

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
