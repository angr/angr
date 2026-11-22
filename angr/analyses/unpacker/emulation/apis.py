from __future__ import annotations

import fnmatch
import ntpath
import re
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from angr.errors import SimSegfaultException

from .stops import StopReason
from .threads import EventObject, Thread

if TYPE_CHECKING:
    from .environment import WindowsEmulator

ApiFunc = Callable[["WindowsEmulator", list[int]], "int | None"]

INVALID_HANDLE = -1
STATUS_SUCCESS = 0
STATUS_DATATYPE_MISALIGNMENT = 0x80000002
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
STATUS_ACCESS_VIOLATION = 0xC0000005
STATUS_NO_MEMORY = 0xC0000017
STATUS_INVALID_HANDLE = 0xC0000008
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_END_OF_FILE = 0xC0000011
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
STATUS_OBJECT_NAME_COLLISION = 0xC0000035
STATUS_NOT_IMPLEMENTED = 0xC0000002
STATUS_PORT_NOT_SET = 0xC0000353
STATUS_INVALID_INFO_CLASS = 0xC0000003
STATUS_DLL_NOT_FOUND = 0xC0000135
STATUS_ORDINAL_NOT_FOUND = 0xC0000138
STATUS_ENTRYPOINT_NOT_FOUND = 0xC0000139

_PAGE_PERMS = {0x01: 0, 0x02: 1, 0x04: 3, 0x08: 3, 0x10: 5, 0x20: 5, 0x40: 7, 0x80: 7}
_PERMS_PAGE = {0: 0x01, 1: 0x02, 3: 0x04, 5: 0x20, 7: 0x40, 4: 0x10, 2: 0x04, 6: 0x40}


@dataclass
class ApiHandler:
    """
    A Python implementation of a Windows API.
    """

    func: ApiFunc
    nargs: int
    cdecl: bool = False


API_HANDLERS: dict[str, ApiHandler] = {}


def api(*names: str, nargs: int, cdecl: bool = False) -> Callable[[ApiFunc], ApiFunc]:
    def register(func: ApiFunc) -> ApiFunc:
        for name in names:
            API_HANDLERS[name] = ApiHandler(func, nargs, cdecl)
        return func

    return register


def _const(names: tuple[str, ...], nargs: int, value: int) -> None:
    def handler(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
        return value

    for name in names:
        API_HANDLERS[name] = ApiHandler(handler, nargs)


def page_perms(protect: int) -> int:
    return _PAGE_PERMS.get(protect & 0xFF, 3)


class FileObject:
    """
    An open file: the emulated copy of the sample's own file or a stand-in for a system file (read-only bytes), or a
    file the program created.
    """

    def __init__(self, data: bytes | bytearray):
        self.data = data
        self.pos = 0

    def write(self, data: bytes) -> bool:
        if not isinstance(self.data, bytearray):
            return False
        if self.pos > len(self.data):
            self.data.extend(bytes(self.pos - len(self.data)))
        self.data[self.pos : self.pos + len(data)] = data
        self.pos += len(data)
        return True


class MappingObject:
    """
    A file-mapping handle. A mapping backed by the paging file has one view, which every MapViewOfFile returns.
    """

    def __init__(self, data: bytes, pagefile: bool = False):
        self.data = data
        self.pagefile = pagefile
        self.view = 0


class FindObject:
    """
    A FindFirstFile handle: the remaining matches, as (name, attributes, size).
    """

    def __init__(self, entries: list[tuple[str, int, int]]):
        self.entries = entries


class ToolhelpSnapshot:
    """
    A CreateToolhelp32Snapshot handle: the threads of the emulated process, as (thread id, process id), and the
    processes of the session, as (process id, parent, threads, name), each with a cursor.
    """

    def __init__(self, threads: list[tuple[int, int]], processes: list[tuple[int, int, int, str]]):
        self.threads = threads
        self.processes = processes
        self.pos = 0
        self.process_pos = 0


#
# Memory
#


def _virtual_alloc(emu: WindowsEmulator, addr: int, size: int, protect: int) -> int:
    perms = page_perms(protect)
    if addr:
        base = addr & ~0xFFF
        span = ((addr + size + 0xFFF) & ~0xFFF) - base
        region = emu.space.find(base)
        if region is not None:
            if emu.module_by_base(region[0]) is not None:
                # a loaded DLL is not free memory
                return 0
            if region[0] not in emu.lazy_regions:
                emu.protect(base, span, perms)
            return base
        if emu.space.is_free(base & ~0xFFFF, span):
            return emu.alloc(span, perms, hint=base & ~0xFFFF)
    return emu.alloc(size, perms)


@api("VirtualAlloc", nargs=4)
def virtual_alloc(emu: WindowsEmulator, args: list[int]) -> int:
    return _virtual_alloc(emu, args[0], args[1], args[3])


@api("VirtualAllocEx", nargs=5)
def virtual_alloc_ex(emu: WindowsEmulator, args: list[int]) -> int:
    return _virtual_alloc(emu, args[1], args[2], args[4])


@api("NtAllocateVirtualMemory", "ZwAllocateVirtualMemory", nargs=6)
def nt_allocate_virtual_memory(emu: WindowsEmulator, args: list[int]) -> int:
    size = emu.read_ptr(args[3])
    addr = _virtual_alloc(emu, emu.read_ptr(args[1]), size, args[5])
    emu.write_ptr(args[1], addr)
    emu.write_ptr(args[3], (size + 0xFFF) & ~0xFFF)
    return STATUS_SUCCESS


def _virtual_protect(emu: WindowsEmulator, addr: int, size: int, protect: int, old_ptr: int) -> None:
    # a range that runs into unmapped memory fails as a whole
    for page in range(addr & ~0xFFF, addr + max(size, 1), 0x1000):
        if not emu.is_mapped(page):
            raise SimSegfaultException(page, "unmapped")
    if old_ptr:
        old = emu.perms(addr & ~0xFFF)
        emu.write_u32(old_ptr, _PERMS_PAGE.get(old, 0x04))
    emu.protect(addr, size, page_perms(protect))


@api("VirtualProtect", nargs=4)
def virtual_protect(emu: WindowsEmulator, args: list[int]) -> int:
    _virtual_protect(emu, args[0], args[1], args[2], args[3])
    return 1


@api("VirtualProtectEx", nargs=5)
def virtual_protect_ex(emu: WindowsEmulator, args: list[int]) -> int:
    _virtual_protect(emu, args[1], args[2], args[3], args[4])
    return 1


@api("NtProtectVirtualMemory", "ZwProtectVirtualMemory", nargs=5)
def nt_protect_virtual_memory(emu: WindowsEmulator, args: list[int]) -> int:
    _virtual_protect(emu, emu.read_ptr(args[1]), emu.read_ptr(args[2]), args[3], args[4])
    return STATUS_SUCCESS


def _query_memory(emu: WindowsEmulator, addr: int, buf: int) -> int:
    """
    Write the MEMORY_BASIC_INFORMATION of the region around addr. Returns its size, or 0 for an invalid address.
    """
    addr &= ~0xFFF
    if addr >= emu.space.limit:
        return 0
    region = emu.space.find(addr)
    if region is not None and region[0] <= emu.image_base and addr >= emu.image_base + emu.image_size:
        # the address space is reserved in 64K steps, but the image ends at SizeOfImage
        region = None
    if region is None:
        # MEM_FREE up to the next region
        fields = (addr, 0, 0, emu.space.next_start(addr) - addr, 0x10000, 1, 0)
    else:
        perms = emu.perms(addr) if emu.is_mapped(addr) else emu.lazy_regions.get(region[0], (3, 0))[0]
        protect = _PERMS_PAGE.get(perms, 0x04)
        # MEM_IMAGE, MEM_MAPPED or MEM_PRIVATE
        kind = 0x1000000 if emu.is_image(region[0]) else 0x40000 if region[0] in emu.file_views else 0x20000
        fields = (addr, region[0], protect, region[1] - addr, 0x1000, protect, kind)
    if emu.is_64bit:
        emu.write(buf, struct.pack("<QQIIQIII", fields[0], fields[1], fields[2], 0, fields[3], *fields[4:]))
        return 48
    emu.write(buf, struct.pack("<IIIIIII", *fields))
    return 28


@api("VirtualQuery", nargs=3)
def virtual_query(emu: WindowsEmulator, args: list[int]) -> int:
    return _query_memory(emu, args[0], args[1])


@api("VirtualQueryEx", nargs=4)
def virtual_query_ex(emu: WindowsEmulator, args: list[int]) -> int:
    return _query_memory(emu, args[1], args[2])


@api("NtQueryVirtualMemory", "ZwQueryVirtualMemory", nargs=6)
def nt_query_virtual_memory(emu: WindowsEmulator, args: list[int]) -> int:
    if args[2] != 0:  # only MemoryBasicInformation
        return STATUS_INVALID_INFO_CLASS
    size = 48 if emu.is_64bit else 28
    if args[4] < size:
        return STATUS_INFO_LENGTH_MISMATCH
    if not _query_memory(emu, args[1], args[3]):
        return STATUS_INVALID_PARAMETER
    if args[5]:
        emu.write_ptr(args[5], size)
    return STATUS_SUCCESS


@api("ReadProcessMemory", nargs=5)
def read_process_memory(emu: WindowsEmulator, args: list[int]) -> int:
    size = min(args[3], 1 << 26)
    if emu.space.find(args[1]) is None:
        return 0
    emu.write(args[2], emu.read(args[1], size))
    if args[4]:
        emu.write_ptr(args[4], size)
    return 1


@api("WriteProcessMemory", nargs=5)
def write_process_memory(emu: WindowsEmulator, args: list[int]) -> int:
    size = min(args[3], 1 << 26)
    if emu.space.find(args[1]) is None:
        return 0
    emu.patch(args[1], emu.read(args[2], size))
    if args[4]:
        emu.write_ptr(args[4], size)
    return 1


_const(("VirtualFree", "FlushInstructionCache"), 3, 1)
_const(("VirtualLock", "VirtualUnlock"), 2, 1)
_const(("VirtualFreeEx",), 4, 1)
_const(("NtFreeVirtualMemory", "ZwFreeVirtualMemory"), 4, STATUS_SUCCESS)


@api("KiFastSystemCall", "KiIntSystemCall", nargs=0)
def ki_system_call(emu: WindowsEmulator, args: list[int]) -> None:  # pylint:disable=unused-argument
    # reached from a 32-bit ntdll stub: the stub's caller pushed the arguments above its own return address
    emu.system_call(emu.sp + 4)


@api("HeapAlloc", "RtlAllocateHeap", nargs=3)
def heap_alloc(emu: WindowsEmulator, args: list[int]) -> int:
    return emu.heap_alloc(args[2])


@api("HeapReAlloc", "RtlReAllocateHeap", nargs=4)
def heap_realloc(emu: WindowsEmulator, args: list[int]) -> int:
    return emu.heap_realloc(args[2], args[3])


@api("LocalAlloc", "GlobalAlloc", nargs=2)
def local_alloc(emu: WindowsEmulator, args: list[int]) -> int:
    return emu.heap_alloc(args[1])


@api("HeapSize", "RtlSizeHeap", nargs=3)
def heap_size(emu: WindowsEmulator, args: list[int]) -> int:
    return emu.allocations.get(args[2], 0)


@api("malloc", nargs=1, cdecl=True)
def c_malloc(emu: WindowsEmulator, args: list[int]) -> int:
    return emu.heap_alloc(args[0])


@api("GetProcessHeap", nargs=0)
def get_process_heap(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.process_heap


@api("HeapCreate", nargs=3)
def heap_create(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.new_handle("heap")


@api("HeapFree", "RtlFreeHeap", nargs=3)
def heap_free(emu: WindowsEmulator, args: list[int]) -> int:
    emu.heap_free(args[2])
    return 1


@api("LocalFree", "GlobalFree", nargs=1)
def local_free(emu: WindowsEmulator, args: list[int]) -> int:
    emu.heap_free(args[0])
    return 0


@api("GlobalLock", "LocalLock", "GlobalHandle", "LocalHandle", nargs=1)
def global_lock(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    # memory handles are the blocks' addresses
    return args[0]


_const(("GlobalUnlock", "LocalUnlock"), 1, 0)


@api("GlobalSize", "LocalSize", nargs=1)
def global_size(emu: WindowsEmulator, args: list[int]) -> int:
    return emu.allocations.get(args[0], 0)


@api("GlobalReAlloc", "LocalReAlloc", nargs=3)
def global_realloc(emu: WindowsEmulator, args: list[int]) -> int:
    return emu.heap_realloc(args[0], args[1])


_const(("HeapSetInformation",), 4, 1)
_const(("HeapDestroy",), 1, 1)

#
# Modules
#


def _module_handle(emu: WindowsEmulator, name: str) -> int:
    normalized = emu.normalize_module_name(name)
    if normalized == ntpath.basename(emu.image_path).lower():
        return emu.image_base
    module = emu.modules.get(normalized)
    return module.base if module is not None else 0


@api("GetModuleHandleA", nargs=1)
def get_module_handle_a(emu: WindowsEmulator, args: list[int]) -> int:
    return emu.image_base if args[0] == 0 else _module_handle(emu, emu.read_cstr(args[0]))


@api("GetModuleHandleW", nargs=1)
def get_module_handle_w(emu: WindowsEmulator, args: list[int]) -> int:
    return emu.image_base if args[0] == 0 else _module_handle(emu, emu.read_wstr(args[0]))


@api("GetModuleHandleExA", nargs=3)
def get_module_handle_ex_a(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write_ptr(args[2], emu.image_base if args[1] == 0 else _module_handle(emu, emu.read_cstr(args[1])))
    return 1


@api("GetModuleHandleExW", nargs=3)
def get_module_handle_ex_w(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write_ptr(args[2], emu.image_base if args[1] == 0 else _module_handle(emu, emu.read_wstr(args[1])))
    return 1


def _load_library(emu: WindowsEmulator, name: str) -> int:
    existing = _module_handle(emu, name)
    return existing or emu.load_module(name).base


@api("LoadLibraryA", nargs=1)
def load_library_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _load_library(emu, emu.read_cstr(args[0]))


@api("LoadLibraryW", nargs=1)
def load_library_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _load_library(emu, emu.read_wstr(args[0]))


@api("LoadLibraryExA", nargs=3)
def load_library_ex_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _load_library(emu, emu.read_cstr(args[0]))


@api("LoadLibraryExW", nargs=3)
def load_library_ex_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _load_library(emu, emu.read_wstr(args[0]))


def _read_counted_string(emu: WindowsEmulator, addr: int, wide: bool) -> str:
    length = struct.unpack("<H", emu.read(addr, 2))[0]
    data = emu.read(emu.read_ptr(addr + emu.ptr_size), length)
    return data.decode("utf-16-le", "replace") if wide else data.decode("latin-1")


@api("LdrLoadDll", nargs=4)
def ldr_load_dll(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write_ptr(args[3], _load_library(emu, _read_counted_string(emu, args[2], True)))
    return STATUS_SUCCESS


@api("LdrGetDllHandle", nargs=4)
def ldr_get_dll_handle(emu: WindowsEmulator, args: list[int]) -> int:
    handle = _module_handle(emu, _read_counted_string(emu, args[2], True))
    emu.write_ptr(args[3], handle)
    return STATUS_SUCCESS if handle else STATUS_DLL_NOT_FOUND


def _get_proc_address(emu: WindowsEmulator, base: int, name: str | None, ordinal: int) -> int | None:
    """
    The address of an export by name, or by ordinal if name is None: 0 if the module does not have it, None if base
    is not a module.
    """
    module = emu.module_by_base(base)
    if module is None and base != emu.image_base:
        return None
    if not name and (name is not None or ordinal == 0):
        # no export has an empty name; ordinal 0 is what a null name looks like
        return 0
    if module is None:
        symbol = emu.main.get_symbol(name) if name is not None else None
        return symbol.rebased_addr if symbol is not None else 0
    addr = emu.resolve_export(module, name) if name is not None else emu.resolve_ordinal(module, ordinal)
    return addr or 0


@api("GetProcAddress", nargs=2)
def get_proc_address(emu: WindowsEmulator, args: list[int]) -> int:
    if args[1] < 0x10000:
        addr = _get_proc_address(emu, args[0], None, args[1])
    else:
        addr = _get_proc_address(emu, args[0], emu.read_cstr(args[1]), 0)
    if not addr:
        _set_last_error(emu, ERROR_MOD_NOT_FOUND if addr is None else ERROR_PROC_NOT_FOUND)
    return addr or 0


@api("LdrGetProcedureAddress", nargs=4)
def ldr_get_procedure_address(emu: WindowsEmulator, args: list[int]) -> int:
    name = _read_counted_string(emu, args[1], False) if args[1] else None
    addr = _get_proc_address(emu, args[0], name, args[2])
    emu.write_ptr(args[3], addr or 0)
    if addr:
        return STATUS_SUCCESS
    if addr is None:
        return STATUS_DLL_NOT_FOUND
    return STATUS_ENTRYPOINT_NOT_FOUND if name is not None else STATUS_ORDINAL_NOT_FOUND


def _write_text(emu: WindowsEmulator, buf: int, capacity: int, text: str, wide: bool) -> int:
    text = text[: max(capacity - 1, 0)]
    emu.write(buf, text.encode("utf-16-le") + b"\0\0" if wide else text.encode("latin-1", "replace") + b"\0")
    return len(text)


def _module_path(emu: WindowsEmulator, base: int) -> str:
    module = emu.module_by_base(base)
    return emu.image_path if module is None else "C:\\Windows\\System32\\" + module.name


@api("GetModuleFileNameA", nargs=3)
def get_module_file_name_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _write_text(emu, args[1], args[2], _module_path(emu, args[0]), False)


@api("GetModuleFileNameW", nargs=3)
def get_module_file_name_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _write_text(emu, args[1], args[2], _module_path(emu, args[0]), True)


@api("GetModuleInformation", "K32GetModuleInformation", nargs=4)
def get_module_information(emu: WindowsEmulator, args: list[int]) -> int:
    module = emu.module_by_base(args[1])
    if module is not None:
        fields = (module.base, module.size, 0)
    elif args[1] in (0, emu.image_base):
        fields = (emu.image_base, emu.image_size, emu.project.entry)
    else:
        return 0
    emu.write_ptr(args[2], fields[0])
    emu.write_u32(args[2] + emu.ptr_size, fields[1])
    emu.write_ptr(args[2] + 2 * emu.ptr_size, fields[2])
    return 1


_const(("FreeLibrary", "DisableThreadLibraryCalls"), 1, 1)

#
# Process, thread and system information
#


@api("ExitProcess", "exit", "_exit", nargs=1)
def exit_process(emu: WindowsEmulator, args: list[int]) -> int:
    emu.exit_code = args[0]
    emu.stop(StopReason.EXITED, f"ExitProcess({args[0]:#x})")
    return 0


@api("TerminateProcess", "NtTerminateProcess", "ZwTerminateProcess", nargs=2)
def terminate_process(emu: WindowsEmulator, args: list[int]) -> int:
    if args[0] in (0, (1 << (8 * emu.ptr_size)) - 1):
        emu.exit_code = args[1]
        emu.stop(StopReason.EXITED, f"TerminateProcess({args[1]:#x})")
    return 1


_const(("GetCurrentProcess",), 0, -1)
_const(("GetCurrentThread",), 0, -2)
_const(("IsDebuggerPresent", "GetACP"), 0, 0)
_const(("GetLastActivePopup",), 1, 0)
_const(("GetOEMCP",), 0, 437)
_const(("IsProcessorFeaturePresent",), 1, 1)


@api("CloseHandle", nargs=1)
def close_handle(emu: WindowsEmulator, args: list[int]) -> int:
    return int(emu.handles.pop(args[0], None) is not None)


@api("NtClose", "ZwClose", nargs=1)
def nt_close(emu: WindowsEmulator, args: list[int]) -> int:
    return STATUS_SUCCESS if emu.handles.pop(args[0], None) is not None else STATUS_INVALID_HANDLE


TH32CS_SNAPPROCESS = 0x2
TH32CS_SNAPTHREAD = 0x4
ERROR_NO_MORE_FILES = 0x12
# a plain desktop session with the sample started from Explorer: (pid, parent pid, threads, name)
_EXPLORER_PID = 0x6A8
_PROCESSES = (
    (0, 0, 2, "[System Process]"),
    (4, 0, 96, "System"),
    (0x110, 4, 2, "smss.exe"),
    (0x174, 0x16C, 9, "csrss.exe"),
    (0x1A4, 0x16C, 3, "wininit.exe"),
    (0x1B0, 0x19C, 9, "csrss.exe"),
    (0x1E8, 0x19C, 3, "winlogon.exe"),
    (0x210, 0x1A4, 7, "services.exe"),
    (0x220, 0x1A4, 7, "lsass.exe"),
    (0x2A0, 0x210, 18, "svchost.exe"),
    (0x5F4, 0x210, 12, "spoolsv.exe"),
    (0x680, 0x2A0, 5, "dwm.exe"),
    (_EXPLORER_PID, 0x674, 30, "explorer.exe"),
)


@api("CreateToolhelp32Snapshot", nargs=2)
def create_toolhelp32_snapshot(emu: WindowsEmulator, args: list[int]) -> int:
    threads = [(t.tid, emu.PID) for t in emu.threads if t.alive] if args[0] & TH32CS_SNAPTHREAD else []
    processes: list[tuple[int, int, int, str]] = []
    if args[0] & TH32CS_SNAPPROCESS:
        processes = [*_PROCESSES, (emu.PID, _EXPLORER_PID, len(emu.threads), ntpath.basename(emu.image_path))]
    return emu.new_handle(ToolhelpSnapshot(threads, processes))


def _thread32(emu: WindowsEmulator, args: list[int], first: bool) -> int:
    snapshot = emu.handles.get(args[0])
    if not isinstance(snapshot, ToolhelpSnapshot):
        emu.write_u32(emu.teb + (0x68 if emu.is_64bit else 0x34), 6)  # ERROR_INVALID_HANDLE
        return 0
    if first:
        snapshot.pos = 0
    if snapshot.pos >= len(snapshot.threads) or emu.read_u32(args[1]) < 0x1C:
        emu.write_u32(emu.teb + (0x68 if emu.is_64bit else 0x34), ERROR_NO_MORE_FILES)
        return 0
    tid, pid = snapshot.threads[snapshot.pos]
    snapshot.pos += 1
    # THREADENTRY32: dwSize, cntUsage, th32ThreadID, th32OwnerProcessID, tpBasePri, tpDeltaPri, dwFlags
    emu.write(args[1], struct.pack("<IIIIiiI", 0x1C, 0, tid, pid, 8, 0, 0))
    return 1


@api("Thread32First", nargs=2)
def thread32_first(emu: WindowsEmulator, args: list[int]) -> int:
    return _thread32(emu, args, True)


@api("Thread32Next", nargs=2)
def thread32_next(emu: WindowsEmulator, args: list[int]) -> int:
    return _thread32(emu, args, False)


_const(("SetErrorMode", "OutputDebugStringA", "OutputDebugStringW"), 1, 0)
_const(("InitializeCriticalSection", "DeleteCriticalSection", "EnterCriticalSection", "LeaveCriticalSection",
        "RtlInitializeCriticalSection", "RtlEnterCriticalSection", "RtlLeaveCriticalSection",
        "RtlDeleteCriticalSection"), 1, 0)  # fmt: skip
_const(("InitializeCriticalSectionAndSpinCount",), 2, 1)


@api("SetHandleCount", nargs=1)
def set_handle_count(emu: WindowsEmulator, args: list[int]) -> int:
    # a no-op since Windows NT: returns the requested count
    return args[0]


_const(("InitializeCriticalSectionEx",), 3, 1)
_const(("NtSetInformationThread", "ZwSetInformationThread"), 4, STATUS_SUCCESS)


@api("AddVectoredExceptionHandler", "RtlAddVectoredExceptionHandler", nargs=2)
def add_vectored_exception_handler(emu: WindowsEmulator, args: list[int]) -> int:
    if args[0]:
        emu.exceptions.vectored.insert(0, args[1])
    else:
        emu.exceptions.vectored.append(args[1])
    return args[1]


@api("RemoveVectoredExceptionHandler", "RtlRemoveVectoredExceptionHandler", nargs=1)
def remove_vectored_exception_handler(emu: WindowsEmulator, args: list[int]) -> int:
    if args[0] in emu.exceptions.vectored:
        emu.exceptions.vectored.remove(args[0])
        return 1
    return 0


@api("SetUnhandledExceptionFilter", nargs=1)
def set_unhandled_exception_filter(emu: WindowsEmulator, args: list[int]) -> int:
    previous = emu.exceptions.unhandled_filter
    emu.exceptions.unhandled_filter = args[0]
    return previous


@api("UnhandledExceptionFilter", nargs=1)
def unhandled_exception_filter(emu: WindowsEmulator, args: list[int]) -> int | None:
    """
    Run the top-level filter; without one, or when it declines, the default is EXCEPTION_EXECUTE_HANDLER (no
    debugger attached), so the caller's __except block ends the process.
    """
    top_level = emu.exceptions.unhandled_filter
    if not top_level:
        return 1
    ret_pc = emu.pc

    def after_filter(result: int) -> None:
        emu.set_reg("rax" if emu.is_64bit else "eax", result if result & 0xFFFFFFFF else 1)
        emu._set_pc(ret_pc)

    emu.call_guest(top_level, (args[0],), after_filter)
    return None


@api("RaiseException", nargs=4)
def raise_exception(emu: WindowsEmulator, args: list[int]) -> None:
    count = min(args[2], 15) if args[3] else 0
    info = tuple(emu.read_ptr(args[3] + emu.ptr_size * i) for i in range(count))
    emu.exceptions.dispatch(args[0] & 0xFFFFFFFF, emu.pc, info, args[1])


@api("NtContinue", "ZwContinue", nargs=2)
def nt_continue(emu: WindowsEmulator, args: list[int]) -> None:
    emu.exceptions.restore_context(args[0])


@api("RtlAddFunctionTable", nargs=3)
def rtl_add_function_table(emu: WindowsEmulator, args: list[int]) -> int:
    emu.exceptions.add_function_table(args[0], args[1] & 0xFFFFFFFF, args[2])
    return 1


@api("RtlDeleteFunctionTable", nargs=1)
def rtl_delete_function_table(emu: WindowsEmulator, args: list[int]) -> int:
    emu.exceptions.remove_function_table(args[0])
    return 1


@api("RtlLookupFunctionEntry", nargs=3)
def rtl_lookup_function_entry(emu: WindowsEmulator, args: list[int]) -> int:
    found = emu.exceptions.lookup_function(args[0])
    if found is None:
        return 0
    if args[1]:
        emu.write_ptr(args[1], found[0])
    return found[1]


@api("RtlVirtualUnwind", nargs=8)
def rtl_virtual_unwind(emu: WindowsEmulator, args: list[int]) -> int:
    _, base, pc, entry, context, handler_data, establisher = args[:7]
    regs = emu.exceptions.read_registers(context)
    regs["rip"] = pc
    handler, data, frame = emu.exceptions.virtual_unwind(base, entry, regs)
    emu.exceptions.write_registers(context, regs)
    if handler_data:
        emu.write_ptr(handler_data, data)
    if establisher:
        emu.write_ptr(establisher, frame)
    return handler or 0


@api("RtlCaptureContext", nargs=1)
def rtl_capture_context(emu: WindowsEmulator, args: list[int]) -> int:
    emu.exceptions.write_context(args[0], emu.pc)
    return 0


@api("RtlRestoreContext", nargs=2)
def rtl_restore_context(emu: WindowsEmulator, args: list[int]) -> None:
    emu.exceptions.restore_context(args[0])


@api("RtlUnwindEx", nargs=6)
def rtl_unwind_ex(emu: WindowsEmulator, args: list[int]) -> None:
    emu.exceptions.unwind_to(args[0], args[1], args[3])


@api("RtlUnwind", nargs=4)
def rtl_unwind(emu: WindowsEmulator, args: list[int]) -> None:
    """
    x86: call each SEH handler above target_frame with EXCEPTION_UNWINDING and unlink it, then return to the caller
    with eax = return_value. target_frame 0 unwinds the whole chain (exit unwind).
    """
    target, _, record, return_value = args
    if emu.is_64bit:
        emu.exceptions.unwind_to(target, args[1], return_value)
        return
    ret_pc, ret_sp = emu.pc, emu.sp
    scratch = (ret_sp - 0x1000) & ~0xF
    context, dispatcher = scratch + 0x100, scratch + 0x80
    flags = 2 | (4 if target == 0 else 0)  # EXCEPTION_UNWINDING, EXCEPTION_EXIT_UNWIND
    if record:
        emu.write_u32(record + 4, emu.read_u32(record + 4) | flags)
    else:
        record = scratch + 0x10
        emu.write(record, struct.pack("<IIIII", 0xC0000027, flags, 0, ret_pc, 0))  # STATUS_UNWIND
    emu.exceptions.write_context(context, ret_pc)
    emu.write_u32(context + 0xC4, ret_sp)
    emu.write_u32(context + 0xB0, return_value)

    def finish() -> None:
        emu._set_sp(ret_sp)
        emu._set_pc(ret_pc)
        emu.set_reg("eax", return_value)

    def next_frame(_: int = 0) -> None:
        frame = emu.read_ptr(emu.teb)
        if frame in (target, 0, 0xFFFFFFFF) or (target and frame > target) or emu.space.find(frame) is None:
            finish()
            return

        def unlink(_: int) -> None:
            emu.write_ptr(emu.teb, emu.read_ptr(frame))
            next_frame()

        emu._set_sp(scratch - 0x40)
        emu.call_guest(emu.read_ptr(frame + 4), (record, frame, context, dispatcher), unlink)

    next_frame()


@api("__CxxFrameHandler", "__CxxFrameHandler2", "__CxxFrameHandler3", nargs=4, cdecl=True)
def cxx_frame_handler(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    # catch blocks are not run: a C++ frame passes every exception on (ExceptionContinueSearch)
    return 1


@api("__C_specific_handler", nargs=4)
def c_specific_handler(emu: WindowsEmulator, args: list[int]) -> int | None:
    """
    The language handler behind __try/__except on x64: run the filters of the scopes around the faulting address
    and unwind to the first __except block that accepts the exception. __finally blocks are not run.
    """
    record, establisher, _, dispatcher = args
    if emu.read_u32(record + 4) & 6:  # being unwound
        return 1
    control_pc, base = emu.read_ptr(dispatcher), emu.read_ptr(dispatcher + 8)
    table = emu.read_ptr(dispatcher + 0x38)
    count = min(emu.read_u32(table), 4096)
    scopes = [struct.unpack("<4I", emu.read(table + 4 + 16 * i, 16)) for i in range(count)]
    code = emu.read_u32(record)
    ret_pc = emu.pc
    pointers = emu.exceptions.pointers

    def next_scope(idx: int) -> int | None:
        while idx < count:
            begin, end, handler, target = scopes[idx]
            idx += 1
            if not begin <= control_pc - base < end or target == 0:
                continue
            if handler == 1:
                emu.exceptions.unwind_to(establisher, base + target, code)
                return None

            def after_filter(result: int, idx: int = idx, target: int = target) -> None:
                result &= 0xFFFFFFFF
                if result == 0:
                    disposition = next_scope(idx)
                    if disposition is None:
                        return
                elif result < 0x80000000:
                    emu.exceptions.unwind_to(establisher, base + target, code)
                    return
                else:
                    disposition = 0
                emu.set_reg("rax", disposition)
                emu._set_pc(ret_pc)

            emu.call_guest(base + handler, (pointers, establisher), after_filter)
            return None
        return 1

    return next_scope(0)


SCREEN_RECT = (0, 0, 1024, 768)


@api("GetSystemMetrics", nargs=1)
def get_system_metrics(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    # the screen's size; everything else (remote session, mouse buttons, ...) reads as zero
    return {0: SCREEN_RECT[2], 1: SCREEN_RECT[3]}.get(args[0], 0)


_const(("FindWindowA", "FindWindowW"), 2, 0)
ERROR_ENVVAR_NOT_FOUND = 203
_ENVIRONMENT_REFERENCE_RE = re.compile(r"%([^%=]+)%")


def _get_environment_variable(emu: WindowsEmulator, name: str, buf: int, capacity: int, wide: bool) -> int:
    entry = emu.environment.get(name.upper())
    if entry is None:
        emu.write_u32(emu.teb + (0x68 if emu.is_64bit else 0x34), ERROR_ENVVAR_NOT_FOUND)
        return 0
    value = entry[1]
    # the length written, or the size needed if it does not fit
    if capacity <= len(value):
        return len(value) + 1
    return _write_text(emu, buf, capacity, value, wide)


@api("GetEnvironmentVariableA", nargs=3)
def get_environment_variable_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _get_environment_variable(emu, emu.read_cstr(args[0]), args[1], args[2], False)


@api("GetEnvironmentVariableW", nargs=3)
def get_environment_variable_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _get_environment_variable(emu, emu.read_wstr(args[0]), args[1], args[2], True)


def _set_environment_variable(emu: WindowsEmulator, name: str, value: str | None) -> int:
    if not name or "=" in name[1:]:
        emu.write_u32(emu.teb + (0x68 if emu.is_64bit else 0x34), 87)  # ERROR_INVALID_PARAMETER
        return 0
    if value is None:
        emu.environment.pop(name.upper(), None)
    else:
        emu.environment[name.upper()] = (name, value)
    return 1


@api("SetEnvironmentVariableA", nargs=2)
def set_environment_variable_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _set_environment_variable(emu, emu.read_cstr(args[0]), emu.read_cstr(args[1]) if args[1] else None)


@api("SetEnvironmentVariableW", nargs=2)
def set_environment_variable_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _set_environment_variable(emu, emu.read_wstr(args[0]), emu.read_wstr(args[1]) if args[1] else None)


def _expand_environment_strings(emu: WindowsEmulator, text: str, buf: int, capacity: int, wide: bool) -> int:
    def expand(match: re.Match[str]) -> str:
        entry = emu.environment.get(match.group(1).upper())
        return match.group(0) if entry is None else entry[1]

    expanded = _ENVIRONMENT_REFERENCE_RE.sub(expand, text)
    # counts the terminator
    if buf and capacity > len(expanded):
        _write_text(emu, buf, capacity, expanded, wide)
    return len(expanded) + 1


@api("ExpandEnvironmentStringsA", nargs=3)
def expand_environment_strings_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _expand_environment_strings(emu, emu.read_cstr(args[0], limit=1 << 15), args[1], args[2], False)


@api("ExpandEnvironmentStringsW", nargs=3)
def expand_environment_strings_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _expand_environment_strings(emu, emu.read_wstr(args[0], limit=1 << 15), args[1], args[2], True)


def _environment_block(emu: WindowsEmulator) -> str:
    # NAME=value strings in name order; alloc_cstr adds the terminator that ends the block
    return "".join(f"{name}={value}\0" for _, (name, value) in sorted(emu.environment.items()))


_const(("SetThreadAffinityMask", "SetProcessAffinityMask"), 2, 1)


@api("GetProcessAffinityMask", nargs=3)
def get_process_affinity_mask(emu: WindowsEmulator, args: list[int]) -> int:
    # the four processors GetSystemInfo reports
    emu.write_ptr(args[1], 0xF)
    emu.write_ptr(args[2], 0xF)
    return 1


@api("RtlGetCurrentPeb", nargs=0)
def rtl_get_current_peb(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.peb


@api("GetCurrentProcessId", nargs=0)
def get_current_process_id(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.PID


@api("GetCurrentThreadId", nargs=0)
def get_current_thread_id(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.thread.tid


@api("GetLastError", "RtlGetLastWin32Error", "WSAGetLastError", nargs=0)
def get_last_error(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.read_u32(emu.teb + (0x68 if emu.is_64bit else 0x34))


@api("SetLastError", "RtlSetLastWin32Error", nargs=1)
def set_last_error(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write_u32(emu.teb + (0x68 if emu.is_64bit else 0x34), args[0])
    return 0


@api("CheckRemoteDebuggerPresent", nargs=2)
def check_remote_debugger_present(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write_u32(args[1], 0)
    return 1


def _probe_for_write(emu: WindowsEmulator, addr: int, length: int, alignment: int) -> int | None:
    """
    The kernel's ProbeForWrite on a system call's output pointer: the status the call fails with, or None. Nothing
    is checked for an empty range.
    """
    if not length:
        return None
    if addr & (alignment - 1):
        return STATUS_DATATYPE_MISALIGNMENT
    for page in range(addr & ~0xFFF, addr + length, 0x1000):
        if not emu.is_mapped(page) or not emu.perms(page) & 2:
            return STATUS_ACCESS_VIOLATION
    return None


@api("NtQueryInformationProcess", "ZwQueryInformationProcess", nargs=5)
def nt_query_information_process(emu: WindowsEmulator, args: list[int]) -> int:
    info_class, buf, length, return_length = args[1], args[2], args[3], args[4]
    # the kernel first probes the buffer (aligned as a ULONG) and the length pointer (any address that can be
    # written), then checks the length against the class; protectors pass each kind of bad argument and compare
    # the status to catch faked answers
    status = _probe_for_write(emu, buf, length, 4)
    if status is None and return_length:
        status = _probe_for_write(emu, return_length, 4, 1)
    if status is not None:
        return status
    ptr = emu.ptr_size
    sizes = {0: 6 * ptr, 7: ptr, 0x1E: ptr, 0x1F: 4}
    if info_class not in sizes:
        return STATUS_INVALID_INFO_CLASS
    if length != sizes[info_class]:
        return STATUS_INFO_LENGTH_MISMATCH
    status = STATUS_SUCCESS
    if info_class == 7:  # ProcessDebugPort
        emu.write_ptr(buf, 0)
    elif info_class == 0x1E:  # ProcessDebugObjectHandle
        emu.write_ptr(buf, 0)
        status = STATUS_PORT_NOT_SET
    elif info_class == 0x1F:  # ProcessDebugFlags
        emu.write_u32(buf, 1)
    else:  # ProcessBasicInformation
        emu.write(buf, bytes(length))
        emu.write_ptr(buf + ptr, emu.peb)
        emu.write_ptr(buf + 4 * ptr, emu.PID)
    # the kernel stores the length after the data even on failure; protectors overlap the two to catch fakes
    if return_length:
        emu.write_u32(return_length, length)
    return status


class DebugObject:
    """
    A debug object the program created itself (to count the debug objects of the system through NtQueryObject).
    """


@api("NtCreateDebugObject", "ZwCreateDebugObject", nargs=4)
def nt_create_debug_object(emu: WindowsEmulator, args: list[int]) -> int:
    status = _probe_for_write(emu, args[0], emu.ptr_size, 4)
    if status is not None:
        return status
    emu.write_ptr(args[0], emu.new_handle(DebugObject()))
    return STATUS_SUCCESS


def _object_type_name(obj: object) -> str:
    if isinstance(obj, DebugObject):
        return "DebugObject"
    if isinstance(obj, Thread):
        return "Thread"
    if isinstance(obj, EventObject):
        return "Event"
    if isinstance(obj, FileObject):
        return "File"
    if isinstance(obj, MappingObject):
        return "Section"
    return "Event"


@api("NtQueryObject", "ZwQueryObject", nargs=5)
def nt_query_object(emu: WindowsEmulator, args: list[int]) -> int:
    handle, info_class, buf, length, return_length = args
    status = _probe_for_write(emu, buf, length, 4)
    if status is None and return_length:
        status = _probe_for_write(emu, return_length, 4, 1)
    if status is not None:
        return status
    obj = emu.handles.get(handle)
    if obj is None:
        return STATUS_INVALID_HANDLE
    ptr = emu.ptr_size
    if info_class == 0:  # ObjectBasicInformation: attributes, access, one handle, two references
        data = struct.pack("<IIII", 0, 0x1F0003, 1, 2).ljust(0x38, b"\0")
        if length != len(data):
            return STATUS_INFO_LENGTH_MISMATCH
    elif info_class == 2:  # ObjectTypeInformation: the type's name, then how many objects and handles of it exist
        name = _object_type_name(obj).encode("utf-16-le")
        header = 0x68 if emu.is_64bit else 0x60
        text = buf + header
        string = struct.pack("<HH", len(name), len(name) + 2).ljust(ptr, b"\0") + text.to_bytes(ptr, "little")
        # the program's own object is the only one: a debugger would hold another debug object
        counts = struct.pack("<II", 1, 1) + bytes(16) + struct.pack("<II", 1, 1)
        data = (string + counts).ljust(header, b"\0") + name + b"\0\0"
        data = data.ljust((len(data) + ptr - 1) & ~(ptr - 1), b"\0")
        if return_length:
            emu.write_u32(return_length, len(data))
        if length < len(data):
            return STATUS_INFO_LENGTH_MISMATCH
    else:
        return STATUS_INVALID_INFO_CLASS
    emu.write(buf, data)
    if return_length:
        emu.write_u32(return_length, len(data))
    return STATUS_SUCCESS


@api("GetTickCount", nargs=0)
def get_tick_count(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    emu.tick += 16
    return emu.tick & 0xFFFFFFFF


@api("GetTickCount64", nargs=0)
def get_tick_count64(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    emu.tick += 16
    return emu.tick


# the calls that count as polls of a Sleep loop; they share _sleep()
SLEEP_POLL_APIS = frozenset(("Sleep", "SleepEx"))


def _sleep(emu: WindowsEmulator, milliseconds: int) -> None:
    thread = emu.thread
    thread.wake_tick = emu.sleep_wake_tick(milliseconds)
    emu.set_reg("rax" if emu.is_64bit else "eax", 0)
    if not emu.switch_thread():
        # nothing else to run: the sleep simply elapses
        emu.tick = thread.wake_tick


@api("Sleep", nargs=1)
def sleep(emu: WindowsEmulator, args: list[int]) -> None:
    _sleep(emu, args[0])


@api("SleepEx", nargs=2)
def sleep_ex(emu: WindowsEmulator, args: list[int]) -> None:
    _sleep(emu, args[0])


WAIT_TIMEOUT = 0x102
_MAX_WAITS = 4096


def _wait(emu: WindowsEmulator, handle: int, timeout: int) -> int | None:
    """
    Wait on a handle. Unsatisfied waits make the thread retry the call after other threads ran.
    """
    obj = emu.handles.get(handle)
    thread = emu.thread
    emu.tick += 1
    if isinstance(obj, EventObject):
        ready = obj.signaled
        if ready and not obj.manual:
            obj.signaled = False
    elif isinstance(obj, Thread):
        ready = not obj.alive
    else:
        ready = True
    timeout &= 0xFFFFFFFF
    infinite = timeout == 0xFFFFFFFF
    retried = thread.waits > 0
    thread.wait_handle = None
    thread.timed_wait = False
    if ready or (infinite and thread.waits > _MAX_WAITS):
        thread.waits = 0
        return 0
    if not infinite:
        if not retried:
            # like Sleep, at most a minute
            thread.wake_tick = emu.tick + min(timeout, 60000)
        if emu.tick >= thread.wake_tick:
            thread.waits = 0
            return WAIT_TIMEOUT
        thread.timed_wait = True
    thread.waits += 1
    # not scheduled again until the object is signaled or the timeout has passed
    thread.wait_handle = handle
    if emu.block_thread():
        return None
    thread.waits = 0
    thread.wait_handle = None
    thread.timed_wait = False
    if infinite:
        return 0
    # nothing can signal the object before the timeout: the wait simply elapses
    emu.tick = max(emu.tick, thread.wake_tick)
    return WAIT_TIMEOUT


@api("WaitForSingleObject", nargs=2)
def wait_for_single_object(emu: WindowsEmulator, args: list[int]) -> int | None:
    return _wait(emu, args[0], args[1])


@api("WaitForSingleObjectEx", nargs=3)
def wait_for_single_object_ex(emu: WindowsEmulator, args: list[int]) -> int | None:
    return _wait(emu, args[0], args[1])


@api("WaitForMultipleObjects", nargs=4)
def wait_for_multiple_objects(emu: WindowsEmulator, args: list[int]) -> int | None:
    return _wait(emu, emu.read_ptr(args[1]) if args[0] else 0, args[3])


@api("SetEvent", nargs=1)
def set_event(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    if isinstance(obj, EventObject):
        obj.signaled = True
    return 1


@api("ResetEvent", nargs=1)
def reset_event(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    if isinstance(obj, EventObject):
        obj.signaled = False
    return 1


@api("CreateEventA", "CreateEventW", nargs=4)
def create_event(emu: WindowsEmulator, args: list[int]) -> int:
    return emu.new_handle(EventObject(bool(args[1]), bool(args[2])))


@api("SwitchToThread", "NtYieldExecution", "ZwYieldExecution", nargs=0)
def switch_to_thread(emu: WindowsEmulator, args: list[int]) -> None:  # pylint:disable=unused-argument
    emu.yield_thread(1)


@api("ExitThread", nargs=1)
def exit_thread(emu: WindowsEmulator, args: list[int]) -> None:  # pylint:disable=unused-argument
    emu.exit_thread()


@api("TerminateThread", nargs=2)
def terminate_thread(emu: WindowsEmulator, args: list[int]) -> int:
    target = emu.handles.get(args[0])
    if isinstance(target, Thread) and target is not emu.thread:
        target.alive = False
    return 1


@api("QueryPerformanceCounter", nargs=1)
def query_performance_counter(emu: WindowsEmulator, args: list[int]) -> int:
    emu.tick += 1
    emu.write(args[0], struct.pack("<Q", emu.tick * 10000))
    return 1


@api("QueryPerformanceFrequency", nargs=1)
def query_performance_frequency(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write(args[0], struct.pack("<Q", 10_000_000))
    return 1


@api("GetSystemTimeAsFileTime", nargs=1)
def get_system_time_as_file_time(emu: WindowsEmulator, args: list[int]) -> int:
    emu.tick += 1
    emu.write(args[0], struct.pack("<Q", 0x01DB3A0000000000 + emu.tick * 10000))
    return 0


@api("GetVersion", nargs=0)
def get_version(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return 0x1DB10106


def _version_info(emu: WindowsEmulator, addr: int) -> int:
    emu.write(addr + 4, struct.pack("<IIII", 6, 1, 7601, 2))
    return 1


@api("GetVersionExA", "GetVersionExW", nargs=1)
def get_version_ex(emu: WindowsEmulator, args: list[int]) -> int:
    return _version_info(emu, args[0])


@api("RtlGetVersion", nargs=1)
def rtl_get_version(emu: WindowsEmulator, args: list[int]) -> int:
    _version_info(emu, args[0])
    return STATUS_SUCCESS


@api("GetSystemInfo", "GetNativeSystemInfo", nargs=1)
def get_system_info(emu: WindowsEmulator, args: list[int]) -> int:
    arch = 9 if emu.is_64bit else 0
    top = 0x7FFFFFFEFFFF if emu.is_64bit else 0x7FFEFFFF
    if emu.is_64bit:
        data = struct.pack("<HHIQQQIIIHH", arch, 0, 0x1000, 0x10000, top, 0xF, 4, 8664, 0x10000, 6, 0x3A09)
    else:
        data = struct.pack("<HHIIIIIIIHH", arch, 0, 0x1000, 0x10000, top, 0xF, 4, 586, 0x10000, 6, 0x3A09)
    emu.write(args[0], data)
    return 0


@api("GetCommandLineA", nargs=0)
def get_command_line_a(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.alloc_cstr(emu.cmdline)


@api("GetCommandLineW", nargs=0)
def get_command_line_w(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.alloc_cstr(emu.cmdline, wide=True)


@api("GetStartupInfoA", "GetStartupInfoW", nargs=1)
def get_startup_info(emu: WindowsEmulator, args: list[int]) -> int:
    size = 0x68 if emu.is_64bit else 0x44
    emu.write(args[0], struct.pack("<I", size) + bytes(size - 4))
    return 0


WINDOWS_DIRECTORY = "C:\\Windows"
SYSTEM_DIRECTORY = WINDOWS_DIRECTORY + "\\System32"


@api("GetSystemDirectoryA", nargs=2)
def get_system_directory_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _write_text(emu, args[0], args[1], SYSTEM_DIRECTORY, False)


@api("GetSystemDirectoryW", nargs=2)
def get_system_directory_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _write_text(emu, args[0], args[1], SYSTEM_DIRECTORY, True)


@api("GetWindowsDirectoryA", "GetSystemWindowsDirectoryA", nargs=2)
def get_windows_directory_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _write_text(emu, args[0], args[1], WINDOWS_DIRECTORY, False)


@api("GetWindowsDirectoryW", "GetSystemWindowsDirectoryW", nargs=2)
def get_windows_directory_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _write_text(emu, args[0], args[1], WINDOWS_DIRECTORY, True)


TEMP_DIRECTORY = "C:\\Users\\admin\\AppData\\Local\\Temp"
ERROR_FILE_NOT_FOUND = 2
ERROR_ACCESS_DENIED = 5
ERROR_INVALID_HANDLE = 6
ERROR_FILE_EXISTS = 80
ERROR_INVALID_NAME = 123
ERROR_MOD_NOT_FOUND = 126
ERROR_PROC_NOT_FOUND = 127
ERROR_ALREADY_EXISTS = 183


def _set_last_error(emu: WindowsEmulator, code: int) -> None:
    emu.write_u32(emu.teb + (0x68 if emu.is_64bit else 0x34), code)


def full_path(emu: WindowsEmulator, path: str) -> str:
    """
    The absolute form of a DOS or NT path; relative paths start at the current directory.
    """
    path = path.strip().strip('"').replace("/", "\\")
    if path.startswith(("\\??\\", "\\\\?\\")):
        path = path[4:]
    if not ntpath.splitdrive(path)[0]:
        path = ntpath.join(emu.current_directory, path)
    return ntpath.normpath(path)


def _copy_path(emu: WindowsEmulator, capacity: int, buf: int, text: str, wide: bool) -> int:
    """
    The convention of GetCurrentDirectory and GetTempPath: the length written, or the size needed if it does not fit.
    """
    if capacity <= len(text):
        return len(text) + 1
    return _write_text(emu, buf, capacity, text, wide)


@api("GetCurrentDirectoryA", nargs=2)
def get_current_directory_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _copy_path(emu, args[0], args[1], emu.current_directory, False)


@api("GetCurrentDirectoryW", nargs=2)
def get_current_directory_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _copy_path(emu, args[0], args[1], emu.current_directory, True)


def _set_current_directory(emu: WindowsEmulator, path: str) -> int:
    # every well-formed directory is taken to exist
    if not path.strip():
        _set_last_error(emu, ERROR_INVALID_NAME)
        return 0
    emu.set_current_directory(full_path(emu, path))
    return 1


@api("SetCurrentDirectoryA", nargs=1)
def set_current_directory_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _set_current_directory(emu, emu.read_cstr(args[0]))


@api("SetCurrentDirectoryW", nargs=1)
def set_current_directory_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _set_current_directory(emu, emu.read_wstr(args[0]))


# CSIDL values to directories
_SHELL_FOLDERS = {
    0x00: "C:\\Users\\admin\\Desktop",
    0x05: "C:\\Users\\admin\\Documents",
    0x10: "C:\\Users\\admin\\Desktop",
    0x1A: "C:\\Users\\admin\\AppData\\Roaming",
    0x1C: "C:\\Users\\admin\\AppData\\Local",
    0x23: "C:\\ProgramData",
    0x24: "C:\\Windows",
    0x25: "C:\\Windows\\System32",
    0x26: "C:\\Program Files",
    0x28: "C:\\Users\\admin",
    0x2B: "C:\\Program Files\\Common Files",
}
E_INVALIDARG = 0x80070057


def _shell_folder(emu: WindowsEmulator, csidl: int, buf: int, wide: bool) -> bool:
    folder = _SHELL_FOLDERS.get(csidl & 0xFF)
    if folder is None:
        return False
    _write_text(emu, buf, 260, folder, wide)
    return True


@api("SHGetSpecialFolderPathA", nargs=4)
def sh_get_special_folder_path_a(emu: WindowsEmulator, args: list[int]) -> int:
    return int(_shell_folder(emu, args[2], args[1], False))


@api("SHGetSpecialFolderPathW", nargs=4)
def sh_get_special_folder_path_w(emu: WindowsEmulator, args: list[int]) -> int:
    return int(_shell_folder(emu, args[2], args[1], True))


@api("SHGetFolderPathA", nargs=5)
def sh_get_folder_path_a(emu: WindowsEmulator, args: list[int]) -> int:
    return 0 if _shell_folder(emu, args[1], args[4], False) else E_INVALIDARG


@api("SHGetFolderPathW", nargs=5)
def sh_get_folder_path_w(emu: WindowsEmulator, args: list[int]) -> int:
    return 0 if _shell_folder(emu, args[1], args[4], True) else E_INVALIDARG


@api("GetTempPathA", nargs=2)
def get_temp_path_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _copy_path(emu, args[0], args[1], TEMP_DIRECTORY + "\\", False)


@api("GetTempPathW", nargs=2)
def get_temp_path_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _copy_path(emu, args[0], args[1], TEMP_DIRECTORY + "\\", True)


@api("MessageBoxA", nargs=4)
def message_box_a(emu: WindowsEmulator, args: list[int]) -> int:
    emu.messages.append(f"{emu.read_cstr(args[2])}: {emu.read_cstr(args[1])}")
    return 1


@api("NtRaiseHardError", "ZwRaiseHardError", nargs=6)
def nt_raise_hard_error(emu: WindowsEmulator, args: list[int]) -> int:
    # loaders report a missing DLL or export this way; parameters flagged in the mask are UNICODE_STRING pointers
    count, mask, params = min(args[1], 4), args[2], args[3]
    texts = []
    for idx in range(count if params else 0):
        if mask >> idx & 1:
            string = emu.read_ptr(params + emu.ptr_size * idx)
            length = min(emu.read_u32(string) & 0xFFFF, 2048)
            texts.append(emu.read(emu.read_ptr(string + emu.ptr_size), length).decode("utf-16-le", "replace"))
    if texts:
        emu.messages.append(f"{texts[1]}: {texts[0]}" if len(texts) > 1 else texts[0])
    if args[5]:
        emu.write_u32(args[5], 6)  # ResponseOk
    return STATUS_SUCCESS


@api("MessageBoxW", nargs=4)
def message_box_w(emu: WindowsEmulator, args: list[int]) -> int:
    emu.messages.append(f"{emu.read_wstr(args[2])}: {emu.read_wstr(args[1])}")
    return 1


@api("MessageBoxExA", nargs=5)
def message_box_ex_a(emu: WindowsEmulator, args: list[int]) -> int:
    return message_box_a(emu, args)


@api("MessageBoxExW", nargs=5)
def message_box_ex_w(emu: WindowsEmulator, args: list[int]) -> int:
    return message_box_w(emu, args)


@api("MessageBoxTimeoutA", nargs=6)
def message_box_timeout_a(emu: WindowsEmulator, args: list[int]) -> int:
    return message_box_a(emu, args)


@api("MessageBoxTimeoutW", nargs=6)
def message_box_timeout_w(emu: WindowsEmulator, args: list[int]) -> int:
    return message_box_w(emu, args)


#
# Thread-local storage
#


def _tls_alloc(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    emu.tls_slots.append(0)
    return len(emu.tls_slots) - 1


API_HANDLERS["TlsAlloc"] = ApiHandler(_tls_alloc, 0)
API_HANDLERS["FlsAlloc"] = ApiHandler(_tls_alloc, 1)


@api("TlsGetValue", "FlsGetValue", nargs=1)
def tls_get_value(emu: WindowsEmulator, args: list[int]) -> int:
    return emu.tls_slots[args[0]] if args[0] < len(emu.tls_slots) else 0


@api("TlsSetValue", "FlsSetValue", nargs=2)
def tls_set_value(emu: WindowsEmulator, args: list[int]) -> int:
    if args[0] < len(emu.tls_slots):
        emu.tls_slots[args[0]] = args[1]
        return 1
    return 0


_const(("TlsFree", "FlsFree"), 1, 1)

#
# Files: the sample's own image, stand-ins for a few files every Windows 7 installation has, and the files the
# program creates (kept in memory)
#

CREATE_NEW, CREATE_ALWAYS, OPEN_EXISTING, OPEN_ALWAYS, TRUNCATE_EXISTING = 1, 2, 3, 4, 5
FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ARCHIVE = 0x10, 0x20
INVALID_FILE_ATTRIBUTES = -1
_STD_HANDLE = 0x30
_FILE_TIME = 0x01DB3A0000000000

# protectors probe for these, e.g. read the first two bytes of explorer.exe and expect "MZ"
_WINDOWS_FILES = frozenset(("explorer.exe", "notepad.exe", "regedit.exe", "hh.exe", "winhlp32.exe", "write.exe"))
_SYSTEM32_FILES = frozenset(
    ("cmd.exe", "notepad.exe", "calc.exe", "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
     "smss.exe", "taskmgr.exe", "rundll32.exe", "regsvr32.exe", "conhost.exe", "dllhost.exe", "mspaint.exe")
)  # fmt: skip


def _stub_image(is_64bit: bool) -> bytes:
    """
    Headers of an empty PE image.
    """
    image = bytearray(0x400)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", image, 0x84, 0x8664 if is_64bit else 0x14C)
    struct.pack_into("<HH", image, 0x94, 0xF0 if is_64bit else 0xE0, 0x22 if is_64bit else 0x102)
    struct.pack_into("<H", image, 0x98, 0x20B if is_64bit else 0x10B)
    return bytes(image)


def _system_file(emu: WindowsEmulator, path: str) -> bytes | None:
    """
    The stand-in for a system file, given its absolute path in lower case.
    """
    directory, name = ntpath.split(path)
    windows = WINDOWS_DIRECTORY.lower()
    if directory == windows:
        exists = name in _WINDOWS_FILES
    elif directory in (SYSTEM_DIRECTORY.lower(), windows + "\\syswow64"):
        exists = name in _SYSTEM32_FILES or (name.endswith(".dll") and emu.has_export_list(name))
    else:
        exists = False
    return _stub_image(emu.is_64bit) if exists else None


def _file_data(emu: WindowsEmulator, path: str) -> bytes | bytearray | None:
    """
    The contents of an existing file.
    """
    if ntpath.basename(path).lower() == ntpath.basename(emu.image_path).lower():
        return emu.image_file
    key = full_path(emu, path).lower()
    stored = emu.files.get(key)
    return stored[1] if stored is not None else _system_file(emu, key)


def _is_directory(emu: WindowsEmulator, path: str) -> bool:
    key = full_path(emu, path).lower()
    if key in emu.directories or key == emu.current_directory.lower():
        return True
    # system directories and the ancestors of everything known to exist
    known = (emu.image_path, SYSTEM_DIRECTORY + "\\", TEMP_DIRECTORY + "\\", *(name for name, _ in emu.files.values()))
    return any(name.lower().startswith(key.rstrip("\\") + "\\") for name in known)


def _open_file(emu: WindowsEmulator, path: str) -> int:
    data = _file_data(emu, path)
    return INVALID_HANDLE if data is None else emu.new_handle(FileObject(data))


def _create_file(emu: WindowsEmulator, path: str, disposition: int) -> tuple[int, int]:
    """
    CreateFile on the in-memory files. Returns the handle (or INVALID_HANDLE) and the Win32 error code.
    """
    data = _file_data(emu, path)
    if data is None:
        # devices (\\.\name) and directories cannot be created as files
        creatable = bool(path.strip()) and not path.startswith("\\\\.\\") and not _is_directory(emu, path)
        if disposition in (OPEN_EXISTING, TRUNCATE_EXISTING) or not creatable:
            return INVALID_HANDLE, ERROR_FILE_NOT_FOUND
        name = full_path(emu, path)
        data = bytearray()
        emu.files[name.lower()] = (name, data)
        return emu.new_handle(FileObject(data)), 0
    if disposition == CREATE_NEW:
        return INVALID_HANDLE, ERROR_FILE_EXISTS
    if disposition in (CREATE_ALWAYS, TRUNCATE_EXISTING) and isinstance(data, bytearray):
        del data[:]
    error = ERROR_ALREADY_EXISTS if disposition in (CREATE_ALWAYS, OPEN_ALWAYS) else 0
    return emu.new_handle(FileObject(data)), error


def _create_file_win32(emu: WindowsEmulator, path: str, disposition: int) -> int:
    handle, error = _create_file(emu, path, disposition)
    if error or disposition in (CREATE_ALWAYS, OPEN_ALWAYS):
        _set_last_error(emu, error)
    return handle


@api("CreateFileA", nargs=7)
def create_file_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _create_file_win32(emu, emu.read_cstr(args[0]), args[4])


@api("CreateFileW", nargs=7)
def create_file_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _create_file_win32(emu, emu.read_wstr(args[0]), args[4])


@api("WriteFile", nargs=5)
def write_file(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    size = min(args[2], 1 << 26)
    if isinstance(obj, FileObject):
        if not obj.write(emu.read(args[1], size)):
            _set_last_error(emu, ERROR_ACCESS_DENIED)
            return 0
    elif args[0] != _STD_HANDLE:
        _set_last_error(emu, ERROR_INVALID_HANDLE)
        return 0
    # console output is dropped
    if args[3]:
        emu.write_u32(args[3], size)
    return 1


HFILE_ERROR = -1
OF_PARSE, OF_DELETE, OF_CREATE, OF_EXIST = 0x100, 0x200, 0x1000, 0x4000


@api("_lopen", nargs=2)
def lopen(emu: WindowsEmulator, args: list[int]) -> int:
    return _create_file_win32(emu, emu.read_cstr(args[0]), OPEN_EXISTING)


@api("_lcreat", nargs=2)
def lcreat(emu: WindowsEmulator, args: list[int]) -> int:
    return _create_file_win32(emu, emu.read_cstr(args[0]), CREATE_ALWAYS)


@api("OpenFile", nargs=3)
def open_file(emu: WindowsEmulator, args: list[int]) -> int:
    path, style = emu.read_cstr(args[0]), args[2]
    name = full_path(emu, path).encode("latin-1", "replace")[:127]
    if style & OF_PARSE:
        handle, error = 0, 0
    elif style & OF_DELETE:
        handle, error = (1, 0) if _delete_file(emu, path) else (HFILE_ERROR, ERROR_FILE_NOT_FOUND)
    else:
        handle, error = _create_file(emu, path, CREATE_ALWAYS if style & OF_CREATE else OPEN_EXISTING)
        if handle == INVALID_HANDLE:
            _set_last_error(emu, error)
        else:
            error = 0
            if style & OF_EXIST:
                # only a test: the file is closed again
                emu.handles.pop(handle)
    # OFSTRUCT: cBytes, fFixedDisk, nErrCode, two reserved words, szPathName[128]
    emu.write(args[1], struct.pack("<BBHHH", 136, 1, error, 0, 0) + name.ljust(128, b"\0"))
    return handle


@api("_lread", "_hread", nargs=3)
def lread(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    if not isinstance(obj, FileObject):
        return HFILE_ERROR
    data = bytes(obj.data[obj.pos : obj.pos + args[2]])
    obj.pos += len(data)
    emu.write(args[1], data)
    return len(data)


@api("_lwrite", "_hwrite", nargs=3)
def lwrite(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    size = min(args[2], 1 << 26)
    if not isinstance(obj, FileObject) or not obj.write(emu.read(args[1], size)):
        return HFILE_ERROR
    return size


@api("_llseek", nargs=3)
def llseek(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    if not isinstance(obj, FileObject) or args[2] > 2:
        return HFILE_ERROR
    distance = args[1] - (1 << 32) if args[1] & 0x80000000 else args[1]
    obj.pos = max(0, (0, obj.pos, len(obj.data))[args[2]] + distance)
    return obj.pos


@api("_lclose", nargs=1)
def lclose(emu: WindowsEmulator, args: list[int]) -> int:
    return 0 if isinstance(emu.handles.pop(args[0], None), FileObject) else HFILE_ERROR


INVALID_SOCKET = -1
WSAENETDOWN = 10050


def _no_socket(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    # there is no network
    _set_last_error(emu, WSAENETDOWN)
    return INVALID_SOCKET


API_HANDLERS["socket"] = ApiHandler(_no_socket, 3)
API_HANDLERS["WSASocketA"] = API_HANDLERS["WSASocketW"] = ApiHandler(_no_socket, 6)


@api("SetEndOfFile", nargs=1)
def set_end_of_file(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    if not isinstance(obj, FileObject) or not isinstance(obj.data, bytearray):
        return 0
    del obj.data[obj.pos :]
    obj.data.extend(bytes(obj.pos - len(obj.data)))
    return 1


@api("FlushFileBuffers", nargs=1)
def flush_file_buffers(emu: WindowsEmulator, args: list[int]) -> int:
    return int(isinstance(emu.handles.get(args[0]), FileObject))


def _delete_file(emu: WindowsEmulator, path: str) -> int:
    if emu.files.pop(full_path(emu, path).lower(), None) is not None:
        return 1
    # the running image cannot be deleted
    _set_last_error(emu, ERROR_FILE_NOT_FOUND if _file_data(emu, path) is None else ERROR_ACCESS_DENIED)
    return 0


@api("DeleteFileA", nargs=1)
def delete_file_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _delete_file(emu, emu.read_cstr(args[0]))


@api("DeleteFileW", nargs=1)
def delete_file_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _delete_file(emu, emu.read_wstr(args[0]))


def _create_directory(emu: WindowsEmulator, path: str) -> int:
    if not path.strip():
        _set_last_error(emu, ERROR_INVALID_NAME)
        return 0
    if _is_directory(emu, path) or _file_data(emu, path) is not None:
        _set_last_error(emu, ERROR_ALREADY_EXISTS)
        return 0
    name = full_path(emu, path)
    emu.directories[name.lower()] = name
    return 1


@api("CreateDirectoryA", nargs=2)
def create_directory_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _create_directory(emu, emu.read_cstr(args[0]))


@api("CreateDirectoryW", nargs=2)
def create_directory_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _create_directory(emu, emu.read_wstr(args[0]))


def _file_attributes(emu: WindowsEmulator, path: str) -> tuple[int, int] | None:
    """
    The attributes and size of an existing file or directory.
    """
    data = _file_data(emu, path)
    if data is not None:
        return FILE_ATTRIBUTE_ARCHIVE, len(data)
    if path.strip() and _is_directory(emu, path):
        return FILE_ATTRIBUTE_DIRECTORY, 0
    _set_last_error(emu, ERROR_FILE_NOT_FOUND)
    return None


def _get_file_attributes(emu: WindowsEmulator, path: str) -> int:
    found = _file_attributes(emu, path)
    return INVALID_FILE_ATTRIBUTES if found is None else found[0]


@api("GetFileAttributesA", nargs=1)
def get_file_attributes_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _get_file_attributes(emu, emu.read_cstr(args[0]))


@api("GetFileAttributesW", nargs=1)
def get_file_attributes_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _get_file_attributes(emu, emu.read_wstr(args[0]))


def _get_file_attributes_ex(emu: WindowsEmulator, path: str, buf: int) -> int:
    found = _file_attributes(emu, path)
    if found is None:
        return 0
    # WIN32_FILE_ATTRIBUTE_DATA
    emu.write(buf, struct.pack("<IQQQII", found[0], _FILE_TIME, _FILE_TIME, _FILE_TIME, 0, found[1]))
    return 1


@api("GetFileAttributesExA", nargs=3)
def get_file_attributes_ex_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _get_file_attributes_ex(emu, emu.read_cstr(args[0]), args[2])


@api("GetFileAttributesExW", nargs=3)
def get_file_attributes_ex_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _get_file_attributes_ex(emu, emu.read_wstr(args[0]), args[2])


@api("GetFileSize", nargs=2)
def get_file_size(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    if not isinstance(obj, FileObject):
        return INVALID_HANDLE
    if args[1]:
        emu.write_u32(args[1], 0)
    return len(obj.data)


@api("GetFileSizeEx", nargs=2)
def get_file_size_ex(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    if not isinstance(obj, FileObject):
        return 0
    emu.write(args[1], struct.pack("<Q", len(obj.data)))
    return 1


@api("SetFilePointer", nargs=4)
def set_file_pointer(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    if not isinstance(obj, FileObject):
        return INVALID_HANDLE
    distance = args[1] - (1 << 32) if args[1] & 0x80000000 else args[1]
    origin = (0, obj.pos, len(obj.data))[args[3]] if args[3] < 3 else 0
    obj.pos = max(0, origin + distance)
    return obj.pos & 0xFFFFFFFF


@api("ReadFile", nargs=5)
def read_file(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    if not isinstance(obj, FileObject):
        return 0
    data = bytes(obj.data[obj.pos : obj.pos + args[2]])
    obj.pos += len(data)
    emu.write(args[1], data)
    if args[3]:
        emu.write_u32(args[3], len(data))
    return 1


_MAX_PAGEFILE_MAPPING = 1 << 28


def _create_file_mapping(emu: WindowsEmulator, args: list[int], name: str) -> int:
    obj = emu.handles.get(args[0])
    if isinstance(obj, FileObject):
        return emu.new_handle(MappingObject(bytes(obj.data)))
    if args[0] & 0xFFFFFFFF != 0xFFFFFFFF:
        return 0
    # shared memory backed by the paging file, often named so a second instance can find it
    existing = emu.named_mappings.get(name) if name else None
    if existing is not None:
        _set_last_error(emu, ERROR_ALREADY_EXISTS)
        return emu.new_handle(existing)
    size = (args[3] << 32) | args[4]
    if not 0 < size <= _MAX_PAGEFILE_MAPPING:
        return 0
    mapping = MappingObject(bytes(size), pagefile=True)
    if name:
        emu.named_mappings[name] = mapping
    _set_last_error(emu, 0)
    return emu.new_handle(mapping)


@api("CreateFileMappingA", nargs=6)
def create_file_mapping_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _create_file_mapping(emu, args, emu.read_cstr(args[5]) if args[5] else "")


@api("CreateFileMappingW", nargs=6)
def create_file_mapping_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _create_file_mapping(emu, args, emu.read_wstr(args[5]) if args[5] else "")


@api("MapViewOfFile", nargs=5)
def map_view_of_file(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    if not isinstance(obj, MappingObject):
        return 0
    if obj.pagefile:
        if not obj.view:
            obj.view = emu.alloc(len(obj.data))
        return obj.view
    offset = (args[2] << 32) | args[3]
    data = obj.data[offset : offset + args[4]] if args[4] else obj.data[offset:]
    addr = emu.alloc(max(len(data), 1))
    emu.write(addr, data)
    emu.file_views.add(addr)
    return addr


_const(("UnmapViewOfFile",), 1, 1)


def _find_entries(emu: WindowsEmulator, pattern: str) -> list[tuple[str, int, int]]:
    full = full_path(emu, pattern)
    directory, mask = ntpath.split(full)
    if not set(mask) & set("*?"):
        found = _file_attributes(emu, pattern) if mask else None
        return [] if found is None else [(mask, *found)]
    known = [(emu.image_path, FILE_ATTRIBUTE_ARCHIVE, len(emu.image_file))]
    known += [(name, FILE_ATTRIBUTE_ARCHIVE, len(data)) for name, data in emu.files.values()]
    known += [(name, FILE_ATTRIBUTE_DIRECTORY, 0) for name in emu.directories.values()]
    # "*.*" matches names without a dot too; brackets are ordinary characters
    mask = "*" if mask == "*.*" else mask.lower().replace("[", "[[]")
    return [
        (ntpath.basename(name), attributes, size)
        for name, attributes, size in known
        if ntpath.dirname(name).lower() == directory.lower()
        and fnmatch.fnmatchcase(ntpath.basename(name).lower(), mask)
    ]


def _write_find_data(emu: WindowsEmulator, buf: int, entry: tuple[str, int, int], wide: bool) -> None:
    name, attributes, size = entry
    # WIN32_FIND_DATA: attributes, three times, size, two reserved fields, cFileName[260], cAlternateFileName[14]
    data = struct.pack("<IQQQIIII", attributes, _FILE_TIME, _FILE_TIME, _FILE_TIME, 0, size, 0, 0)
    if wide:
        data += name[:259].encode("utf-16-le").ljust(520, b"\0") + bytes(28)
    else:
        data += name[:259].encode("latin-1", "replace").ljust(260, b"\0") + bytes(14)
    emu.write(buf, data)


def _find_first_file(emu: WindowsEmulator, pattern: str, buf: int, wide: bool) -> int:
    entries = _find_entries(emu, pattern)
    if not entries:
        _set_last_error(emu, ERROR_FILE_NOT_FOUND)
        return INVALID_HANDLE
    _write_find_data(emu, buf, entries.pop(0), wide)
    return emu.new_handle(FindObject(entries))


@api("FindFirstFileA", nargs=2)
def find_first_file_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _find_first_file(emu, emu.read_cstr(args[0]), args[1], False)


@api("FindFirstFileW", nargs=2)
def find_first_file_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _find_first_file(emu, emu.read_wstr(args[0]), args[1], True)


@api("FindFirstFileExA", nargs=6)
def find_first_file_ex_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _find_first_file(emu, emu.read_cstr(args[0]), args[2], False)


@api("FindFirstFileExW", nargs=6)
def find_first_file_ex_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _find_first_file(emu, emu.read_wstr(args[0]), args[2], True)


def _find_next_file(emu: WindowsEmulator, args: list[int], wide: bool) -> int:
    obj = emu.handles.get(args[0])
    if not isinstance(obj, FindObject):
        _set_last_error(emu, ERROR_INVALID_HANDLE)
        return 0
    if not obj.entries:
        _set_last_error(emu, ERROR_NO_MORE_FILES)
        return 0
    _write_find_data(emu, args[1], obj.entries.pop(0), wide)
    return 1


@api("FindNextFileA", nargs=2)
def find_next_file_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _find_next_file(emu, args, False)


@api("FindNextFileW", nargs=2)
def find_next_file_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _find_next_file(emu, args, True)


@api("FindClose", nargs=1)
def find_close(emu: WindowsEmulator, args: list[int]) -> int:
    return int(isinstance(emu.handles.pop(args[0], None), FindObject))


@api("CheckSumMappedFile", nargs=4)
def check_sum_mapped_file(emu: WindowsEmulator, args: list[int]) -> int:
    base, length, header_sum, check_sum = args
    data = emu.read(base, (length + 1) & ~1)
    if data[:2] != b"MZ":
        return 0
    nt = base + struct.unpack_from("<I", data, 0x3C)[0]
    if emu.read(nt, 4) != b"PE\0\0":
        return 0
    # 16-bit ones'-complement sum with end-around carry, as imagehlp's ChkSum
    total = sum(struct.unpack(f"<{len(data) // 2}H", data))
    calc = 0 if total == 0 else (total - 1) % 0xFFFF + 1
    stored = emu.read_u32(nt + 0x58)
    for part in (stored & 0xFFFF, stored >> 16):
        calc = (calc - part if calc & 0xFFFF >= part else ((calc - part) & 0xFFFF) - 1) & 0xFFFFFFFF
    emu.write_u32(header_sum, stored)
    emu.write_u32(check_sum, (calc + length) & 0xFFFFFFFF)
    return nt


def _object_name(emu: WindowsEmulator, attributes: int) -> str:
    """
    The name in an OBJECT_ATTRIBUTES structure.
    """
    name = emu.read_ptr(attributes + 2 * emu.ptr_size) if attributes else 0
    if not name:
        return ""
    length = struct.unpack("<H", emu.read(name, 2))[0]
    return emu.read(emu.read_ptr(name + emu.ptr_size), length).decode("utf-16-le", "replace")


# NtCreateFile dispositions (FILE_SUPERSEDE ... FILE_OVERWRITE_IF) as CreateFile ones
_NT_DISPOSITIONS = (CREATE_ALWAYS, OPEN_EXISTING, CREATE_NEW, OPEN_ALWAYS, TRUNCATE_EXISTING, CREATE_ALWAYS)
FILE_DIRECTORY_FILE = 1


def _nt_open_file(emu: WindowsEmulator, handle_ptr: int, attributes: int, io_status: int, disposition: int) -> int:
    name = _object_name(emu, attributes)
    existed = _file_data(emu, name) is not None
    handle, error = _create_file(emu, name, disposition)
    if handle == INVALID_HANDLE:
        return STATUS_OBJECT_NAME_COLLISION if error == ERROR_FILE_EXISTS else STATUS_OBJECT_NAME_NOT_FOUND
    emu.write_ptr(handle_ptr, handle)
    if io_status:
        emu.write_ptr(io_status, STATUS_SUCCESS)
        # FILE_CREATED, FILE_OVERWRITTEN or FILE_OPENED
        information = 2 if not existed else 3 if disposition in (CREATE_ALWAYS, TRUNCATE_EXISTING) else 1
        emu.write_ptr(io_status + emu.ptr_size, information)
    return STATUS_SUCCESS


@api("NtOpenFile", "ZwOpenFile", nargs=6)
def nt_open_file(emu: WindowsEmulator, args: list[int]) -> int:
    return _nt_open_file(emu, args[0], args[2], args[3], OPEN_EXISTING)


@api("NtCreateFile", "ZwCreateFile", nargs=11)
def nt_create_file(emu: WindowsEmulator, args: list[int]) -> int:
    # directories are not created through here
    creating = args[7] < len(_NT_DISPOSITIONS) and not args[8] & FILE_DIRECTORY_FILE
    return _nt_open_file(emu, args[0], args[2], args[3], _NT_DISPOSITIONS[args[7]] if creating else OPEN_EXISTING)


@api("NtWriteFile", "ZwWriteFile", nargs=9)
def nt_write_file(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    if not isinstance(obj, FileObject):
        return STATUS_INVALID_HANDLE
    if args[7]:
        obj.pos = struct.unpack("<Q", emu.read(args[7], 8))[0]
    size = min(args[6], 1 << 26)
    if not obj.write(emu.read(args[5], size)):
        return STATUS_ACCESS_DENIED
    if args[4]:
        emu.write_ptr(args[4], STATUS_SUCCESS)
        emu.write_ptr(args[4] + emu.ptr_size, size)
    return STATUS_SUCCESS


@api("NtQueryInformationFile", "ZwQueryInformationFile", nargs=5)
def nt_query_information_file(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    if not isinstance(obj, FileObject):
        return STATUS_INVALID_HANDLE
    if args[4] != 5:  # only FileStandardInformation
        return STATUS_INVALID_INFO_CLASS
    if args[3] < 24:
        return STATUS_INFO_LENGTH_MISMATCH
    size = len(obj.data)
    emu.write(args[2], struct.pack("<QQIBBH", (size + 0xFFF) & ~0xFFF, size, 1, 0, 0, 0))
    emu.write_ptr(args[1], STATUS_SUCCESS)
    emu.write_ptr(args[1] + emu.ptr_size, 24)
    return STATUS_SUCCESS


@api("NtReadFile", "ZwReadFile", nargs=9)
def nt_read_file(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    if not isinstance(obj, FileObject):
        return STATUS_INVALID_HANDLE
    if args[7]:
        obj.pos = struct.unpack("<Q", emu.read(args[7], 8))[0]
    data = bytes(obj.data[obj.pos : obj.pos + args[6]])
    if not data and args[6]:
        return STATUS_END_OF_FILE
    obj.pos += len(data)
    emu.write(args[5], data)
    if args[4]:
        emu.write_ptr(args[4], STATUS_SUCCESS)
        emu.write_ptr(args[4] + emu.ptr_size, len(data))
    return STATUS_SUCCESS


@api("NtCreateSection", "ZwCreateSection", nargs=7)
def nt_create_section(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[6])
    if not isinstance(obj, FileObject):
        return STATUS_INVALID_HANDLE
    # SEC_IMAGE: the view is the file laid out as a loaded image
    data = emu.pe.get_memory_mapped_image() if args[5] & 0x1000000 else bytes(obj.data)
    emu.write_ptr(args[0], emu.new_handle(MappingObject(data)))
    return STATUS_SUCCESS


@api("NtMapViewOfSection", "ZwMapViewOfSection", nargs=10)
def nt_map_view_of_section(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    if not isinstance(obj, MappingObject):
        return STATUS_INVALID_HANDLE
    offset = struct.unpack("<Q", emu.read(args[5], 8))[0] if args[5] else 0
    size = emu.read_ptr(args[6]) if args[6] else 0
    data = obj.data[offset : offset + size] if size else obj.data[offset:]
    addr = emu.alloc(max(len(data), 1))
    emu.write(addr, data)
    emu.file_views.add(addr)
    emu.write_ptr(args[2], addr)
    if args[6]:
        emu.write_ptr(args[6], (len(data) + 0xFFF) & ~0xFFF)
    return STATUS_SUCCESS


_const(("NtUnmapViewOfSection", "ZwUnmapViewOfSection"), 2, STATUS_SUCCESS)

#
# Strings
#


@api("lstrlenA", nargs=1)
def lstrlen_a(emu: WindowsEmulator, args: list[int]) -> int:
    return len(emu.read_cstr(args[0], limit=1 << 16))


@api("lstrlenW", nargs=1)
def lstrlen_w(emu: WindowsEmulator, args: list[int]) -> int:
    return len(emu.read_wstr(args[0], limit=1 << 16))


@api("lstrcpyA", nargs=2)
def lstrcpy_a(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write(args[0], emu.read_cstr(args[1], limit=1 << 16).encode("latin-1") + b"\0")
    return args[0]


@api("lstrcpyW", nargs=2)
def lstrcpy_w(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write(args[0], emu.read_wstr(args[1], limit=1 << 16).encode("utf-16-le") + b"\0\0")
    return args[0]


@api("lstrcpynA", nargs=3)
def lstrcpyn_a(emu: WindowsEmulator, args: list[int]) -> int:
    if args[2]:
        emu.write(args[0], emu.read_cstr(args[1], limit=args[2] - 1)[: args[2] - 1].encode("latin-1") + b"\0")
    return args[0]


@api("lstrcpynW", nargs=3)
def lstrcpyn_w(emu: WindowsEmulator, args: list[int]) -> int:
    if args[2]:
        emu.write(args[0], emu.read_wstr(args[1], limit=args[2] - 1)[: args[2] - 1].encode("utf-16-le") + b"\0\0")
    return args[0]


@api("lstrcatA", nargs=2)
def lstrcat_a(emu: WindowsEmulator, args: list[int]) -> int:
    end = args[0] + len(emu.read_cstr(args[0], limit=1 << 16))
    emu.write(end, emu.read_cstr(args[1], limit=1 << 16).encode("latin-1") + b"\0")
    return args[0]


@api("lstrcatW", nargs=2)
def lstrcat_w(emu: WindowsEmulator, args: list[int]) -> int:
    end = args[0] + 2 * len(emu.read_wstr(args[0], limit=1 << 16))
    emu.write(end, emu.read_wstr(args[1], limit=1 << 16).encode("utf-16-le") + b"\0\0")
    return args[0]


@api("lstrcmpiA", "lstrcmpA", nargs=2)
def lstrcmpi_a(emu: WindowsEmulator, args: list[int]) -> int:
    left, right = emu.read_cstr(args[0]).lower(), emu.read_cstr(args[1]).lower()
    return 0 if left == right else (1 if left > right else -1)


_FORMAT_RE = re.compile(r"%([-+ #0]*)(\*|\d+)?(?:\.(\*|\d+))?(hh|h|ll|l|I64|I32|w|L)?([diuxXcCsSpn%])")


def _call_arg(emu: WindowsEmulator, index: int) -> int:
    """
    The index-th argument of the API call being handled, for variadic calls.
    """
    if emu.is_64bit:
        if index < 4:
            return emu.reg(("rcx", "rdx", "r8", "r9")[index])
        return emu.read_ptr(emu.sp + 0x20 + 8 * (index - 4))
    return emu.read_ptr(emu.sp + 4 * index)


def _format(emu: WindowsEmulator, fmt: str, next_arg: Callable[[], int], wide: bool) -> str:
    """
    printf-style formatting with arguments pulled from the guest.
    """
    bits = 8 * emu.ptr_size

    def convert(match: re.Match[str]) -> str:
        flags, width, precision, size, conv = match.groups()
        if conv == "%":
            return "%"
        pad = next_arg() if width == "*" else int(width or 0)
        limit = next_arg() if precision == "*" else (int(precision) if precision is not None else None)
        value = next_arg()
        if conv == "n":
            return ""
        if conv in "sS":
            is_wide = size in ("l", "w") or (size != "h" and wide != (conv == "S"))
            if value == 0:
                text = "(null)"
            else:
                text = emu.read_wstr(value, limit=1 << 16) if is_wide else emu.read_cstr(value, limit=1 << 16)
            text = text if limit is None else text[:limit]
        elif conv in "cC":
            text = chr(value & (0xFFFF if wide else 0xFF))
        else:
            if size in ("ll", "I64"):
                if not emu.is_64bit:
                    value |= next_arg() << 32
                int_bits = 64
            else:
                int_bits = bits if conv == "p" else 32
            value &= (1 << int_bits) - 1
            if conv in "di" and value >> (int_bits - 1):
                value -= 1 << int_bits
            if conv == "p":
                text = f"{value:0{bits // 4}X}"
            elif conv in "xX":
                text = ("0x" if "#" in flags and value else "") + format(value, conv)
            else:
                text = ("+" if "+" in flags and value >= 0 and conv != "u" else "") + str(value)
            if limit is not None:
                text = text.rjust(limit, "0")
            elif "0" in flags and "-" not in flags:
                return text.rjust(pad, "0")
        return text.ljust(pad) if "-" in flags else text.rjust(pad)

    return _FORMAT_RE.sub(convert, fmt)


def _sprintf(
    emu: WindowsEmulator, buf: int, fmt_ptr: int, first: int, wide: bool, va_list: int | None = None,
    capacity: int | None = None,
) -> int:  # fmt: skip
    """
    Format into buf. Arguments come from the call (starting at index `first`) or from a va_list.
    """
    position = [0]

    def next_arg() -> int:
        idx = position[0]
        position[0] += 1
        return emu.read_ptr(va_list + emu.ptr_size * idx) if va_list is not None else _call_arg(emu, first + idx)

    fmt = emu.read_wstr(fmt_ptr, limit=1 << 16) if wide else emu.read_cstr(fmt_ptr, limit=1 << 16)
    text = _format(emu, fmt, next_arg, wide)
    if capacity is not None:
        text = text[: max(capacity - 1, 0)]
    emu.write(buf, text.encode("utf-16-le") + b"\0\0" if wide else text.encode("latin-1", "replace") + b"\0")
    return len(text)


@api("wsprintfA", "sprintf", nargs=2, cdecl=True)
def sprintf_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _sprintf(emu, args[0], args[1], 2, False)


@api("wsprintfW", "swprintf", nargs=2, cdecl=True)
def sprintf_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _sprintf(emu, args[0], args[1], 2, True)


@api("wvsprintfA", nargs=3)
def wvsprintf_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _sprintf(emu, args[0], args[1], 0, False, va_list=args[2])


@api("wvsprintfW", nargs=3)
def wvsprintf_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _sprintf(emu, args[0], args[1], 0, True, va_list=args[2])


@api("vsprintf", nargs=3, cdecl=True)
def vsprintf(emu: WindowsEmulator, args: list[int]) -> int:
    return _sprintf(emu, args[0], args[1], 0, False, va_list=args[2])


@api("_snprintf", "sprintf_s", nargs=3, cdecl=True)
def snprintf(emu: WindowsEmulator, args: list[int]) -> int:
    return _sprintf(emu, args[0], args[2], 3, False, capacity=args[1])


@api("_snwprintf", "swprintf_s", nargs=3, cdecl=True)
def snwprintf(emu: WindowsEmulator, args: list[int]) -> int:
    return _sprintf(emu, args[0], args[2], 3, True, capacity=args[1])


@api("_vsnprintf", "vsprintf_s", nargs=4, cdecl=True)
def vsnprintf(emu: WindowsEmulator, args: list[int]) -> int:
    return _sprintf(emu, args[0], args[2], 0, False, va_list=args[3], capacity=args[1])


@api("_vsnwprintf", "vswprintf_s", nargs=4, cdecl=True)
def vsnwprintf(emu: WindowsEmulator, args: list[int]) -> int:
    return _sprintf(emu, args[0], args[2], 0, True, va_list=args[3], capacity=args[1])


#
# Time, synchronization, registry and CRT startup helpers
#


@api("timeGetTime", nargs=0)
def time_get_time(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    # WinLicense rejects a timer that changes on every poll of its virtualized loop
    return emu.clock_ms() & 0xFFFFFFFF


@api("GetLocalTime", "GetSystemTime", nargs=1)
def get_local_time(emu: WindowsEmulator, args: list[int]) -> int:
    emu.tick += 16
    seconds = emu.tick // 1000
    emu.write(args[0], struct.pack("<8H", 2024, 11, 2, 19, 10, (seconds // 60) % 60, seconds % 60, emu.tick % 1000))
    return 0


@api("NtDelayExecution", "ZwDelayExecution", nargs=2)
def nt_delay_execution(emu: WindowsEmulator, args: list[int]) -> None:  # pylint:disable=unused-argument
    emu.tick += 50
    emu.yield_thread(STATUS_SUCCESS)


@api("NtQuerySystemInformation", "ZwQuerySystemInformation", "RtlGetNativeSystemInformation", nargs=4)
def nt_query_system_information(emu: WindowsEmulator, args: list[int]) -> int:
    info_class, buf, length, ret_length = args
    if info_class == 0:  # SystemBasicInformation
        top = 0x7FFFFFFEFFFF if emu.is_64bit else 0x7FFEFFFF
        ptr_fmt = "Q" if emu.is_64bit else "I"
        data = struct.pack(
            "<7I3" + ptr_fmt + "B", 0, 156250, 0x1000, 0x100000, 1, 0x100000, 0x10000, 0x10000, top, 0xF, 4
        )
        data = data.ljust(0x40 if emu.is_64bit else 0x2C, b"\0")
    elif info_class == 0x23:  # SystemKernelDebuggerInformation: not enabled, not present
        data = b"\x00\x01"
    elif info_class == 0xB:  # SystemModuleInformation: no drivers
        data = bytes(16)
    else:
        data = bytes(min(length, 0x1000))
    if ret_length:
        emu.write_u32(ret_length, len(data))
    if length < len(data):
        return STATUS_INFO_LENGTH_MISMATCH
    emu.write(buf, data)
    return STATUS_SUCCESS


_const(("NtSetInformationProcess", "ZwSetInformationProcess"), 4, STATUS_SUCCESS)


@api("NtQueryInformationThread", "ZwQueryInformationThread", nargs=5)
def nt_query_information_thread(emu: WindowsEmulator, args: list[int]) -> int:
    info_class, buf, length = args[1], args[2], args[3]
    if info_class == 0x11:  # ThreadHideFromDebugger: report that hiding took effect
        data = b"\x01"
    elif info_class == 0:  # ThreadBasicInformation
        ptr = emu.ptr_size
        data = bytearray(6 * ptr)
        data[ptr : 2 * ptr] = emu.teb.to_bytes(ptr, "little")
        data[2 * ptr : 3 * ptr] = emu.PID.to_bytes(ptr, "little")
        data[3 * ptr : 4 * ptr] = emu.thread.tid.to_bytes(ptr, "little")
        data = bytes(data)
    else:
        data = bytes(min(length, 0x100))
    if length < len(data):
        return STATUS_INFO_LENGTH_MISMATCH
    emu.write(buf, data)
    if args[4]:
        emu.write_u32(args[4], len(data))
    return STATUS_SUCCESS


_const(("NtQueryPerformanceCounter",), 2, STATUS_SUCCESS)

# registry: empty, except for the keys and values the sample creates itself (trial bookkeeping reads them back)
ERROR_MORE_DATA = 234


class RegistryKey:
    """
    An open registry key: (predefined root, lower-case path).
    """

    def __init__(self, key: tuple[int, str]):
        self.key = key


def _registry_key(emu: WindowsEmulator, parent: int, subkey: int, wide: bool) -> tuple[int, str] | None:
    path = (emu.read_wstr(subkey) if wide else emu.read_cstr(subkey)) if subkey else ""
    opened = emu.handles.get(parent)
    if isinstance(opened, RegistryKey):
        root, base = opened.key
        path = base + "\\" + path
    elif parent & 0xFFFFFFFF in (0x80000000, 0x80000001, 0x80000002, 0x80000003, 0x80000005):
        root = parent & 0xFFFFFFFF
    else:
        return None
    return root, "\\".join(part for part in path.lower().split("\\") if part)


def _reg_open(emu: WindowsEmulator, parent: int, subkey: int, result: int, wide: bool, create: bool) -> int:
    key = _registry_key(emu, parent, subkey, wide)
    if key is None:
        return ERROR_INVALID_HANDLE
    if key not in emu.registry:
        if not create:
            return ERROR_FILE_NOT_FOUND
        emu.registry[key] = {}
    emu.write_ptr(result, emu.new_handle(RegistryKey(key)))
    return 0


@api("RegOpenKeyA", nargs=3)
def reg_open_key_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_open(emu, args[0], args[1], args[2], False, False)


@api("RegOpenKeyW", nargs=3)
def reg_open_key_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_open(emu, args[0], args[1], args[2], True, False)


@api("RegOpenKeyExA", nargs=5)
def reg_open_key_ex_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_open(emu, args[0], args[1], args[4], False, False)


@api("RegOpenKeyExW", nargs=5)
def reg_open_key_ex_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_open(emu, args[0], args[1], args[4], True, False)


@api("RegCreateKeyA", nargs=3)
def reg_create_key_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_open(emu, args[0], args[1], args[2], False, True)


@api("RegCreateKeyW", nargs=3)
def reg_create_key_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_open(emu, args[0], args[1], args[2], True, True)


def _reg_create_ex(emu: WindowsEmulator, args: list[int], wide: bool) -> int:
    key = _registry_key(emu, args[0], args[1], wide)
    existed = key in emu.registry
    status = _reg_open(emu, args[0], args[1], args[7], wide, True)
    if status == 0 and args[8]:
        emu.write_u32(args[8], 2 if existed else 1)  # REG_OPENED_EXISTING_KEY, REG_CREATED_NEW_KEY
    return status


@api("RegCreateKeyExA", nargs=9)
def reg_create_key_ex_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_create_ex(emu, args, False)


@api("RegCreateKeyExW", nargs=9)
def reg_create_key_ex_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_create_ex(emu, args, True)


def _reg_values(emu: WindowsEmulator, handle: int) -> dict[str, tuple[int, bytes]] | None:
    opened = emu.handles.get(handle)
    return emu.registry.get(opened.key) if isinstance(opened, RegistryKey) else None


def _reg_set(emu: WindowsEmulator, args: list[int], wide: bool) -> int:
    values = _reg_values(emu, args[0])
    if values is None:
        return ERROR_INVALID_HANDLE
    name = (emu.read_wstr(args[1]) if wide else emu.read_cstr(args[1])) if args[1] else ""
    values[name.lower()] = (args[3], emu.read(args[4], min(args[5], 1 << 20)))
    return 0


@api("RegSetValueExA", nargs=6)
def reg_set_value_ex_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_set(emu, args, False)


@api("RegSetValueExW", nargs=6)
def reg_set_value_ex_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_set(emu, args, True)


def _reg_query(emu: WindowsEmulator, args: list[int], wide: bool) -> int:
    values = _reg_values(emu, args[0])
    if values is None:
        return ERROR_INVALID_HANDLE
    name = (emu.read_wstr(args[1]) if wide else emu.read_cstr(args[1])) if args[1] else ""
    value = values.get(name.lower())
    if value is None:
        return ERROR_FILE_NOT_FOUND
    kind, data = value
    if args[2]:
        emu.write_u32(args[2], kind)
    if not args[4]:
        return 0
    capacity = emu.read_u32(args[4])
    emu.write_u32(args[4], len(data))
    if args[3]:
        if capacity < len(data):
            return ERROR_MORE_DATA
        emu.write(args[3], data)
    return 0


@api("RegQueryValueExA", nargs=6)
def reg_query_value_ex_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_query(emu, [args[0], args[1], args[3], args[4], args[5]], False)


@api("RegQueryValueExW", nargs=6)
def reg_query_value_ex_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_query(emu, [args[0], args[1], args[3], args[4], args[5]], True)


@api("RegCloseKey", nargs=1)
def reg_close_key(emu: WindowsEmulator, args: list[int]) -> int:
    emu.handles.pop(args[0], None)
    return 0


ERROR_NO_MORE_ITEMS = 259


def _reg_name(emu: WindowsEmulator, buf: int, size_ptr: int, name: str, wide: bool) -> int:
    """
    Store an enumerated name; the size is in characters, without the terminator on return.
    """
    capacity = emu.read_u32(size_ptr)
    if capacity <= len(name):
        return ERROR_MORE_DATA
    _write_text(emu, buf, capacity, name, wide)
    emu.write_u32(size_ptr, len(name))
    return 0


def _reg_enum_value(emu: WindowsEmulator, args: list[int], wide: bool) -> int:
    values = _reg_values(emu, args[0])
    if values is None:
        return ERROR_INVALID_HANDLE
    if args[1] >= len(values):
        return ERROR_NO_MORE_ITEMS
    # names are kept in lower case
    name, (kind, data) = list(values.items())[args[1]]
    status = _reg_name(emu, args[2], args[3], name, wide)
    if status:
        return status
    if args[5]:
        emu.write_u32(args[5], kind)
    if args[7]:
        capacity = emu.read_u32(args[7])
        emu.write_u32(args[7], len(data))
        if args[6]:
            if capacity < len(data):
                return ERROR_MORE_DATA
            emu.write(args[6], data)
    return 0


@api("RegEnumValueA", nargs=8)
def reg_enum_value_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_enum_value(emu, args, False)


@api("RegEnumValueW", nargs=8)
def reg_enum_value_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_enum_value(emu, args, True)


def _reg_subkeys(emu: WindowsEmulator, key: tuple[int, str]) -> list[str]:
    root, path = key
    prefix = path + "\\" if path else ""
    names = {
        other[len(prefix) :].split("\\")[0]
        for other_root, other in emu.registry
        if other_root == root and other != path and other.startswith(prefix)
    }
    return sorted(names)


def _reg_enum_key(emu: WindowsEmulator, handle: int, index: int, buf: int, size_ptr: int, wide: bool) -> int:
    opened = emu.handles.get(handle)
    if not isinstance(opened, RegistryKey):
        # a predefined root (or anything else): the registry has no keys but the sample's own
        return ERROR_NO_MORE_ITEMS
    subkeys = _reg_subkeys(emu, opened.key)
    if index >= len(subkeys):
        return ERROR_NO_MORE_ITEMS
    return _reg_name(emu, buf, size_ptr, subkeys[index], wide)


@api("RegEnumKeyExA", nargs=8)
def reg_enum_key_ex_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_enum_key(emu, args[0], args[1], args[2], args[3], False)


@api("RegEnumKeyExW", nargs=8)
def reg_enum_key_ex_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_enum_key(emu, args[0], args[1], args[2], args[3], True)


def _reg_enum_key_plain(emu: WindowsEmulator, args: list[int], wide: bool) -> int:
    # the size is passed by value
    size = emu.alloc(4)
    emu.write_u32(size, args[3])
    return _reg_enum_key(emu, args[0], args[1], args[2], size, wide)


@api("RegEnumKeyA", nargs=4)
def reg_enum_key_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_enum_key_plain(emu, args, False)


@api("RegEnumKeyW", nargs=4)
def reg_enum_key_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_enum_key_plain(emu, args, True)


def _reg_delete_value(emu: WindowsEmulator, args: list[int], wide: bool) -> int:
    values = _reg_values(emu, args[0])
    name = (emu.read_wstr(args[1]) if wide else emu.read_cstr(args[1])) if args[1] else ""
    if values is None or values.pop(name.lower(), None) is None:
        return ERROR_FILE_NOT_FOUND
    return 0


@api("RegDeleteValueA", nargs=2)
def reg_delete_value_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_delete_value(emu, args, False)


@api("RegDeleteValueW", nargs=2)
def reg_delete_value_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_delete_value(emu, args, True)


def _reg_delete_key(emu: WindowsEmulator, args: list[int], wide: bool) -> int:
    key = _registry_key(emu, args[0], args[1], wide)
    if key is None or key not in emu.registry:
        return ERROR_FILE_NOT_FOUND
    if _reg_subkeys(emu, key):
        return ERROR_ACCESS_DENIED
    del emu.registry[key]
    return 0


@api("RegDeleteKeyA", nargs=2)
def reg_delete_key_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_delete_key(emu, args, False)


@api("RegDeleteKeyW", nargs=2)
def reg_delete_key_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _reg_delete_key(emu, args, True)


def _new_object(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.new_handle("object")


for _name, _nargs in (("CreateMutexA", 3), ("CreateMutexW", 3),
                      ("CreateSemaphoreA", 4), ("CreateSemaphoreW", 4), ("OpenMutexA", 3), ("OpenEventA", 3)):  # fmt: skip
    API_HANDLERS[_name] = ApiHandler(_new_object, _nargs)

_const(("ReleaseMutex",), 1, 1)
_const(("GetStdHandle",), 1, _STD_HANDLE)
_const(("GetFileType",), 1, 2)
_const(("InitializeSListHead", "FreeEnvironmentStringsW", "FreeEnvironmentStringsA"), 1, 1)
_const(("GetThreadLocale", "GetUserDefaultLCID", "GetSystemDefaultLCID"), 0, 0x409)
_const(("GetUserDefaultUILanguage", "GetSystemDefaultUILanguage", "GetUserDefaultLangID", "GetSystemDefaultLangID"),
       0, 0x409)  # fmt: skip
# no network adapters: ERROR_NO_DATA, not success with an untouched buffer
_const(("GetAdaptersInfo",), 2, 232)
_const(("GetAdaptersAddresses",), 5, 232)
_const(("SetConsoleCtrlHandler", "SetThreadPriority"), 2, 1)


#
# Tool Help process lists
#

ERROR_BAD_LENGTH = 24


def _process_entry(emu: WindowsEmulator, handle: int, entry: int, wide: bool, first: bool) -> int:
    snapshot = emu.handles.get(handle)
    if not isinstance(snapshot, ToolhelpSnapshot):
        set_last_error(emu, [6])  # ERROR_INVALID_HANDLE
        return 0
    # PROCESSENTRY32: the name follows nine fields, th32DefaultHeapID is pointer-sized
    name_offset = 0x2C if emu.is_64bit else 0x24
    size = name_offset + 260 * (2 if wide else 1)
    if emu.is_64bit:
        size = (size + 7) & ~7
    if emu.read_u32(entry) < size:
        set_last_error(emu, [ERROR_BAD_LENGTH])
        return 0
    if first:
        snapshot.process_pos = 0
    if snapshot.process_pos >= len(snapshot.processes):
        set_last_error(emu, [ERROR_NO_MORE_FILES])
        return 0
    pid, parent, threads, name = snapshot.processes[snapshot.process_pos]
    snapshot.process_pos += 1
    if emu.is_64bit:
        fields = struct.pack("<IIIIQIIIiI", size, 0, pid, 0, 0, 0, threads, parent, 8, 0)
    else:
        fields = struct.pack("<IIIIIIIiI", size, 0, pid, 0, 0, threads, parent, 8, 0)
    emu.write(entry, fields)
    _write_text(emu, entry + name_offset, 260, name, wide)
    return 1


@api("Process32First", nargs=2)
def process32_first(emu: WindowsEmulator, args: list[int]) -> int:
    return _process_entry(emu, args[0], args[1], False, True)


@api("Process32Next", nargs=2)
def process32_next(emu: WindowsEmulator, args: list[int]) -> int:
    return _process_entry(emu, args[0], args[1], False, False)


@api("Process32FirstW", nargs=2)
def process32_first_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _process_entry(emu, args[0], args[1], True, True)


@api("Process32NextW", nargs=2)
def process32_next_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _process_entry(emu, args[0], args[1], True, False)


@api("CreateThread", nargs=6)
def create_thread(emu: WindowsEmulator, args: list[int]) -> int:
    thread = emu.spawn_thread(args[2], args[3])
    if args[4] & 4:  # CREATE_SUSPENDED
        thread.alive = False
    if args[5]:
        emu.write_u32(args[5], thread.tid)
    return emu.new_handle(thread)


@api("ResumeThread", nargs=1)
def resume_thread(emu: WindowsEmulator, args: list[int]) -> int:
    target = emu.handles.get(args[0])
    if isinstance(target, Thread) and not target.started:
        target.alive = True
    return 1


@api("EncodePointer", "DecodePointer", "RtlEncodePointer", "RtlDecodePointer", nargs=1)
def encode_pointer(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return args[0]


@api("GetEnvironmentStringsW", nargs=0)
def get_environment_strings_w(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.alloc_cstr(_environment_block(emu), wide=True)


@api("GetEnvironmentStrings", "GetEnvironmentStringsA", nargs=0)
def get_environment_strings_a(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.alloc_cstr(_environment_block(emu))


@api("SystemFunction036", "RtlGenRandom", nargs=2)
def rtl_gen_random(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write(args[0], bytes((0x5A + 37 * i) & 0xFF for i in range(min(args[1], 0x10000))))
    return 1


@api("GetCPInfo", nargs=2)
def get_cp_info(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write(args[1], struct.pack("<I2s12s", 1, b"?\0", bytes(12)))
    return 1


@api("MultiByteToWideChar", nargs=6)
def multi_byte_to_wide_char(emu: WindowsEmulator, args: list[int]) -> int:
    length = args[3] if args[3] < 0x80000000 else len(emu.read_cstr(args[2], limit=1 << 16)) + 1
    if args[5] == 0:
        return length
    data = emu.read(args[2], min(length, args[5]))
    emu.write(args[4], data.decode("latin-1").encode("utf-16-le"))
    return len(data)


@api("WideCharToMultiByte", nargs=8)
def wide_char_to_multi_byte(emu: WindowsEmulator, args: list[int]) -> int:
    length = args[3] if args[3] < 0x80000000 else len(emu.read_wstr(args[2], limit=1 << 16)) + 1
    if args[5] == 0:
        return length
    data = emu.read(args[2], 2 * min(length, args[5]))
    emu.write(args[4], data.decode("utf-16-le", "replace").encode("latin-1", "replace"))
    return len(data) // 2


@api("memset", nargs=3, cdecl=True)
def c_memset(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write(args[0], bytes([args[1] & 0xFF]) * min(args[2], 1 << 26))
    return args[0]


@api("memcpy", "memmove", nargs=3, cdecl=True)
def c_memcpy(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write(args[0], emu.read(args[1], min(args[2], 1 << 26)))
    return args[0]


@api("RtlMoveMemory", "RtlCopyMemory", nargs=3)
def rtl_move_memory(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write(args[0], emu.read(args[1], min(args[2], 1 << 26)))
    return 0


@api("RtlZeroMemory", nargs=2)
def rtl_zero_memory(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write(args[0], bytes(min(args[1], 1 << 26)))
    return 0


@api("GetThreadContext", nargs=2)
def get_thread_context(emu: WindowsEmulator, args: list[int]) -> int:
    # debug registers read back as zero
    emu.exceptions.write_context(args[1], emu.pc)
    return 1


_const(("SetThreadContext",), 2, 1)


@api("NtGetContextThread", "ZwGetContextThread", nargs=2)
def nt_get_context_thread(emu: WindowsEmulator, args: list[int]) -> int:
    emu.exceptions.write_context(args[1], emu.pc)
    return STATUS_SUCCESS


@api("IsWow64Process", nargs=2)
def is_wow64_process(emu: WindowsEmulator, args: list[int]) -> int:
    emu.write_u32(args[1], 0)
    return 1


_const(("InterlockedIncrement", "InterlockedDecrement"), 1, 1)
_const(("IsBadReadPtr", "IsBadWritePtr"), 2, 0)
_const(("GetProcessWindowStation", "GetDesktopWindow", "GetForegroundWindow", "GetActiveWindow"), 0, 0)


#
# Windows and GDI: enough for a splash screen (a window, a DIB section to draw into)
#


@dataclass
class WindowClass:
    name: str
    wndproc: int


@dataclass
class WindowObject:
    wndclass: WindowClass | None
    parent: int
    thread: Thread | None = None
    wndproc: int = 0
    longs: dict[int, int] = field(default_factory=dict)
    # left, top, right, bottom
    rect: list[int] = field(default_factory=lambda: [0, 0, 0, 0])
    visible: bool = False
    # a visible window with an invalid region gets WM_PAINT once its thread's queue is empty
    needs_paint: bool = False
    # when the simulated user clicks the window (None: not yet scheduled; -1: clicked)
    click_tick: int | None = None


class GdiObject:
    """
    A device context, bitmap, cursor or icon handle.
    """

    def __init__(self, kind: str, bits: int = 0):
        self.kind = kind
        self.bits = bits


def _class_name(emu: WindowsEmulator, ptr: int, wide: bool) -> str:
    if ptr < 0x10000:
        return f"#{ptr}"
    return emu.read_wstr(ptr) if wide else emu.read_cstr(ptr)


def _register_class(emu: WindowsEmulator, wndclass: int, extended: bool, wide: bool) -> int:
    # x86 WNDCLASSEX is WNDCLASS behind cbSize; on x64 cbSize fills the padding after style
    if emu.is_64bit:
        wndproc, name = emu.read_ptr(wndclass + 8), emu.read_ptr(wndclass + 64)
    else:
        base = wndclass + (4 if extended else 0)
        wndproc, name = emu.read_ptr(base + 4), emu.read_ptr(base + 36)
    classes = emu.window_classes
    wc = WindowClass(_class_name(emu, name, wide), wndproc)
    classes[wc.name.lower()] = wc
    return 0xC000 + len(classes)


@api("RegisterClassExA", nargs=1)
def register_class_ex_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _register_class(emu, args[0], True, False)


@api("RegisterClassExW", nargs=1)
def register_class_ex_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _register_class(emu, args[0], True, True)


@api("RegisterClassA", nargs=1)
def register_class_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _register_class(emu, args[0], False, False)


@api("RegisterClassW", nargs=1)
def register_class_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _register_class(emu, args[0], False, True)


def _create_window(emu: WindowsEmulator, args: list[int], wide: bool) -> int | None:
    name = _class_name(emu, args[1], wide).lower()
    wndclass = emu.window_classes.get(name)
    window = WindowObject(wndclass, args[8], emu.thread, wndclass.wndproc if wndclass is not None else 0)
    x, y, width, height = (value - (1 << 32) if value & 0x80000000 else value for value in args[4:8])
    # the system picks the position and the size
    if x == CW_USEDEFAULT:
        x = y = 0
    if width == CW_USEDEFAULT:
        width, height = 640, 480
    window.rect = [x, y, x + width, y + height]
    window.visible = window.needs_paint = bool(args[3] & WS_VISIBLE)
    hwnd = emu.new_handle(window)
    if not window.wndproc:
        return hwnd
    # WM_NCCREATE and WM_CREATE get a CREATESTRUCT: the arguments in reverse order
    if emu.is_64bit:
        create = struct.pack("<QQQQiiiiIIQQII", args[11], args[10], args[9], args[8], height, width, y, x,
                             args[3], 0, args[2], args[1], args[0], 0)  # fmt: skip
    else:
        create = struct.pack("<IIIIiiiiIIII", args[11], args[10], args[9], args[8], height, width, y, x, *args[3::-1])
    buf = emu.alloc(len(create))
    emu.write(buf, create)

    def created(results: list[int]) -> int:
        # WM_NCCREATE returning FALSE or WM_CREATE returning -1 fail the creation
        if results[0] == 0 or (len(results) == 2 and results[1] == (1 << (8 * emu.ptr_size)) - 1):
            emu.handles.pop(hwnd, None)
            return 0
        return hwnd

    _guest_calls(
        emu,
        [(window.wndproc, (hwnd, WM_NCCREATE, 0, buf)), (window.wndproc, (hwnd, WM_CREATE, 0, buf))],
        created,
        lambda results: results[-1] != 0,
        window.thread,
    )
    return None


@api("CreateWindowExA", nargs=12)
def create_window_ex_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _create_window(emu, args, False)


@api("CreateWindowExW", nargs=12)
def create_window_ex_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _create_window(emu, args, True)


@api("LoadCursorA", "LoadCursorW", "LoadIconA", "LoadIconW", nargs=2)
def load_cursor(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.new_handle(GdiObject("cursor"))


@api("GetDC", "GetWindowDC", nargs=1)
def get_dc(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.new_handle(GdiObject("dc"))


@api("CreateCompatibleDC", nargs=1)
def create_compatible_dc(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.new_handle(GdiObject("dc"))


@api("CreateDIBSection", nargs=6)
def create_dib_section(emu: WindowsEmulator, args: list[int]) -> int:
    # BITMAPINFOHEADER: biSize, biWidth, biHeight, biPlanes, biBitCount
    _, width, height, _, bpp = struct.unpack("<IiiHH", emu.read(args[1], 16))
    if width <= 0 or height == 0 or bpp not in (1, 4, 8, 16, 24, 32):
        return 0
    stride = (width * bpp + 31) // 32 * 4
    bits = emu.alloc(stride * abs(height))
    if args[3]:
        emu.write_ptr(args[3], bits)
    return emu.new_handle(GdiObject("bitmap", bits))


@api("SelectObject", nargs=2)
def select_object(emu: WindowsEmulator, args: list[int]) -> int:
    dc = emu.handles.get(args[0])
    if not isinstance(dc, GdiObject) or dc.kind != "dc":
        return 0
    # the previously selected object: a fresh DC holds a stock 1x1 bitmap
    previous = dc.bits or emu.new_handle(GdiObject("bitmap"))
    dc.bits = args[1]
    return previous


@api("SetDIBColorTable", nargs=4)
def set_dib_color_table(emu: WindowsEmulator, args: list[int]) -> int:
    return args[2] if isinstance(emu.handles.get(args[0]), GdiObject) else 0


_const(("ReleaseDC",), 2, 1)
_const(("DeleteDC", "DeleteObject"), 1, 1)
_const(("BitBlt",), 9, 1)
_const(("StretchBlt",), 11, 1)


#
# Window messages: per-thread queues, timers, and calls into window procedures
#

WM_CREATE = 0x1
WM_DESTROY = 0x2
WM_PAINT = 0xF
WS_VISIBLE = 0x10000000
CW_USEDEFAULT = -0x80000000
WM_CLOSE = 0x10
WM_QUIT = 0x12
WM_NCCREATE = 0x81
WM_NCDESTROY = 0x82
WM_TIMER = 0x113
WM_LBUTTONDOWN = 0x201
WM_LBUTTONUP = 0x202
# how long a window waits for input before the simulated user clicks it (splash screens that close on a click)
USER_CLICK_DELAY = 3000


@dataclass
class TimerObject:
    thread: Thread
    hwnd: int
    ident: int
    elapse: int
    proc: int
    due: int


def _guest_calls(
    emu: WindowsEmulator,
    calls: list[tuple[int, tuple[int, ...]]],
    finish: Callable[[list[int]], int],
    proceed: Callable[[list[int]], bool] = lambda _: True,
    owner: Thread | None = None,
) -> None:
    """
    For API handlers that call guest code (window procedures): make the calls in order while proceed(results)
    holds, then return finish(results) to the API's caller. The handler itself returns None. The calls run on
    behalf of owner, the thread of the window whose procedure is called.
    """
    ret_pc = emu.pc
    results: list[int] = []
    caller = emu.thread
    if owner is not None:
        caller.window_owners.append(owner)

    def step(result: int | None = None) -> None:
        if result is not None:
            results.append(result & ((1 << (8 * emu.ptr_size)) - 1))
        if len(results) < len(calls) and (not results or proceed(results)):
            addr, args = calls[len(results)]
            emu.call_guest(addr, args, step)
            return
        if owner is not None:
            caller.window_owners.pop()
        emu.set_reg("rax" if emu.is_64bit else "eax", finish(results))
        emu._set_pc(ret_pc)  # pylint:disable=protected-access

    step()


def _window(emu: WindowsEmulator, hwnd: int) -> WindowObject | None:
    window = emu.handles.get(hwnd)
    return window if isinstance(window, WindowObject) else None


def _post(emu: WindowsEmulator, thread: Thread, message: tuple[int, int, int, int]) -> None:
    thread.messages.append(message)
    if thread.wait_handle is None:
        # a thread blocked in GetMessage wakes up
        thread.wake_tick = min(thread.wake_tick, emu.tick)


def _next_message(emu: WindowsEmulator, remove: bool) -> tuple[int, int, int, int] | None:
    thread = emu.thread
    if thread.messages:
        return thread.messages.pop(0) if remove else thread.messages[0]
    due = [t for t in emu.timers if t.thread is thread and t.due <= emu.tick]
    if not due:
        windows = [(h, w) for h, w in emu.handles.items() if isinstance(w, WindowObject) and w.thread is thread]
        for hwnd, window in windows:
            if window.needs_paint:
                # WM_PAINT stays pending until BeginPaint or ValidateRect
                return hwnd, WM_PAINT, 0, 0
        for hwnd, window in windows:
            if window.click_tick is not None and 0 <= window.click_tick <= emu.tick:
                if remove:
                    window.click_tick = -1
                    thread.messages.append((hwnd, WM_LBUTTONUP, 0, 0x000A000A))
                return hwnd, WM_LBUTTONDOWN, 1, 0x000A000A  # MK_LBUTTON at (10, 10)
        return None
    timer = min(due, key=lambda t: t.due)
    if remove:
        timer.due = emu.tick + timer.elapse
    return timer.hwnd, WM_TIMER, timer.ident, timer.proc


def _write_message(emu: WindowsEmulator, addr: int, message: tuple[int, int, int, int]) -> None:
    hwnd, msg, wparam, lparam = message
    if emu.is_64bit:
        emu.write(addr, struct.pack("<QIIQQIii", hwnd, msg, 0, wparam, lparam, emu.tick & 0xFFFFFFFF, 0, 0))
    else:
        emu.write(addr, struct.pack("<IIIIIii", hwnd, msg, wparam, lparam, emu.tick & 0xFFFFFFFF, 0, 0))


def _read_message(emu: WindowsEmulator, addr: int) -> tuple[int, int, int, int]:
    if emu.is_64bit:
        hwnd, msg, _, wparam, lparam = struct.unpack("<QIIQQ", emu.read(addr, 32))
    else:
        hwnd, msg, wparam, lparam = struct.unpack("<IIII", emu.read(addr, 16))
    return hwnd, msg, wparam, lparam


def _get_message(emu: WindowsEmulator, addr: int) -> int | None:
    message = _next_message(emu, True)
    if message is None:
        thread = emu.thread
        timers = [t.due for t in emu.timers if t.thread is thread]
        # a visible window that waits for input gets clicked a while later
        for window in emu.handles.values():
            if isinstance(window, WindowObject) and window.thread is thread and window.visible:
                if window.click_tick is None:
                    window.click_tick = emu.tick + USER_CLICK_DELAY
                if window.click_tick >= 0:
                    timers.append(window.click_tick)
        # nothing queued: sleep until the next timer, or until another thread posts something
        thread.wake_tick = min(timers) if timers else emu.tick + 60000
        if emu.block_thread():
            return None
        if not timers:
            emu.stop(StopReason.BUDGET, "GetMessage waits forever")
            return 0
        emu.tick = thread.wake_tick
        thread.wake_tick = 0
        message = _next_message(emu, True)
        assert message is not None
    _write_message(emu, addr, message)
    return int(message[1] != WM_QUIT)


@api("GetMessageA", "GetMessageW", nargs=4)
def get_message(emu: WindowsEmulator, args: list[int]) -> int | None:
    return _get_message(emu, args[0])


@api("PeekMessageA", "PeekMessageW", nargs=5)
def peek_message(emu: WindowsEmulator, args: list[int]) -> int:
    emu.tick += 1
    message = _next_message(emu, bool(args[4] & 1))
    if message is None:
        return 0
    _write_message(emu, args[0], message)
    return 1


@api("DispatchMessageA", "DispatchMessageW", nargs=1)
def dispatch_message(emu: WindowsEmulator, args: list[int]) -> int | None:
    hwnd, msg, wparam, lparam = _read_message(emu, args[0])
    window = _window(emu, hwnd)
    if msg == WM_TIMER and lparam:
        target = lparam
        call_args = (hwnd, msg, wparam, emu.tick & 0xFFFFFFFF)
    else:
        if window is None or not window.wndproc:
            return 0
        target, call_args = window.wndproc, (hwnd, msg, wparam, lparam)
    owner = window.thread if window is not None else None
    _guest_calls(emu, [(target, call_args)], lambda results: results[0], owner=owner)
    return None


def _send(emu: WindowsEmulator, hwnd: int, msg: int, wparam: int, lparam: int) -> int | None:
    window = _window(emu, hwnd)
    if window is None or not window.wndproc:
        return 0
    # the procedure runs for the window's thread, whichever thread sends
    _guest_calls(emu, [(window.wndproc, (hwnd, msg, wparam, lparam))], lambda results: results[0], owner=window.thread)
    return None


@api("SendMessageA", "SendMessageW", nargs=4)
def send_message(emu: WindowsEmulator, args: list[int]) -> int | None:
    return _send(emu, *args)


@api("PostMessageA", "PostMessageW", nargs=4)
def post_message(emu: WindowsEmulator, args: list[int]) -> int:
    window = _window(emu, args[0])
    thread = window.thread if window is not None and window.thread is not None else emu.thread
    _post(emu, thread, (args[0], args[1], args[2], args[3]))
    return 1


@api("PostThreadMessageA", "PostThreadMessageW", nargs=4)
def post_thread_message(emu: WindowsEmulator, args: list[int]) -> int:
    thread = next((t for t in emu.threads if t.tid == args[0] and t.alive), None)
    if thread is None:
        return 0
    _post(emu, thread, (0, args[1], args[2], args[3]))
    return 1


@api("PostQuitMessage", nargs=1)
def post_quit_message(emu: WindowsEmulator, args: list[int]) -> int:
    # from a window procedure that another thread called (SendMessage, DestroyWindow): the window's thread quits
    owners = emu.thread.window_owners
    _post(emu, owners[-1] if owners else emu.thread, (0, WM_QUIT, args[0], 0))
    return 0


@api("DestroyWindow", nargs=1)
def destroy_window(emu: WindowsEmulator, args: list[int]) -> int | None:
    hwnd = args[0]
    window = _window(emu, hwnd)
    if window is None:
        return 0
    emu.timers = [t for t in emu.timers if t.hwnd != hwnd]

    def destroyed(_: list[int]) -> int:
        emu.handles.pop(hwnd, None)
        return 1

    if not window.wndproc:
        return destroyed([])
    _guest_calls(emu, [(window.wndproc, (hwnd, WM_DESTROY, 0, 0)), (window.wndproc, (hwnd, WM_NCDESTROY, 0, 0))],
                 destroyed, owner=window.thread)  # fmt: skip
    return None


@api("DefWindowProcA", "DefWindowProcW", nargs=4)
def def_window_proc(emu: WindowsEmulator, args: list[int]) -> int | None:
    if args[1] == WM_CLOSE:
        return destroy_window(emu, args[:1])
    window = _window(emu, args[0])
    if args[1] == WM_PAINT and window is not None:
        window.needs_paint = False
    return int(args[1] == WM_NCCREATE)


@api("ShowWindow", nargs=2)
def show_window(emu: WindowsEmulator, args: list[int]) -> int:
    window = _window(emu, args[0])
    if window is None:
        return 0
    was_visible = window.visible
    window.visible = args[1] != 0  # SW_HIDE
    window.needs_paint |= window.visible and not was_visible
    return int(was_visible)


@api("UpdateWindow", nargs=1)
def update_window(emu: WindowsEmulator, args: list[int]) -> int | None:
    window = _window(emu, args[0])
    if window is None:
        return 0
    if not (window.visible and window.needs_paint and window.wndproc):
        return 1
    # sends WM_PAINT right away
    _guest_calls(emu, [(window.wndproc, (args[0], WM_PAINT, 0, 0))], lambda _: 1, owner=window.thread)
    return None


def _invalidate(emu: WindowsEmulator, hwnd: int, invalid: bool) -> int:
    window = _window(emu, hwnd)
    if window is None:
        return 0
    window.needs_paint = invalid and window.visible
    return 1


@api("InvalidateRect", nargs=3)
def invalidate_rect(emu: WindowsEmulator, args: list[int]) -> int:
    return _invalidate(emu, args[0], True)


@api("ValidateRect", nargs=2)
def validate_rect(emu: WindowsEmulator, args: list[int]) -> int:
    return _invalidate(emu, args[0], False)


@api("BeginPaint", nargs=2)
def begin_paint(emu: WindowsEmulator, args: list[int]) -> int:
    window = _window(emu, args[0])
    if window is None:
        return 0
    window.needs_paint = False
    dc = emu.new_handle(GdiObject("dc"))
    left, top, right, bottom = window.rect
    # PAINTSTRUCT: hdc, fErase, rcPaint, ...
    emu.write_ptr(args[1], dc)
    emu.write(args[1] + emu.ptr_size, struct.pack("<Iiiii", 0, 0, 0, right - left, bottom - top))
    return dc


_const(("EndPaint",), 2, 1)


@api("GetDeviceCaps", nargs=2)
def get_device_caps(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    # HORZRES, VERTRES, BITSPIXEL, PLANES, LOGPIXELSX, LOGPIXELSY
    return {8: SCREEN_RECT[2], 10: SCREEN_RECT[3], 12: 32, 14: 1, 0x58: 96, 0x5A: 96}.get(args[1], 0)


@api("MulDiv", nargs=3)
def mul_div(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    a, b, c = (value - (1 << 32) if value & 0x80000000 else value for value in (x & 0xFFFFFFFF for x in args))
    if c == 0:
        return -1
    product = a * b
    # rounded half away from zero, as Windows does
    quotient = (abs(product) + abs(c) // 2) // abs(c)
    return quotient if (product < 0) == (c < 0) else -quotient


@api("SetTimer", nargs=4)
def set_timer(emu: WindowsEmulator, args: list[int]) -> int:
    hwnd, ident, elapse, proc = args
    window = _window(emu, hwnd)
    if hwnd and window is None:
        return 0
    if not hwnd:
        ident = 0x7FF0 + len(emu.timers)
    emu.timers = [t for t in emu.timers if (t.hwnd, t.ident) != (hwnd, ident)]
    thread = window.thread if window is not None and window.thread is not None else emu.thread
    elapse = min(max(elapse, 10), 0x7FFFFFFF)
    emu.timers.append(TimerObject(thread, hwnd, ident, elapse, proc, emu.tick + elapse))
    return ident or 1


@api("KillTimer", nargs=2)
def kill_timer(emu: WindowsEmulator, args: list[int]) -> int:
    before = len(emu.timers)
    emu.timers = [t for t in emu.timers if (t.hwnd, t.ident) != (args[0], args[1])]
    return int(len(emu.timers) < before)


@api("IsWindow", nargs=1)
def is_window(emu: WindowsEmulator, args: list[int]) -> int:
    return int(_window(emu, args[0]) is not None)


def _window_long(emu: WindowsEmulator, args: list[int], value: int | None) -> int:
    window = _window(emu, args[0])
    if window is None:
        return 0
    index = args[1] - (1 << 32) if args[1] & 0x80000000 else args[1]
    previous = window.wndproc if index == -4 else window.longs.get(index, 0)
    if value is not None:
        if index == -4:  # GWL_WNDPROC
            window.wndproc = value
        else:
            window.longs[index] = value
    return previous


@api("GetWindowLongA", "GetWindowLongW", "GetWindowLongPtrA", "GetWindowLongPtrW", nargs=2)
def get_window_long(emu: WindowsEmulator, args: list[int]) -> int:
    return _window_long(emu, args, None)


@api("SetWindowLongA", "SetWindowLongW", "SetWindowLongPtrA", "SetWindowLongPtrW", nargs=3)
def set_window_long(emu: WindowsEmulator, args: list[int]) -> int:
    return _window_long(emu, args, args[2])


def _window_rect(emu: WindowsEmulator, hwnd: int, rect: int, client: bool) -> int:
    window = _window(emu, hwnd)
    if window is None and hwnd:
        return 0
    # 0 is the desktop window (GetDesktopWindow)
    left, top, right, bottom = window.rect if window is not None else SCREEN_RECT
    emu.write(
        rect, struct.pack("<iiii", *((0, 0, right - left, bottom - top) if client else (left, top, right, bottom)))
    )
    return 1


@api("GetWindowRect", nargs=2)
def get_window_rect(emu: WindowsEmulator, args: list[int]) -> int:
    return _window_rect(emu, args[0], args[1], False)


@api("GetClientRect", nargs=2)
def get_client_rect(emu: WindowsEmulator, args: list[int]) -> int:
    return _window_rect(emu, args[0], args[1], True)


@api("SetWindowPos", nargs=7)
def set_window_pos(emu: WindowsEmulator, args: list[int]) -> int:
    window = _window(emu, args[0])
    if window is None:
        return 0
    x, y, width, height = (value - (1 << 32) if value & 0x80000000 else value for value in args[2:6])
    left, top, right, bottom = window.rect
    if not args[6] & 2:  # SWP_NOMOVE
        left, top, right, bottom = x, y, x + right - left, y + bottom - top
    if not args[6] & 1:  # SWP_NOSIZE
        right, bottom = left + width, top + height
    window.rect = [left, top, right, bottom]
    return 1


@api("MoveWindow", nargs=6)
def move_window(emu: WindowsEmulator, args: list[int]) -> int:
    window = _window(emu, args[0])
    if window is None:
        return 0
    x, y, width, height = (value - (1 << 32) if value & 0x80000000 else value for value in args[1:5])
    window.rect = [x, y, x + width, y + height]
    return 1


_const(("TranslateMessage",), 1, 0)
