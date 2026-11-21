from __future__ import annotations

import ntpath
import re
import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

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
STATUS_INVALID_HANDLE = 0xC0000008
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_NOT_IMPLEMENTED = 0xC0000002
STATUS_PORT_NOT_SET = 0xC0000353
STATUS_INVALID_INFO_CLASS = 0xC0000003
STATUS_DLL_NOT_FOUND = 0xC0000135
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
    An open handle on the emulated copy of the sample's own file.
    """

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0


class MappingObject:
    """
    A file-mapping handle.
    """

    def __init__(self, data: bytes):
        self.data = data


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
    if old_ptr:
        old = emu.state.solver.eval(emu.state.memory.permissions(addr & ~0xFFF, priv=True))
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
        if emu.is_mapped(addr):
            perms = emu.state.solver.eval(emu.state.memory.permissions(addr, priv=True))
        else:
            perms = emu.lazy_regions.get(region[0], (3, 0))[0]
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


_const(("VirtualFree", "VirtualLock", "VirtualUnlock", "FlushInstructionCache"), 3, 1)
_const(("VirtualFreeEx",), 4, 1)
_const(("NtFreeVirtualMemory", "ZwFreeVirtualMemory"), 4, STATUS_SUCCESS)


@api("KiFastSystemCall", "KiIntSystemCall", nargs=0)
def ki_system_call(emu: WindowsEmulator, args: list[int]) -> None:  # pylint:disable=unused-argument
    # reached from a 32-bit ntdll stub: the stub's caller pushed the arguments above its own return address
    emu.system_call(emu.sp + 4)


@api("HeapAlloc", "RtlAllocateHeap", nargs=3)
def heap_alloc(emu: WindowsEmulator, args: list[int]) -> int:
    return emu.alloc(max(args[2], 1))


@api("HeapReAlloc", "RtlReAllocateHeap", nargs=4)
def heap_realloc(emu: WindowsEmulator, args: list[int]) -> int:
    new = emu.alloc(max(args[3], 1))
    old_size = emu.allocations.get(args[2], 0)
    emu.write(new, emu.read(args[2], min(old_size, args[3])))
    return new


@api("LocalAlloc", "GlobalAlloc", nargs=2)
def local_alloc(emu: WindowsEmulator, args: list[int]) -> int:
    return emu.alloc(max(args[1], 1))


@api("HeapSize", "RtlSizeHeap", nargs=3)
def heap_size(emu: WindowsEmulator, args: list[int]) -> int:
    return emu.allocations.get(args[2], 0)


@api("malloc", nargs=1, cdecl=True)
def c_malloc(emu: WindowsEmulator, args: list[int]) -> int:
    return emu.alloc(max(args[0], 1))


@api("GetProcessHeap", nargs=0)
def get_process_heap(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.process_heap


@api("HeapCreate", nargs=3)
def heap_create(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.new_handle("heap")


_const(("HeapFree", "RtlFreeHeap"), 3, 1)
_const(("LocalFree", "GlobalFree"), 1, 0)
_const(("GlobalLock",), 1, 0)
_const(("HeapDestroy", "HeapSetInformation"), 4, 1)

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


def _get_proc_address(emu: WindowsEmulator, base: int, name: str | None, ordinal: int) -> int:
    module = emu.module_by_base(base)
    if module is None:
        if base == emu.image_base and name is not None:
            symbol = emu.main.get_symbol(name)
            return symbol.rebased_addr if symbol is not None else 0
        return 0
    addr = emu.resolve_export(module, name) if name is not None else emu.resolve_ordinal(module, ordinal)
    return addr or 0


@api("GetProcAddress", nargs=2)
def get_proc_address(emu: WindowsEmulator, args: list[int]) -> int:
    if args[1] < 0x10000:
        return _get_proc_address(emu, args[0], None, args[1])
    return _get_proc_address(emu, args[0], emu.read_cstr(args[1]), 0)


@api("LdrGetProcedureAddress", nargs=4)
def ldr_get_procedure_address(emu: WindowsEmulator, args: list[int]) -> int:
    name = _read_counted_string(emu, args[1], False) if args[1] else None
    addr = _get_proc_address(emu, args[0], name, args[2])
    emu.write_ptr(args[3], addr)
    return STATUS_SUCCESS if addr else STATUS_ENTRYPOINT_NOT_FOUND


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
_const(("IsDebuggerPresent", "GetLastActivePopup", "GetACP"), 0, 0)
_const(("GetOEMCP",), 0, 437)
_const(("IsProcessorFeaturePresent",), 1, 1)


@api("CloseHandle", nargs=1)
def close_handle(emu: WindowsEmulator, args: list[int]) -> int:
    return int(emu.handles.pop(args[0], None) is not None)


@api("NtClose", "ZwClose", nargs=1)
def nt_close(emu: WindowsEmulator, args: list[int]) -> int:
    return STATUS_SUCCESS if emu.handles.pop(args[0], None) is not None else STATUS_INVALID_HANDLE


_const(("SetErrorMode", "OutputDebugStringA", "OutputDebugStringW"), 1, 0)
_const(("InitializeCriticalSection", "DeleteCriticalSection", "EnterCriticalSection", "LeaveCriticalSection",
        "RtlInitializeCriticalSection", "RtlEnterCriticalSection", "RtlLeaveCriticalSection",
        "RtlDeleteCriticalSection"), 1, 0)  # fmt: skip
_const(("InitializeCriticalSectionAndSpinCount", "SetHandleCount"), 2, 1)
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
                emu.state.regs.ip = ret_pc

            emu.call_guest(base + handler, (pointers, establisher), after_filter)
            return None
        return 1

    return next_scope(0)


_const(("GetSystemMetrics",), 1, 0)
_const(("FindWindowA", "FindWindowW"), 2, 0)
_const(("GetEnvironmentVariableA", "GetEnvironmentVariableW"), 3, 0)
_const(("SetThreadAffinityMask", "SetProcessAffinityMask"), 2, 1)


@api("GetCurrentProcessId", nargs=0)
def get_current_process_id(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.PID


@api("GetCurrentThreadId", nargs=0)
def get_current_thread_id(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.thread.tid


@api("GetLastError", "RtlGetLastWin32Error", nargs=0)
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


@api("NtQueryInformationProcess", "ZwQueryInformationProcess", nargs=5)
def nt_query_information_process(emu: WindowsEmulator, args: list[int]) -> int:
    info_class, buf, length = args[1], args[2], args[3]
    if args[4] & 3:
        # the kernel probes the pointers first; protectors pass an odd one to catch faked answers
        return STATUS_DATATYPE_MISALIGNMENT
    status = STATUS_SUCCESS
    if info_class == 7:  # ProcessDebugPort
        emu.write_ptr(buf, 0)
        length = emu.ptr_size
    elif info_class == 0x1E:  # ProcessDebugObjectHandle
        emu.write_ptr(buf, 0)
        length = emu.ptr_size
        status = STATUS_PORT_NOT_SET
    elif info_class == 0x1F:  # ProcessDebugFlags
        emu.write_u32(buf, 1)
        length = 4
    elif info_class == 0:  # ProcessBasicInformation
        emu.write(buf, bytes(length))
        emu.write_ptr(buf + emu.ptr_size, emu.peb)
        emu.write_ptr(buf + 4 * emu.ptr_size, emu.PID)
    else:
        return STATUS_INVALID_INFO_CLASS
    # the kernel stores the length after the data even on failure; protectors overlap the two to catch fakes
    if args[4]:
        emu.write_u32(args[4], length)
    return status


@api("GetTickCount", nargs=0)
def get_tick_count(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    emu.tick += 16
    return emu.tick & 0xFFFFFFFF


@api("GetTickCount64", nargs=0)
def get_tick_count64(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    emu.tick += 16
    return emu.tick


def _sleep(emu: WindowsEmulator, milliseconds: int) -> None:
    thread = emu.thread
    thread.wake_tick = emu.tick + min(max(milliseconds, 1), 60000)
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
    infinite = timeout & 0xFFFFFFFF == 0xFFFFFFFF
    thread.wait_handle = None
    if ready or (infinite and thread.waits > _MAX_WAITS):
        thread.waits = 0
        return 0
    if timeout == 0 or (not infinite and thread.waits >= 2):
        thread.waits = 0
        return WAIT_TIMEOUT
    thread.waits += 1
    if infinite:
        # not scheduled again until the object is signaled
        thread.wait_handle = handle
    if emu.block_thread():
        return None
    thread.waits = 0
    thread.wait_handle = None
    return 0 if infinite else WAIT_TIMEOUT


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


@api("GetSystemDirectoryA", "GetWindowsDirectoryA", nargs=2)
def get_system_directory_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _write_text(emu, args[0], args[1], "C:\\Windows\\System32", False)


@api("GetSystemDirectoryW", "GetWindowsDirectoryW", nargs=2)
def get_system_directory_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _write_text(emu, args[0], args[1], "C:\\Windows\\System32", True)


@api("MessageBoxA", nargs=4)
def message_box_a(emu: WindowsEmulator, args: list[int]) -> int:
    emu.messages.append(f"{emu.read_cstr(args[2])}: {emu.read_cstr(args[1])}")
    return 1


@api("MessageBoxW", nargs=4)
def message_box_w(emu: WindowsEmulator, args: list[int]) -> int:
    emu.messages.append(f"{emu.read_wstr(args[2])}: {emu.read_wstr(args[1])}")
    return 1


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
# Files: only the sample's own image can be opened
#


def _open_file(emu: WindowsEmulator, path: str) -> int:
    if ntpath.basename(path).lower() != ntpath.basename(emu.image_path).lower():
        return INVALID_HANDLE
    return emu.new_handle(FileObject(emu.image_file))


@api("CreateFileA", nargs=7)
def create_file_a(emu: WindowsEmulator, args: list[int]) -> int:
    return _open_file(emu, emu.read_cstr(args[0]))


@api("CreateFileW", nargs=7)
def create_file_w(emu: WindowsEmulator, args: list[int]) -> int:
    return _open_file(emu, emu.read_wstr(args[0]))


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
    data = obj.data[obj.pos : obj.pos + args[2]]
    obj.pos += len(data)
    emu.write(args[1], data)
    if args[3]:
        emu.write_u32(args[3], len(data))
    return 1


@api("CreateFileMappingA", "CreateFileMappingW", nargs=6)
def create_file_mapping(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    if not isinstance(obj, FileObject):
        return 0
    return emu.new_handle(MappingObject(obj.data))


@api("MapViewOfFile", nargs=5)
def map_view_of_file(emu: WindowsEmulator, args: list[int]) -> int:
    obj = emu.handles.get(args[0])
    if not isinstance(obj, MappingObject):
        return 0
    offset = (args[2] << 32) | args[3]
    data = obj.data[offset : offset + args[4]] if args[4] else obj.data[offset:]
    addr = emu.alloc(max(len(data), 1))
    emu.write(addr, data)
    emu.file_views.add(addr)
    return addr


_const(("UnmapViewOfFile",), 1, 1)

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
    emu.tick += 16
    return emu.tick & 0xFFFFFFFF


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

# registry: nothing exists
_const(("RegOpenKeyA", "RegOpenKeyW"), 3, 2)
_const(("RegOpenKeyExA", "RegOpenKeyExW"), 5, 2)
_const(("RegQueryValueExA", "RegQueryValueExW"), 6, 2)
_const(("RegCloseKey",), 1, 0)
_const(("RegCreateKeyExA", "RegCreateKeyExW"), 9, 5)


def _new_object(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.new_handle("object")


for _name, _nargs in (("CreateMutexA", 3), ("CreateMutexW", 3),
                      ("CreateSemaphoreA", 4), ("CreateSemaphoreW", 4), ("OpenMutexA", 3), ("OpenEventA", 3)):  # fmt: skip
    API_HANDLERS[_name] = ApiHandler(_new_object, _nargs)

_const(("ReleaseMutex",), 1, 1)
_const(("GetStdHandle",), 1, 0x30)
_const(("GetFileType",), 1, 2)
_const(("InitializeSListHead", "FreeEnvironmentStringsW", "FreeEnvironmentStringsA"), 1, 1)
_const(("GetThreadLocale", "GetUserDefaultLCID", "GetSystemDefaultLCID"), 0, 0x409)
_const(("SetConsoleCtrlHandler", "SetThreadPriority"), 2, 1)


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
    return emu.alloc_cstr("SystemRoot=C:\\Windows\0", wide=True)


@api("GetEnvironmentStrings", "GetEnvironmentStringsA", nargs=0)
def get_environment_strings_a(emu: WindowsEmulator, args: list[int]) -> int:  # pylint:disable=unused-argument
    return emu.alloc_cstr("SystemRoot=C:\\Windows\0")


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


_const(("NtRaiseHardError", "ZwRaiseHardError"), 6, STATUS_SUCCESS)
_const(("UnhandledExceptionFilter",), 1, 0)
_const(("InterlockedIncrement", "InterlockedDecrement"), 1, 1)
_const(("IsBadReadPtr", "IsBadWritePtr"), 2, 0)
_const(("GetProcessWindowStation", "GetDesktopWindow", "GetForegroundWindow", "GetActiveWindow"), 0, 0)
