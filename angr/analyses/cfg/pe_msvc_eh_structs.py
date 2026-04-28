"""
Struct definitions and parsing utilities for MSVC C++ exception handling structures
found in x86 PE binaries.

References:
- ___CxxFrameHandler3: The MSVC C++ exception handler for 32-bit binaries.
- __EH_prolog3 / __EH_prolog3_catch / __EH_prolog3_GS: C++ EH prolog helpers.
- __SEH_prolog4 / __SEH_prolog4_GS: SEH prolog helpers.
- FuncInfo: Describes exception handling metadata for a function.
- UnwindMapEntry: Describes state unwinding actions during exception handling.
"""

from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Byte signatures for identification
# ---------------------------------------------------------------------------

# ___CxxFrameHandler3 (x86 32-bit):
#   push ebp; mov ebp, esp; sub esp, 8; push ebx; push esi; push edi;
#   cld; mov [ebp-4], eax
CXXFRAMEHANDLER3_SIGNATURE = b"\x55\x8b\xec\x83\xec\x08\x53\x56\x57\xfc\x89\x45\xfc"

# __EH_prolog3 family common prefix (23 bytes):
#   push eax;              50
#   push dword ptr fs:[0]; 64 FF 35 00 00 00 00
#   lea eax, [esp+0xc];   8D 44 24 0C
#   sub esp, [esp+0xc];   2B 64 24 0C
#   push ebx; push esi; push edi;  53 56 57
#   mov [eax], ebp;       89 28
#   mov ebp, eax;         8B E8
EH_PROLOG3_COMMON = b"\x50\x64\xff\x35\x00\x00\x00\x00\x8d\x44\x24\x0c\x2b\x64\x24\x0c\x53\x56\x57\x89\x28\x8b\xe8"

# After the common prefix + 8 bytes (security cookie xor + push), the
# distinguishing bytes at offset 31 are:
#   __EH_prolog3:       FF 75 FC       push [ebp-4]
#   __EH_prolog3_catch: 89 65 F0       mov [ebp-0x10], esp
#   __EH_prolog3_GS:    89 45 F0       mov [ebp-0x10], eax
EH_PROLOG3_DISCRIM_OFFSET = 31
EH_PROLOG3_DISCRIM = b"\xff"  # push [ebp-4]
EH_PROLOG3_CATCH_DISCRIM = b"\x89\x65"  # mov [ebp-0x10], esp
EH_PROLOG3_GS_DISCRIM = b"\x89\x45"  # mov [ebp-0x10], eax

# __SEH_prolog4 family common prefix (24 bytes starting at offset 5):
#   push <handler>;        68 xx xx xx xx          (offset 0-4, varies)
#   push dword ptr fs:[0]; 64 FF 35 00 00 00 00    (offset 5-11)
#   mov eax, [esp+0x10];   8B 44 24 10             (offset 12-15)
#   mov [esp+0x10], ebp;   89 6C 24 10             (offset 16-19)
#   lea ebp, [esp+0x10];   8D 6C 24 10             (offset 20-23)
#   sub esp, eax;          2B E0                   (offset 24-25)
#   push ebx; push esi; push edi;  53 56 57        (offset 26-28)
SEH_PROLOG4_COMMON = b"\x64\xff\x35\x00\x00\x00\x00\x8b\x44\x24\x10\x89\x6c\x24\x10\x8d\x6c\x24\x10\x2b\xe0\x53\x56\x57"

# After the common prefix + security cookie ops, the distinguishing byte at
# offset 39 is:
#   __SEH_prolog4:    50       push eax
#   __SEH_prolog4_GS: 89       mov [ebp-0x1c], eax
SEH_PROLOG4_DISCRIM_OFFSET = 39
SEH_PROLOG4_DISCRIM = b"\x50"  # push eax
SEH_PROLOG4_GS_DISCRIM = b"\x89"  # mov [ebp-0x1c], eax

FUNCINFO_MAGIC = 0x19930522

FUNCINFO_SIZE = 36  # 9 * 4 bytes

UNWINDMAPENTRY_SIZE = 8  # 2 * 4 bytes

TRYBLOCKMAPENTRY_SIZE = 20  # 5 * 4 bytes

HANDLERTYPE_SIZE = 16  # 4 * 4 bytes


class FuncInfo:
    """Parsed FuncInfo struct from a 32-bit PE binary."""

    __slots__ = (
        "addr",
        "eh_flags",
        "magic_number",
        "max_state",
        "n_ip_map_entries",
        "n_try_blocks",
        "p_es_type_list",
        "p_ip_to_state_map",
        "p_try_block_map",
        "p_unwind_map",
    )

    def __init__(
        self,
        addr: int,
        magic_number: int,
        max_state: int,
        p_unwind_map: int,
        n_try_blocks: int,
        p_try_block_map: int,
        n_ip_map_entries: int,
        p_ip_to_state_map: int,
        p_es_type_list: int,
        eh_flags: int,
    ):
        self.addr = addr
        self.magic_number = magic_number
        self.max_state = max_state
        self.p_unwind_map = p_unwind_map
        self.n_try_blocks = n_try_blocks
        self.p_try_block_map = p_try_block_map
        self.n_ip_map_entries = n_ip_map_entries
        self.p_ip_to_state_map = p_ip_to_state_map
        self.p_es_type_list = p_es_type_list
        self.eh_flags = eh_flags

    def __repr__(self):
        return (
            f"FuncInfo(addr={self.addr:#x}, magic={self.magic_number:#x}, "
            f"maxState={self.max_state}, pUnwindMap={self.p_unwind_map:#x}, "
            f"nTryBlocks={self.n_try_blocks})"
        )


class UnwindMapEntry:
    """Parsed UnwindMapEntry struct from a 32-bit PE binary."""

    __slots__ = ("action", "addr", "to_state")

    def __init__(self, addr: int, to_state: int, action: int):
        self.addr = addr
        self.to_state = to_state
        self.action = action

    def __repr__(self):
        return f"UnwindMapEntry(addr={self.addr:#x}, toState={self.to_state}, action={self.action:#x})"


def parse_funcinfo(memory, addr: int) -> FuncInfo | None:
    """
    Parse a FuncInfo struct at the given address.

    :param memory:  The loader memory interface (supports .load(addr, size)).
    :param addr:    The virtual address of the FuncInfo struct.
    :return:        A FuncInfo object, or None if parsing fails.
    """
    try:
        data = memory.load(addr, FUNCINFO_SIZE)
    except KeyError:
        log.debug("Failed to read FuncInfo at %#x", addr)
        return None

    if len(data) < FUNCINFO_SIZE:
        return None

    values = struct.unpack("<IIIIIIIII", data)
    magic_number = values[0]

    # Validate magic number (basic check - the low bits should be 0x19930522)
    if (magic_number & 0x1FFFFFFF) != (FUNCINFO_MAGIC & 0x1FFFFFFF):
        log.debug("Invalid FuncInfo magic %#x at %#x", magic_number, addr)
        return None

    return FuncInfo(
        addr=addr,
        magic_number=values[0],
        max_state=values[1],
        p_unwind_map=values[2],
        n_try_blocks=values[3],
        p_try_block_map=values[4],
        n_ip_map_entries=values[5],
        p_ip_to_state_map=values[6],
        p_es_type_list=values[7],
        eh_flags=values[8],
    )


EH4_SCOPETABLE_HEADER_SIZE = 16  # 4 * 4 bytes

EH4_SCOPETABLE_RECORD_SIZE = 12  # 3 * 4 bytes


class EH4ScopeTable:
    """Parsed _EH4_SCOPETABLE struct from a 32-bit PE binary."""

    __slots__ = (
        "addr",
        "eh_cookie_offset",
        "eh_cookie_xor_offset",
        "gs_cookie_offset",
        "gs_cookie_xor_offset",
        "records",
    )

    def __init__(
        self,
        addr: int,
        gs_cookie_offset: int,
        gs_cookie_xor_offset: int,
        eh_cookie_offset: int,
        eh_cookie_xor_offset: int,
        records: list[EH4ScopeRecord],
    ):
        self.addr = addr
        self.gs_cookie_offset = gs_cookie_offset
        self.gs_cookie_xor_offset = gs_cookie_xor_offset
        self.eh_cookie_offset = eh_cookie_offset
        self.eh_cookie_xor_offset = eh_cookie_xor_offset
        self.records = records

    @property
    def total_size(self) -> int:
        return EH4_SCOPETABLE_HEADER_SIZE + len(self.records) * EH4_SCOPETABLE_RECORD_SIZE

    def __repr__(self):
        return f"EH4ScopeTable(addr={self.addr:#x}, records={len(self.records)}, size={self.total_size})"


class EH4ScopeRecord:
    """Parsed _EH4_SCOPETABLE_RECORD struct from a 32-bit PE binary."""

    __slots__ = ("enclosing_level", "filter_func", "handler_func")

    def __init__(self, enclosing_level: int, filter_func: int, handler_func: int):
        self.enclosing_level = enclosing_level
        self.filter_func = filter_func
        self.handler_func = handler_func

    def __repr__(self):
        return (
            f"EH4ScopeRecord(enclosing={self.enclosing_level}, "
            f"filter={self.filter_func:#x}, handler={self.handler_func:#x})"
        )


def parse_eh4_scopetable(
    memory,
    addr: int,
    code_range: tuple[int, int] | None = None,
) -> EH4ScopeTable | None:
    """
    Parse an _EH4_SCOPETABLE at the given address.

    :param memory:      The loader memory interface.
    :param addr:        The virtual address of the _EH4_SCOPETABLE.
    :param code_range:  Optional (min_addr, max_addr) of executable memory.
                        When provided, FilterFunc and HandlerFunc pointers are
                        validated against this range.
    :return:            An EH4ScopeTable object, or None if parsing fails.
    """
    try:
        header = memory.load(addr, EH4_SCOPETABLE_HEADER_SIZE)
    except KeyError:
        log.debug("Failed to read _EH4_SCOPETABLE header at %#x", addr)
        return None

    if len(header) < EH4_SCOPETABLE_HEADER_SIZE:
        return None

    gs_cookie_off, gs_cookie_xor, eh_cookie_off, eh_cookie_xor = struct.unpack("<iiii", header)

    def _is_code_ptr(ptr: int) -> bool:
        if code_range is not None:
            return code_range[0] <= ptr < code_range[1]
        return ptr != 0

    records: list[EH4ScopeRecord] = []
    rec_base = addr + EH4_SCOPETABLE_HEADER_SIZE
    for i in range(64):  # reasonable upper bound
        try:
            data = memory.load(rec_base + i * EH4_SCOPETABLE_RECORD_SIZE, EH4_SCOPETABLE_RECORD_SIZE)
        except KeyError:
            break
        if len(data) < EH4_SCOPETABLE_RECORD_SIZE:
            break

        enclosing, filter_func, handler_func = struct.unpack("<iII", data)

        # Validate EnclosingLevel: must be -2 (top-level) or a valid prior index
        if enclosing != -2 and not 0 <= enclosing < i:
            break
        # HandlerFunc must point to executable code
        if handler_func == 0 or not _is_code_ptr(handler_func):
            break
        # FilterFunc must be 0 (__finally) or point to executable code (__except)
        if filter_func != 0 and not _is_code_ptr(filter_func):
            break

        records.append(EH4ScopeRecord(enclosing, filter_func, handler_func))

    if not records:
        return None

    return EH4ScopeTable(
        addr=addr,
        gs_cookie_offset=gs_cookie_off,
        gs_cookie_xor_offset=gs_cookie_xor,
        eh_cookie_offset=eh_cookie_off,
        eh_cookie_xor_offset=eh_cookie_xor,
        records=records,
    )


def parse_unwind_map(memory, addr: int, count: int) -> list[UnwindMapEntry]:
    """
    Parse an array of UnwindMapEntry structs.

    :param memory:  The loader memory interface.
    :param addr:    The virtual address of the first UnwindMapEntry.
    :param count:   The number of entries (maxState from FuncInfo).
    :return:        A list of UnwindMapEntry objects.
    """
    entries = []
    for i in range(count):
        entry_addr = addr + i * UNWINDMAPENTRY_SIZE
        try:
            data = memory.load(entry_addr, UNWINDMAPENTRY_SIZE)
        except KeyError:
            log.debug("Failed to read UnwindMapEntry at %#x", entry_addr)
            break

        if len(data) < UNWINDMAPENTRY_SIZE:
            break

        to_state, action = struct.unpack("<iI", data)
        entries.append(UnwindMapEntry(addr=entry_addr, to_state=to_state, action=action))

    return entries


class TryBlockMapEntry:
    """Parsed TryBlockMapEntry struct from a 32-bit PE binary."""

    __slots__ = ("addr", "catch_high", "handlers", "n_catches", "p_handler_array", "try_high", "try_low")

    def __init__(
        self,
        addr: int,
        try_low: int,
        try_high: int,
        catch_high: int,
        n_catches: int,
        p_handler_array: int,
        handlers: list[HandlerType],
    ):
        self.addr = addr
        self.try_low = try_low
        self.try_high = try_high
        self.catch_high = catch_high
        self.n_catches = n_catches
        self.p_handler_array = p_handler_array
        self.handlers = handlers

    def __repr__(self):
        return (
            f"TryBlockMapEntry(addr={self.addr:#x}, tryLow={self.try_low}, "
            f"tryHigh={self.try_high}, catchHigh={self.catch_high}, "
            f"nCatches={self.n_catches})"
        )


class HandlerType:
    """Parsed HandlerType struct from a 32-bit PE binary."""

    __slots__ = ("addr", "address_of_handler", "adjectives", "disp_catch_obj", "p_type")

    def __init__(
        self,
        addr: int,
        adjectives: int,
        p_type: int,
        disp_catch_obj: int,
        address_of_handler: int,
    ):
        self.addr = addr
        self.adjectives = adjectives
        self.p_type = p_type
        self.disp_catch_obj = disp_catch_obj
        self.address_of_handler = address_of_handler

    def __repr__(self):
        return (
            f"HandlerType(addr={self.addr:#x}, adj={self.adjectives}, "
            f"pType={self.p_type:#x}, handler={self.address_of_handler:#x})"
        )


def parse_handler_array(memory, addr: int, count: int) -> list[HandlerType]:
    """
    Parse an array of HandlerType structs.

    :param memory:  The loader memory interface.
    :param addr:    The virtual address of the first HandlerType.
    :param count:   The number of entries (nCatches from TryBlockMapEntry).
    :return:        A list of HandlerType objects.
    """
    handlers = []
    for i in range(count):
        h_addr = addr + i * HANDLERTYPE_SIZE
        try:
            data = memory.load(h_addr, HANDLERTYPE_SIZE)
        except KeyError:
            log.debug("Failed to read HandlerType at %#x", h_addr)
            break
        if len(data) < HANDLERTYPE_SIZE:
            break

        adjectives, p_type, disp_catch_obj, address_of_handler = struct.unpack("<IIiI", data)
        handlers.append(
            HandlerType(
                addr=h_addr,
                adjectives=adjectives,
                p_type=p_type,
                disp_catch_obj=disp_catch_obj,
                address_of_handler=address_of_handler,
            )
        )
    return handlers


def parse_try_block_map(memory, addr: int, count: int) -> list[TryBlockMapEntry]:
    """
    Parse an array of TryBlockMapEntry structs, including their nested
    HandlerType arrays.

    :param memory:  The loader memory interface.
    :param addr:    The virtual address of the first TryBlockMapEntry.
    :param count:   The number of entries (nTryBlocks from FuncInfo).
    :return:        A list of TryBlockMapEntry objects.
    """
    entries = []
    for i in range(count):
        entry_addr = addr + i * TRYBLOCKMAPENTRY_SIZE
        try:
            data = memory.load(entry_addr, TRYBLOCKMAPENTRY_SIZE)
        except KeyError:
            log.debug("Failed to read TryBlockMapEntry at %#x", entry_addr)
            break
        if len(data) < TRYBLOCKMAPENTRY_SIZE:
            break

        try_low, try_high, catch_high, n_catches, p_handler_array = struct.unpack("<iiiII", data)

        handlers: list[HandlerType] = []
        if n_catches > 0 and p_handler_array != 0:
            handlers = parse_handler_array(memory, p_handler_array, n_catches)

        entries.append(
            TryBlockMapEntry(
                addr=entry_addr,
                try_low=try_low,
                try_high=try_high,
                catch_high=catch_high,
                n_catches=n_catches,
                p_handler_array=p_handler_array,
                handlers=handlers,
            )
        )
    return entries
