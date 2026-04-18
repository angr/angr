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
from collections import OrderedDict
from typing import TYPE_CHECKING

from angr.sim_type import SimStruct, SimTypeInt

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
EH_PROLOG3_COMMON = (
    b"\x50"
    b"\x64\xff\x35\x00\x00\x00\x00"
    b"\x8d\x44\x24\x0c"
    b"\x2b\x64\x24\x0c"
    b"\x53\x56\x57"
    b"\x89\x28"
    b"\x8b\xe8"
)

# After the common prefix + 8 bytes (security cookie xor + push), the
# distinguishing bytes at offset 31 are:
#   __EH_prolog3:       FF 75 FC       push [ebp-4]
#   __EH_prolog3_catch: 89 65 F0       mov [ebp-0x10], esp
#   __EH_prolog3_GS:    89 45 F0       mov [ebp-0x10], eax
EH_PROLOG3_DISCRIM_OFFSET = 31
EH_PROLOG3_DISCRIM = b"\xff"           # push [ebp-4]
EH_PROLOG3_CATCH_DISCRIM = b"\x89\x65"  # mov [ebp-0x10], esp
EH_PROLOG3_GS_DISCRIM = b"\x89\x45"    # mov [ebp-0x10], eax

# __SEH_prolog4 family common prefix (24 bytes starting at offset 5):
#   push <handler>;        68 xx xx xx xx          (offset 0-4, varies)
#   push dword ptr fs:[0]; 64 FF 35 00 00 00 00    (offset 5-11)
#   mov eax, [esp+0x10];   8B 44 24 10             (offset 12-15)
#   mov [esp+0x10], ebp;   89 6C 24 10             (offset 16-19)
#   lea ebp, [esp+0x10];   8D 6C 24 10             (offset 20-23)
#   sub esp, eax;          2B E0                   (offset 24-25)
#   push ebx; push esi; push edi;  53 56 57        (offset 26-28)
SEH_PROLOG4_COMMON = (
    b"\x64\xff\x35\x00\x00\x00\x00"
    b"\x8b\x44\x24\x10"
    b"\x89\x6c\x24\x10"
    b"\x8d\x6c\x24\x10"
    b"\x2b\xe0"
    b"\x53\x56\x57"
)

# After the common prefix + security cookie ops, the distinguishing byte at
# offset 39 is:
#   __SEH_prolog4:    50       push eax
#   __SEH_prolog4_GS: 89       mov [ebp-0x1c], eax
SEH_PROLOG4_DISCRIM_OFFSET = 39
SEH_PROLOG4_DISCRIM = b"\x50"    # push eax
SEH_PROLOG4_GS_DISCRIM = b"\x89"  # mov [ebp-0x1c], eax

FUNCINFO_MAGIC = 0x19930522

FUNCINFO_STRUCT = SimStruct(
    fields=OrderedDict(
        [
            ("magicNumber", SimTypeInt(signed=False)),
            ("maxState", SimTypeInt(signed=False)),
            ("pUnwindMap", SimTypeInt(signed=False)),
            ("nTryBlocks", SimTypeInt(signed=False)),
            ("pTryBlockMap", SimTypeInt(signed=False)),
            ("nIPMapEntries", SimTypeInt(signed=False)),
            ("pIPtoStateMap", SimTypeInt(signed=False)),
        ]
    ),
    name="FuncInfo",
)

FUNCINFO_SIZE = 28  # 7 * 4 bytes

UNWINDMAPENTRY_STRUCT = SimStruct(
    fields=OrderedDict(
        [
            ("toState", SimTypeInt(signed=True)),
            ("action", SimTypeInt(signed=False)),
        ]
    ),
    name="UnwindMapEntry",
)

UNWINDMAPENTRY_SIZE = 8  # 2 * 4 bytes


class FuncInfo:
    """Parsed FuncInfo struct from a 32-bit PE binary."""

    __slots__ = (
        "addr",
        "magic_number",
        "max_state",
        "p_unwind_map",
        "n_try_blocks",
        "p_try_block_map",
        "n_ip_map_entries",
        "p_ip_to_state_map",
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
    ):
        self.addr = addr
        self.magic_number = magic_number
        self.max_state = max_state
        self.p_unwind_map = p_unwind_map
        self.n_try_blocks = n_try_blocks
        self.p_try_block_map = p_try_block_map
        self.n_ip_map_entries = n_ip_map_entries
        self.p_ip_to_state_map = p_ip_to_state_map

    def __repr__(self):
        return (
            f"FuncInfo(addr={self.addr:#x}, magic={self.magic_number:#x}, "
            f"maxState={self.max_state}, pUnwindMap={self.p_unwind_map:#x}, "
            f"nTryBlocks={self.n_try_blocks})"
        )


class UnwindMapEntry:
    """Parsed UnwindMapEntry struct from a 32-bit PE binary."""

    __slots__ = ("addr", "to_state", "action")

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
    except Exception:
        log.debug("Failed to read FuncInfo at %#x", addr)
        return None

    if len(data) < FUNCINFO_SIZE:
        return None

    values = struct.unpack("<IIIIIII", data)
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
        except Exception:
            log.debug("Failed to read UnwindMapEntry at %#x", entry_addr)
            break

        if len(data) < UNWINDMAPENTRY_SIZE:
            break

        to_state, action = struct.unpack("<iI", data)
        entries.append(UnwindMapEntry(addr=entry_addr, to_state=to_state, action=action))

    return entries
