from __future__ import annotations

import io
import struct

import angr
from angr.simos import SimWindows, SimWindows16


def _name_entry(name: bytes, ordinal: int) -> bytes:
    return bytes([len(name)]) + name + struct.pack("<H", ordinal)


def _minimal_windows_ne() -> bytes:
    """Build a copyright-free NE whose code lives above the native 16-bit flat range."""
    ne_offset = 0x40
    segment_table = 0x40
    resource_table = 0x50
    resident_table = 0x54
    resident_names = _name_entry(b"SYNTH", 0) + _name_entry(b"Start", 1) + b"\0"
    entry_table = resident_table + len(resident_names)
    entries = b"\x01\x02\x01\x00\x00\x00"  # one exported fixed entry in code segment 2
    data_offset = 0xB0
    code_offset = 0xC0
    code = b"\x1e\xc3"  # push ds; ret

    result = bytearray(code_offset + len(code))
    result[:2] = b"MZ"
    struct.pack_into("<I", result, 0x3C, ne_offset)

    header = memoryview(result)[ne_offset : ne_offset + 0x40]
    header[:2] = b"NE"
    struct.pack_into("<H", header, 0x04, entry_table)
    struct.pack_into("<H", header, 0x06, len(entries))
    struct.pack_into("<H", header, 0x0C, 2)  # MULTIPLEDATA executable
    struct.pack_into("<H", header, 0x0E, 1)  # automatic data segment
    struct.pack_into("<HH", header, 0x14, 0, 2)  # CS:IP = segment 2:0
    struct.pack_into("<HH", header, 0x18, 4, 1)  # SS:SP = segment 1:4
    struct.pack_into("<HH", header, 0x1C, 2, 0)
    struct.pack_into("<H", header, 0x22, segment_table)
    struct.pack_into("<H", header, 0x24, resource_table)
    struct.pack_into("<H", header, 0x26, resident_table)
    struct.pack_into("<H", header, 0x28, entry_table)
    struct.pack_into("<H", header, 0x2A, entry_table)
    struct.pack_into("<H", header, 0x32, 4)
    header[0x36] = 2  # Windows

    struct.pack_into("<4H", result, ne_offset + segment_table, data_offset >> 4, 4, 1, 4)
    struct.pack_into("<4H", result, ne_offset + segment_table + 8, code_offset >> 4, len(code), 0, len(code))
    struct.pack_into("<HH", result, ne_offset + resource_table, 4, 0)
    result[ne_offset + resident_table : ne_offset + resident_table + len(resident_names)] = resident_names
    result[ne_offset + entry_table : ne_offset + entry_table + len(entries)] = entries
    result[data_offset : data_offset + 4] = b"DATA"
    result[code_offset : code_offset + len(code)] = code
    return bytes(result)


def test_windows_ne_uses_static_win16_environment_and_decompiles():
    project = angr.Project(io.BytesIO(_minimal_windows_ne()), auto_load_libs=False)

    assert isinstance(project.simos, SimWindows16)
    assert not isinstance(project.simos, SimWindows)
    assert project.simos.name == "Win16"
    assert project.arch.name == "x86:LE:16:Protected Mode"
    assert project.entry == 0x10000

    block = project.factory.block(project.entry, size=2)
    assert block.instructions == 2
    assert block.vex.jumpkind == "Ijk_Ret"

    cfg = project.analyses.CFGFast(
        function_starts=[project.entry],
        regions=[(project.entry, project.entry + 2)],
        force_complete_scan=False,
        force_smart_scan=False,
        normalize=True,
        resolve_indirect_jumps=False,
    )
    function = cfg.kb.functions[project.entry]
    decompilation = project.analyses.Decompiler(
        function,
        cfg=cfg.model,
        fail_fast=False,  # pyright: ignore[reportCallIssue]
    )

    assert decompilation.codegen is not None
    assert not decompilation.errors
