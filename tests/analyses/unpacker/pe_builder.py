from __future__ import annotations

import struct

SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT = 0x200
IMAGE_BASE = 0x400000
IMAGE_BASE_64 = 0x140000000


def build_pe(
    sections: list[tuple[bytes, int, int, bytes, int]],
    entry_rva: int,
    is_64bit: bool = False,
    directories: dict[int, tuple[int, int]] | None = None,
) -> bytes:
    """
    Build a minimal PE file. Each section is (name, rva, virtual size, raw data, characteristics); directories maps
    a data-directory index to (rva, size).
    """
    headers_size = 0x400
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    image_size = max(
        rva + ((vsize + SECTION_ALIGNMENT - 1) & ~(SECTION_ALIGNMENT - 1)) for _, rva, vsize, _, _ in sections
    )
    if is_64bit:
        file_header = struct.pack("<HHIIIHH", 0x8664, len(sections), 0, 0, 0, 0xF0, 0x22)
        optional = struct.pack(
            "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
            0x20B, 14, 0, 0, 0, 0, entry_rva, 0x1000,
            IMAGE_BASE_64, SECTION_ALIGNMENT, FILE_ALIGNMENT, 6, 0, 0, 0, 6, 0, 0, image_size, headers_size, 0, 3, 0,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )  # fmt: skip
    else:
        file_header = struct.pack("<HHIIIHH", 0x14C, len(sections), 0, 0, 0, 0xE0, 0x102)
        optional = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x10B, 14, 0, 0, 0, 0, entry_rva, 0x1000, 0x1000,
            IMAGE_BASE, SECTION_ALIGNMENT, FILE_ALIGNMENT, 6, 0, 0, 0, 6, 0, 0, image_size, headers_size, 0, 3, 0,
            0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
        )  # fmt: skip
    data_dirs = bytearray(8 * 16)
    for index, (rva, size) in (directories or {}).items():
        struct.pack_into("<II", data_dirs, 8 * index, rva, size)
    table = bytearray()
    body = bytearray()
    offset = headers_size
    for name, rva, vsize, raw, characteristics in sections:
        raw_size = (len(raw) + FILE_ALIGNMENT - 1) & ~(FILE_ALIGNMENT - 1)
        table += struct.pack(
            "<8sIIIIIIHHI", name, vsize, rva, raw_size, offset if raw else 0, 0, 0, 0, 0, characteristics
        )
        body += raw.ljust(raw_size, b"\0")
        offset += raw_size
    header = bytes(dos) + b"PE\0\0" + file_header + optional + bytes(data_dirs) + bytes(table)
    return header.ljust(headers_size, b"\0") + bytes(body)


def fake_code(size: int, rva: int, functions: int = 30) -> bytes:
    """
    Bytes that look like compiler output to call-structure heuristics: every function is called three times.
    """
    code = bytearray(b"\x90" * size)
    targets = [rva + size - 0x10 * (i + 1) for i in range(functions)]
    pos = 0
    for target in targets:
        for _ in range(3):
            code[pos : pos + 5] = b"\xe8" + struct.pack("<i", target - (rva + pos + 5))
            pos += 8
    for target in targets:
        code[target - rva] = 0xC3
    return bytes(code)
