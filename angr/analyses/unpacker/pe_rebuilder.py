from __future__ import annotations

import struct
from dataclasses import dataclass

import pefile

_SECTION_HEADER_SIZE = 40
_DIR_IMPORT = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
_DIR_SECURITY = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
_DIR_BOUND_IMPORT = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"]
_DIR_IAT = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IAT"]


@dataclass(frozen=True)
class RecoveredImport:
    """
    One import-address-table slot recovered from a memory image.
    """

    iat_rva: int
    dll: str
    name: str | None
    ordinal: int = 0


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _import_runs(imports: list[RecoveredImport], ptr_size: int) -> list[list[RecoveredImport]]:
    runs: list[list[RecoveredImport]] = []
    for imp in sorted(imports, key=lambda i: i.iat_rva):
        last = runs[-1][-1] if runs else None
        if last is not None and last.dll == imp.dll and imp.iat_rva == last.iat_rva + ptr_size:
            runs[-1].append(imp)
        else:
            runs.append([imp])
    return runs


def _build_import_section(imports: list[RecoveredImport], section_rva: int, is_64bit: bool) -> tuple[bytes, int]:
    """
    Build import descriptors whose FirstThunk fields point at the IAT slots already in the image.
    """
    ptr_size = 8 if is_64bit else 4
    ptr_fmt = "<Q" if is_64bit else "<I"
    ordinal_flag = 1 << (63 if is_64bit else 31)
    runs = _import_runs(imports, ptr_size)
    descriptors_size = 20 * (len(runs) + 1)
    lookup_size = sum((len(run) + 1) * ptr_size for run in runs)
    strings = bytearray()
    string_base = section_rva + descriptors_size + lookup_size
    descriptors = bytearray()
    lookups = bytearray()
    for run in runs:
        lookup_rva = section_rva + descriptors_size + len(lookups)
        for imp in run:
            if imp.name is None:
                lookups += struct.pack(ptr_fmt, ordinal_flag | imp.ordinal)
            else:
                lookups += struct.pack(ptr_fmt, string_base + len(strings))
                strings += b"\0\0" + imp.name.encode("latin-1", "replace") + b"\0"
                if len(strings) % 2:
                    strings += b"\0"
        lookups += bytes(ptr_size)
        name_rva = string_base + len(strings)
        strings += run[0].dll.encode("latin-1", "replace") + b"\0"
        descriptors += struct.pack("<IIIII", lookup_rva, 0, 0, name_rva, run[0].iat_rva)
    descriptors += bytes(20)
    return bytes(descriptors + lookups + strings), descriptors_size


def rebuild_pe(
    image: bytes,
    entry_rva: int | None = None,
    imports: list[RecoveredImport] | None = None,
    import_section_name: bytes = b".angr_i",
) -> bytes:
    """
    Turn a memory image of a PE (headers included, sections at their RVAs) into a loadable PE file.

    Every section's raw data is realigned to its virtual address. When imports are given, a new section with fresh
    import descriptors is appended and the import directory is pointed at it.
    """
    out = bytearray(image)
    pe = pefile.PE(data=bytes(image[:0x1000]), fast_load=True)
    is_64bit = pe.OPTIONAL_HEADER.Magic == 0x20B
    opt = pe.OPTIONAL_HEADER.get_file_offset()
    section_alignment = max(pe.OPTIONAL_HEADER.SectionAlignment, 0x200)
    table = opt + pe.FILE_HEADER.SizeOfOptionalHeader
    count = pe.FILE_HEADER.NumberOfSections
    dirs = opt + (112 if is_64bit else 96)
    num_dirs = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    end = 0
    for idx in range(count):
        off = table + idx * _SECTION_HEADER_SIZE
        vsize, rva, raw_size = struct.unpack_from("<III", out, off + 8)
        size = _align(max(vsize, raw_size if vsize == 0 else 0), section_alignment)
        size = min(size, max(len(out) - rva, 0))
        struct.pack_into("<I", out, off + 8, vsize or size)
        struct.pack_into("<II", out, off + 16, size, rva)
        end = max(end, rva + size)
    end = _align(end, section_alignment)
    del out[end:]
    out += bytes(end - len(out))

    if imports:
        if table + (count + 1) * _SECTION_HEADER_SIZE > pe.OPTIONAL_HEADER.SizeOfHeaders:
            raise ValueError("No room in the PE header for an import section")
        content, descriptors_size = _build_import_section(imports, end, is_64bit)
        size = _align(len(content), section_alignment)
        struct.pack_into(
            "<8sIIIIIIHHI", out, table + count * _SECTION_HEADER_SIZE,
            import_section_name, len(content), end, size, end, 0, 0, 0, 0, 0xC0000040,
        )  # fmt: skip
        struct.pack_into("<H", out, pe.FILE_HEADER.get_file_offset() + 2, count + 1)
        out += content.ljust(size, b"\0")
        if num_dirs > _DIR_IMPORT:
            struct.pack_into("<II", out, dirs + 8 * _DIR_IMPORT, end, descriptors_size)
        if num_dirs > _DIR_IAT:
            struct.pack_into("<II", out, dirs + 8 * _DIR_IAT, 0, 0)
        end += size

    for index in (_DIR_SECURITY, _DIR_BOUND_IMPORT):
        if num_dirs > index:
            struct.pack_into("<II", out, dirs + 8 * index, 0, 0)
    struct.pack_into("<I", out, opt + 36, section_alignment)  # FileAlignment
    struct.pack_into("<I", out, opt + 56, end)  # SizeOfImage
    struct.pack_into("<I", out, opt + 64, 0)  # CheckSum
    if entry_rva is not None:
        struct.pack_into("<I", out, opt + 16, entry_rva)
    return bytes(out)
