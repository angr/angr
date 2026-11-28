from __future__ import annotations

import lzma
import struct
from dataclasses import dataclass, field

import pefile

from angr.analyses.analysis import AnalysesHub, Analysis
from angr.errors import AngrError

from .pe_rebuilder import rebuild_pe

IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x80
_DEFAULT_LZMA_PROPS = bytes([0x5D, 0x00, 0x00, 0x00, 0x04])
_PROBE_SIZE = 0x1000


class VMProtectStaticError(AngrError):
    """
    The static VMProtect unpacker cannot handle the file.
    """


@dataclass
class VMProtectStaticResult:
    """
    The result of statically unpacking a VMProtect-packed PE.
    """

    image: bytes
    table_kind: str
    table_offset: int
    blocks: dict[str, int] = field(default_factory=dict)


def _lzma_decode(props: bytes, data: bytes, limit: int) -> bytes | None:
    packed = props[0]
    lc, rest = packed % 9, packed // 9
    lp, pb = rest % 5, rest // 5
    if pb > 4:
        return None
    filters = [
        {
            "id": lzma.FILTER_LZMA1,
            "lc": lc,
            "lp": lp,
            "pb": pb,
            "dict_size": max(struct.unpack_from("<I", props, 1)[0], 4096),
        }
    ]
    try:
        return lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filters).decompress(data, limit)
    except lzma.LZMAError:
        return None


def _rol32(value: int, count: int) -> int:
    count &= 31
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


class _Packed:
    """
    This class locates the PACKER_INFO table of VMProtect. The table has one pair of source RVA and destination RVA
    for each packed section.
    """

    def __init__(self, data: bytes):
        self.data = data
        self.pe = pefile.PE(data=data, fast_load=True)
        # A packed section has a virtual range but no bytes on disk.
        self.dests = [
            s
            for s in self.pe.sections
            if s.SizeOfRawData == 0 and s.Misc_VirtualSize and not s.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA
        ]
        self.dest_rvas = [s.VirtualAddress for s in self.dests]

    def offset(self, rva: int) -> int | None:
        try:
            off = self.pe.get_offset_from_rva(rva)
        except pefile.PEFormatError:
            return None
        return off if 0 <= off < len(self.data) else None

    def locate_plain(self) -> tuple[int, bytes, list[tuple[int, int]]] | None:
        """
        Before VMProtect 3.9, the table stores plaintext entries in section order. The entry before the plaintext
        entries points at the LZMA properties.
        """
        first = struct.pack("<I", self.dest_rvas[0])
        pos = -1
        while True:
            pos = self.data.find(first, pos + 1)
            if pos < 0:
                return None
            base = pos - 4
            if base < 8 or base + 8 * len(self.dests) > len(self.data):
                continue
            entries = [struct.unpack_from("<II", self.data, base + 8 * i) for i in range(len(self.dests))]
            if [dst for _, dst in entries] != self.dest_rvas:
                continue
            props_off = self.offset(struct.unpack_from("<I", self.data, base - 8)[0])
            candidates = [_DEFAULT_LZMA_PROPS]
            if props_off is not None:
                candidates.insert(0, self.data[props_off : props_off + 5])
            for props in candidates:
                if len(props) == 5 and all(self._probe(src, props) for src, _ in entries):
                    return base, props, entries

    def locate_encrypted(self) -> tuple[int, bytes, list[tuple[int, int]]] | None:
        """
        Since VMProtect 3.9, the table stores each destination as dst ^ rol(key, 7 * index).
        We know the destinations, so we derive the key from entry 0. Every other entry must decrypt to a distinct
        packed section.
        """
        count = len(self.dests)
        if count < 2:
            return None
        known = set(self.dest_rvas)
        data = self.data
        # The source of a block is in a file-backed section, so we reject any other source.
        backed = [
            (s.VirtualAddress, s.VirtualAddress + s.SizeOfRawData, s.PointerToRawData - s.VirtualAddress)
            for s in self.pe.sections
            if s.SizeOfRawData
        ]
        size = len(data)
        for start, end, _ in ((s.PointerToRawData, s.PointerToRawData + s.SizeOfRawData, 0) for s in self.pe.sections):
            for pos in range(start, min(end, size) - 8 * count):
                src = int.from_bytes(data[pos : pos + 4], "little")
                delta = next((d for lo, hi, d in backed if lo <= src < hi), None)
                if delta is None or src + delta >= size or data[src + delta] != 0:
                    continue
                stored = int.from_bytes(data[pos + 4 : pos + 8], "little")
                for seed in self.dest_rvas:
                    key = stored ^ seed
                    entries: list[tuple[int, int]] = []
                    for idx in range(count):
                        entry_src, enc = struct.unpack_from("<II", data, pos + 8 * idx)
                        dst = enc ^ _rol32(key, 7 * idx)
                        if dst not in known or any(dst == other for _, other in entries):
                            break
                        entries.append((entry_src, dst))
                    if len(entries) == count and all(
                        self._probe(entry_src, _DEFAULT_LZMA_PROPS) for entry_src, _ in entries
                    ):
                        return pos, _DEFAULT_LZMA_PROPS, entries
        return None

    def _probe(self, src_rva: int, props: bytes) -> bool:
        off = self.offset(src_rva)
        return off is not None and bool(_lzma_decode(props, self.data[off:], _PROBE_SIZE))


def has_packer_info(data: bytes) -> bool:
    """
    This function returns whether the file has a plaintext VMProtect PACKER_INFO table for the sections that have no
    bytes on disk.
    """
    packed = _Packed(data)
    return bool(packed.dests) and packed.locate_plain() is not None


def unpack_vmprotect_static(data: bytes) -> VMProtectStaticResult:
    """
    This function statically unpacks a VMProtect-packed PE. We find the PACKER_INFO table and decompress each block
    with LZMA into the memory image.
    We do not restore the entry point and the import table.

    The algorithm follows VMPStatic, which is MIT-licensed and available at https://github.com/notsnakesilent/VMPStatic.
    """
    packed = _Packed(data)
    pe = packed.pe
    if not packed.dests:
        raise VMProtectStaticError("No packed (virtual-only) sections")
    kind = "plain"
    located = packed.locate_plain()
    if located is None:
        kind = "encrypted"
        located = packed.locate_encrypted()
    if located is None:
        raise VMProtectStaticError("PACKER_INFO table not found")
    table_offset, props, entries = located

    image = bytearray(pe.OPTIONAL_HEADER.SizeOfImage)
    header_size = min(pe.OPTIONAL_HEADER.SizeOfHeaders, len(data))
    image[:header_size] = data[:header_size]
    for section in pe.sections:
        raw = section.get_data()[: section.SizeOfRawData]
        raw = raw[: max(0, len(image) - section.VirtualAddress)]
        image[section.VirtualAddress : section.VirtualAddress + len(raw)] = raw

    result = VMProtectStaticResult(b"", kind, table_offset)
    bounds = [*sorted(s.VirtualAddress for s in pe.sections), len(image)]
    for src, dst in entries:
        src_off = packed.offset(src)
        if src_off is None:
            raise VMProtectStaticError(f"Block source RVA {src:#x} is outside the file")
        limit = next(b for b in bounds if b > dst) - dst
        block = _lzma_decode(props, data[src_off:], limit)
        if not block:
            raise VMProtectStaticError(f"LZMA decompression failed for the block at RVA {dst:#x}")
        image[dst : dst + len(block)] = block
        name = next(s.Name.split(b"\0")[0].decode("latin-1") for s in pe.sections if s.VirtualAddress == dst)
        result.blocks[name] = len(block)
    result.image = bytes(image)
    return result


class VMProtectStaticUnpacker(Analysis):
    """
    This analysis statically unpacks the VMProtect-packed main object.

    `unpacked` holds a rebuilt PE file whose original sections are decompressed. The entry point of the rebuilt PE file
    still points into the VMProtect loader.
    """

    def __init__(self):
        binary = self.project.loader.main_object.binary
        if binary is None:
            raise ValueError("VMProtectStaticUnpacker requires a file-backed main object")
        with open(binary, "rb") as f:
            data = f.read()
        self.result = unpack_vmprotect_static(data)
        self.unpacked: bytes = rebuild_pe(self.result.image)


AnalysesHub.register_default("VMProtectStaticUnpacker", VMProtectStaticUnpacker)
