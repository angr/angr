from __future__ import annotations

import struct

IMAGE_FILE_MACHINE_I386 = 0x14C
IMAGE_FILE_MACHINE_AMD64 = 0x8664

# Each export gets a 16-byte slot: a hot-patchable prologue followed by a jump back to the slot start. Only the slot
# start is trapped, so code that runs a stolen copy of the prologue and jumps into the middle still reaches the trap.
SLOT_SIZE = 16
_SLOT_X86 = bytes.fromhex("8bff 558bec 5d ebf8").ljust(SLOT_SIZE, b"\xcc")
_SLOT_AMD64 = bytes.fromhex("48895c2408 488b5c2408 ebf4").ljust(SLOT_SIZE, b"\xcc")

_HEADER_SIZE = 0x1000
_SPARE_SLOTS = 512


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


class FakeModule:
    """
    A synthetic DLL image: a PE header, one trap slot per export, and a real export directory, so both
    GetProcAddress-style lookups and manual export-table walks resolve to trap addresses.
    """

    def __init__(self, name: str, base: int, export_names: list[str], is_64bit: bool, ordinal_base: int = 1):
        self.name = name.lower()
        self.base = base
        self.is_64bit = is_64bit
        self.ordinal_base = ordinal_base
        self.exports: dict[str, int] = {}
        self.slot_names: dict[int, str] = {}
        self._code_rva = _HEADER_SIZE
        self._next_spare = 0

        names = sorted(set(export_names))
        self._static_count = len(names)
        for idx, export in enumerate(names):
            self._register(export, idx)
        code_size = _align((len(names) + _SPARE_SLOTS) * SLOT_SIZE, 0x1000)
        self._export_rva = self._code_rva + code_size
        export_data = self._build_export_directory(names)
        self.size = _align(self._export_rva + len(export_data), 0x10000)
        slot = _SLOT_AMD64 if is_64bit else _SLOT_X86
        self.image = (
            self._build_header(code_size, len(export_data)).ljust(_HEADER_SIZE, b"\0")
            + (slot * (code_size // SLOT_SIZE))
            + export_data
        ).ljust(self.size, b"\0")

    def _register(self, name: str, idx: int) -> int:
        addr = self.base + self._code_rva + idx * SLOT_SIZE
        self.exports[name] = addr
        self.slot_names[addr] = name
        return addr

    @property
    def code_range(self) -> tuple[int, int]:
        return self.base + self._code_rva, self.base + self._export_rva

    def resolve(self, name: str, create: bool = True) -> int | None:
        """
        Get the trap address of an export. Unknown names get a spare slot (reachable by address only).
        """
        addr = self.exports.get(name)
        if addr is None and create and self._next_spare < _SPARE_SLOTS:
            addr = self._register(name, self._static_count + self._next_spare)
            self._next_spare += 1
        return addr

    def resolve_ordinal(self, ordinal: int) -> int | None:
        idx = ordinal - self.ordinal_base
        if 0 <= idx < self._static_count:
            return self.base + self._code_rva + idx * SLOT_SIZE
        return self.resolve(f"ordinal_{ordinal}")

    def _build_export_directory(self, names: list[str]) -> bytes:
        count = len(names)
        dir_size = 40
        eat_off = dir_size
        npt_off = eat_off + 4 * count
        ord_off = npt_off + 4 * count
        strings_off = ord_off + 2 * count
        # system DLLs conventionally export an upper-case module name
        stem, _, ext = self.name.rpartition(".")
        export_name = self.name if stem == "ntdll" else f"{stem.upper()}.{ext}"
        strings = bytearray(export_name.encode("ascii", "replace") + b"\0")
        name_rvas = []
        for export in names:
            name_rvas.append(self._export_rva + strings_off + len(strings))
            strings += export.encode("ascii", "replace") + b"\0"
        directory = struct.pack(
            "<IIHHIIIIIII",
            0,
            0,
            0,
            0,
            self._export_rva + strings_off,
            self.ordinal_base,
            count,
            count,
            self._export_rva + eat_off,
            self._export_rva + npt_off,
            self._export_rva + ord_off,
        )
        eat = b"".join(struct.pack("<I", self._code_rva + i * SLOT_SIZE) for i in range(count))
        npt = b"".join(struct.pack("<I", rva) for rva in name_rvas)
        ordinals = b"".join(struct.pack("<H", i) for i in range(count))
        return directory + eat + npt + ordinals + bytes(strings)

    def _build_header(self, code_size: int, export_size: int) -> bytes:
        e_lfanew = 0x80
        dos = bytearray(e_lfanew)
        dos[0:2] = b"MZ"
        struct.pack_into("<I", dos, 0x3C, e_lfanew)
        machine = IMAGE_FILE_MACHINE_AMD64 if self.is_64bit else IMAGE_FILE_MACHINE_I386
        opt_size = 0xF0 if self.is_64bit else 0xE0
        file_header = struct.pack("<HHIIIHH", machine, 2, 0, 0, 0, opt_size, 0x2102 if not self.is_64bit else 0x2022)
        image_size = _align(self._export_rva + export_size, 0x10000)
        if self.is_64bit:
            opt = struct.pack(
                "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
                0x20B, 14, 0, code_size, export_size, 0, 0, self._code_rva,
                self.base, 0x1000, 0x1000, 10, 0, 10, 0, 10, 0, 0, image_size, _HEADER_SIZE, 0, 3, 0x4140,
                0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
            )  # fmt: skip
        else:
            opt = struct.pack(
                "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
                0x10B, 14, 0, code_size, export_size, 0, 0, self._code_rva, self._export_rva,
                self.base, 0x1000, 0x1000, 10, 0, 10, 0, 10, 0, 0, image_size, _HEADER_SIZE, 0, 3, 0x4140,
                0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
            )  # fmt: skip
        data_dirs = struct.pack("<II", self._export_rva, export_size) + bytes(8 * 15)
        sections = self._section_header(b".text", self._code_rva, code_size, 0x60000020) + self._section_header(
            b".rdata", self._export_rva, _align(export_size, 0x1000), 0x40000040
        )
        return bytes(dos) + b"PE\0\0" + file_header + opt + data_dirs + sections

    @staticmethod
    def _section_header(name: bytes, rva: int, size: int, characteristics: int) -> bytes:
        return struct.pack("<8sIIIIIIHHI", name, size, rva, size, rva, 0, 0, 0, 0, characteristics)
