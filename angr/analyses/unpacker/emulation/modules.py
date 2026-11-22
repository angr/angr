from __future__ import annotations

import bisect
import struct

IMAGE_FILE_MACHINE_I386 = 0x14C
IMAGE_FILE_MACHINE_AMD64 = 0x8664

# Each export gets a 16-byte slot: a short prologue, then an absolute jump back to the slot start. Only the slot start
# is trapped. Protectors run stolen copies of an API's first instructions from their own memory; because the jump
# is absolute, a copy of any length, and a jump into the middle of the slot, still end at the trap.
SLOT_SIZE = 16
# 32-bit ntdll routines whose bodies protectors read or call through KUSER_SHARED_DATA.SystemCall
_X86_NTDLL_BODIES = {
    "KiFastSystemCall": bytes.fromhex("8bd4 0f34 c3"),
    "KiFastSystemCallRet": bytes.fromhex("c3"),
    "KiIntSystemCall": bytes.fromhex("8d542408 cd2e c3"),
}

_HEADER_SIZE = 0x1000
_SPARE_SLOTS = 512


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


_DOS_STUB = bytes.fromhex("0e1fba0e00b409cd21b8014ccd21") + b"This program cannot be run in DOS mode.\r\r\n$"


class FakeModule:
    """
    A synthetic DLL image: a PE header, one trap slot per export, and a real export directory, so both
    GetProcAddress-style lookups and manual export-table walks resolve to trap addresses.
    """

    def __init__(
        self,
        name: str,
        base: int,
        export_names: list[str],
        is_64bit: bool,
        ordinals: dict[int, str | None] | None = None,
        syscalls: dict[str, int] | None = None,
        stack_bytes: dict[str, int] | None = None,
        listed: bool = False,
    ):
        """
        :param ordinals:    Known export ordinals: the export's name, or None for an export without a name. Other
                            exports get the ordinals that follow.
        :param listed:      Whether export_names is the real DLL's export list (and not only the names somebody
                            asked for): lookups of other names should then fail.
        """
        self.name = name.lower()
        self.listed = listed
        self.base = base
        self.is_64bit = is_64bit
        self.exports: dict[str, int] = {}
        self.slot_names: dict[int, str] = {}
        self._code_rva = _HEADER_SIZE
        self._next_spare = 0

        ordinals = ordinals or {}
        names = sorted(set(export_names) | {export for export in ordinals.values() if export is not None})
        # slots: the named exports in name order, then the exports that only have an ordinal
        slot_of = {export: idx for idx, export in enumerate(names)}
        self._ordinal_slots: dict[int, int] = {}
        self._slot_ordinals: dict[int, int] = {}
        slot_count = len(names)
        for ordinal, export in sorted(ordinals.items()):
            if export is None:
                self._ordinal_slots[ordinal] = slot_count
                self._register(f"ordinal_{ordinal}", slot_count)
                slot_count += 1
            else:
                self._ordinal_slots[ordinal] = slot_of[export]
        for ordinal, idx in self._ordinal_slots.items():
            self._slot_ordinals.setdefault(idx, ordinal)
        self.ordinal_base = min(ordinals, default=1)
        next_ordinal = max(ordinals, default=0) + 1
        for export, idx in slot_of.items():
            self._register(export, idx)
            if idx not in self._slot_ordinals:
                self._ordinal_slots[next_ordinal] = idx
                self._slot_ordinals[idx] = next_ordinal
                next_ordinal += 1
        self._static_count = slot_count
        code_size = _align((slot_count + _SPARE_SLOTS) * SLOT_SIZE, 0x1000)
        self._export_rva = self._code_rva + code_size
        export_data = self._build_export_directory(names)
        self.size = _align(self._export_rva + len(export_data), 0x10000)
        code = bytearray()
        for addr in range(base + self._code_rva, base + self._code_rva + code_size, SLOT_SIZE):
            code += self._slot(addr)
        if syscalls:
            # system-call stubs must look real: protectors read the number out of them, compare neighbouring stubs,
            # or reject foreign bytes
            for idx, export in enumerate(names):
                number = syscalls.get(export)
                if number is not None:
                    code[idx * SLOT_SIZE : (idx + 1) * SLOT_SIZE] = self._syscall_stub(
                        number, (stack_bytes or {}).get(export, 0)
                    )
            if not is_64bit:
                for export, body in _X86_NTDLL_BODIES.items():
                    idx = bisect.bisect_left(names, export)
                    if idx < len(names) and names[idx] == export:
                        code[idx * SLOT_SIZE : (idx + 1) * SLOT_SIZE] = body.ljust(SLOT_SIZE, b"\x90")
        self.image = (
            self._build_header(code_size, len(export_data)).ljust(_HEADER_SIZE, b"\0") + bytes(code) + export_data
        ).ljust(self.size, b"\0")

    def _slot(self, addr: int) -> bytes:
        if self.is_64bit:
            # mov r11, rsp; nop; mov rax, addr; jmp rax
            return b"\x4c\x8b\xdc\x90\x48\xb8" + struct.pack("<Q", addr) + b"\xff\xe0"
        # mov edi, edi; push ebp; mov ebp, esp; pop ebp; push addr; ret
        return (b"\x8b\xff\x55\x8b\xec\x5d\x68" + struct.pack("<I", addr) + b"\xc3").ljust(SLOT_SIZE, b"\x90")

    def _syscall_stub(self, number: int, stack_bytes: int) -> bytes:
        if self.is_64bit:
            stub = b"\x4c\x8b\xd1\xb8" + struct.pack("<I", number) + b"\x0f\x05\xc3"
            return stub.ljust(SLOT_SIZE, b"\xcc")
        # mov eax, number; mov edx, 0x7ffe0300; call [edx]; ret n
        ret = b"\xc2" + struct.pack("<H", stack_bytes) if stack_bytes else b"\xc3"
        return (b"\xb8" + struct.pack("<I", number) + b"\xba\x00\x03\xfe\x7f\xff\x12" + ret).ljust(SLOT_SIZE, b"\x90")

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

    def resolve_ordinal(self, ordinal: int, create: bool = True) -> int | None:
        idx = self._ordinal_slots.get(ordinal)
        if idx is not None:
            return self.base + self._code_rva + idx * SLOT_SIZE
        return self.resolve(f"ordinal_{ordinal}", create)

    def unnamed_ordinal(self, addr: int) -> int | None:
        """
        The ordinal of the export at a trap address if that export has no name.
        """
        name = self.slot_names.get(addr, "")
        return int(name[8:]) if name.startswith("ordinal_") and name[8:].isdigit() else None

    def _build_export_directory(self, names: list[str]) -> bytes:
        count = len(names)
        functions = max(self._ordinal_slots, default=self.ordinal_base - 1) - self.ordinal_base + 1
        dir_size = 40
        eat_off = dir_size
        npt_off = eat_off + 4 * functions
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
            functions,
            count,
            self._export_rva + eat_off,
            self._export_rva + npt_off,
            self._export_rva + ord_off,
        )
        eat = bytearray(4 * functions)
        for ordinal, idx in self._ordinal_slots.items():
            struct.pack_into("<I", eat, 4 * (ordinal - self.ordinal_base), self._code_rva + idx * SLOT_SIZE)
        npt = b"".join(struct.pack("<I", rva) for rva in name_rvas)
        name_ordinals = b"".join(
            struct.pack("<H", self._slot_ordinals[idx] - self.ordinal_base) for idx in range(count)
        )
        return directory + bytes(eat) + npt + name_ordinals + bytes(strings)

    def _build_header(self, code_size: int, export_size: int) -> bytes:
        e_lfanew = 0x80
        dos = bytearray(e_lfanew)
        dos[0:2] = b"MZ"
        struct.pack_into("<I", dos, 0x3C, e_lfanew)
        # the linker's DOS stub: code that finds a system DLL by scanning memory checks for its text at 0x4E
        dos[0x40 : 0x40 + len(_DOS_STUB)] = _DOS_STUB
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
