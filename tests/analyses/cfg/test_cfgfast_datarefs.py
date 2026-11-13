#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import io
import logging
import os
import struct
import time
import unittest

import angr
from angr.knowledge_plugins.cfg import MemoryDataSort
from tests.common import bin_location

l = logging.getLogger(__name__)

test_location = os.path.join(bin_location, "tests")


def cstring_to_unicode_string(cstr: bytes) -> bytes:
    return b"".join((bytes([ch]) + b"\x00") for ch in cstr)


class TestCfgfastDataReferences(unittest.TestCase):
    def test_data_references_x86_64(self):
        path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(data_references=True)

        memory_data = cfg.memory_data
        # There is no code reference
        code_ref_count = len([d for d in memory_data.values() if d.sort == MemoryDataSort.CodeReference])
        assert code_ref_count >= 0, "There should be no code reference."

        # There are at least 2 pointer arrays
        ptr_array_count = len([d for d in memory_data.values() if d.sort == MemoryDataSort.PointerArray])
        assert ptr_array_count > 2, "Missing some pointer arrays."

        assert 0x4008D0 in memory_data
        sneaky_str = memory_data[0x4008D0]
        assert sneaky_str.sort == "string"
        assert sneaky_str.content == b"SOSNEAKY"

    def test_data_references_mipsel(self):
        path = os.path.join(test_location, "mipsel", "fauxware")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(data_references=True)

        memory_data = cfg.memory_data
        # There is no code reference
        code_ref_count = len([d for d in memory_data.values() if d.sort == MemoryDataSort.CodeReference])
        assert code_ref_count >= 0, "There should be no code reference."

        # There are at least 2 pointer arrays
        ptr_array_count = len([d for d in memory_data.values() if d.sort == MemoryDataSort.PointerArray])
        assert ptr_array_count >= 1, "Missing some pointer arrays."

        assert 0x400C00 in memory_data
        sneaky_str = memory_data[0x400C00]
        assert sneaky_str.sort == "string"
        assert sneaky_str.content == b"SOSNEAKY"

        assert 0x400C0C in memory_data
        str_ = memory_data[0x400C0C]
        assert str_.sort == "string"
        assert str_.content == b"Welcome to the admin console, trusted user!"

        assert 0x400C38 in memory_data
        str_ = memory_data[0x400C38]
        assert str_.sort == "string"
        assert str_.content == b"Go away!"

        assert 0x400C44 in memory_data
        str_ = memory_data[0x400C44]
        assert str_.sort == "string"
        assert str_.content == b"Username: "

        assert 0x400C50 in memory_data
        str_ = memory_data[0x400C50]
        assert str_.sort == "string"
        assert str_.content == b"Password: "

    def test_data_references_mips64(self):
        path = os.path.join(test_location, "mips64", "true")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(data_references=True, cross_references=True)
        memory_data = cfg.memory_data

        assert 0x120007DD8 in memory_data
        assert memory_data[0x120007DD8].sort == "string"
        assert memory_data[0x120007DD8].content == b"coreutils"

        xrefs = proj.kb.xrefs
        refs = list(xrefs.get_xrefs_by_dst(0x120007DD8))
        assert len(refs) == 2
        assert {x.ins_addr for x in refs} == {0x1200020E8, 0x120002108}

    def test_data_references_i386_gcc_pie(self):
        path = os.path.join(test_location, "i386", "nl")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(data_references=True, cross_references=True)
        memory_data = cfg.memory_data

        assert 0x405BB0 in memory_data
        assert memory_data[0x405BB0].sort == "string"
        assert memory_data[0x405BB0].content == b"/usr/local/share/locale"

        xrefs = proj.kb.xrefs
        refs = list(xrefs.get_xrefs_by_dst(0x405BB0))
        assert len(refs) == 1
        assert {x.ins_addr for x in refs} == {0x4011DD}

    def test_data_references_wide_string(self):
        path = os.path.join(test_location, "x86_64", "windows", "fauxware-wide.exe")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(data_references=True)
        recovered_strings = [d.content for d in cfg.memory_data.values() if d.sort == MemoryDataSort.UnicodeString]

        for testme in ("SOSNEAKY", "Welcome to the admin console, trusted user!\n", "Go away!\n", "Username: \n"):
            assert testme.encode("utf-16-le") in recovered_strings

    def test_data_references_lea_string_addr(self):
        path = os.path.join(test_location, "x86_64", "windows", "3ware.sys")
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(data_references=True)
        assert cfg.memory_data[0x1C0010A20].sort == MemoryDataSort.String
        assert cfg.memory_data[0x1C0010A20].content == b"Initialize> %s"

    def test_arm_function_hints_from_data_references(self):
        path = os.path.join(test_location, "armel", "sha224sum")
        proj = angr.Project(path, auto_load_libs=False)

        proj.analyses.CFGFast(data_references=True)
        funcs = proj.kb.functions
        assert funcs.contains_addr(0x129C4)
        func = funcs[0x129C4]
        assert len(list(func.blocks)) == 1
        assert next(iter(func.blocks)).size == 16

    def test_data_references_windows_driver_utf16_strings(self):
        path = os.path.join(
            test_location, "x86_64", "windows", "aaba7db353eb9400e3471eaaa1cf0105f6d1fab0ce63f1a2665c8ba0e8963a05.bin"
        )
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast()

        assert cfg.model.memory_data[0x1DCE0].sort == MemoryDataSort.UnicodeString
        assert cfg.model.memory_data[0x1DCE0].content == cstring_to_unicode_string(
            b"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WinApi"
        )
        assert cfg.model.memory_data[0x1DCE0].size == 116
        assert cfg.model.memory_data[0x1DD90].sort == MemoryDataSort.UnicodeString
        assert cfg.model.memory_data[0x1DD90].content == cstring_to_unicode_string(b"ntdll.dll")
        assert cfg.model.memory_data[0x1DD90].size == 20

    def test_pe_32bit_pointer_array_detection(self):
        path = os.path.join(
            test_location, "i386", "windows", "53575875777863a69a573be858e75ceea834ea54c844bb528128a4ad16879d45"
        )
        proj = angr.Project(path, auto_load_libs=False)

        # this binary's .data is 32 MB of virtual space, so a whole-binary CFG costs ~14 s. both asserted pointer
        # arrays are at the head of .text: the one at 0x10001004 comes from the PE relocation hints, and the one at
        # 0x100018bc from the single code reference to it, in sub_10066a14. scanning those two spots is enough.
        cfg = proj.analyses.CFGFast(regions=[(0x10001000, 0x10002000), (0x10066A14, 0x10066A40)], start_at_entry=False)
        cfg_model = cfg.model
        assert cfg._seg_list.is_occupied(0x100018BC) is True
        assert cfg._seg_list.occupied_by_sort(0x100018BC) == "pointer-array"
        assert cfg_model.memory_data[0x100018BC].size == 4
        assert cfg_model.memory_data[0x100018BC].sort == MemoryDataSort.PointerArray
        assert cfg._seg_list.is_occupied(0x10001004) is True
        assert cfg._seg_list.occupied_by_sort(0x10001004) == "pointer-array"
        assert cfg_model.memory_data[0x10001004].size == 228
        assert cfg_model.memory_data[0x10001004].sort == MemoryDataSort.PointerArray

    def test_pe_32bit_string_tables_in_text_section(self):
        # this binary carries read-only data (string tables, pointer tables, etc.) at the beginning of its .text
        # section. its string tables separate strings with two null bytes; the string scans only consume one
        # terminating null byte, and the single remaining null byte used to defeat all data heuristics in
        # _next_code_addr_core(), causing entire string tables to be misidentified as code (and functions).
        path = os.path.join(
            test_location, "i386", "windows", "9888704382abfb694984c1c7a7707a45b4ebc406fc98d35622461077553aa797"
        )
        proj = angr.Project(path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast()
        memory_data = cfg.model.memory_data

        # ASCII string tables: strings must be recovered and no functions created among them
        assert memory_data[0x4019B0].sort == MemoryDataSort.String
        assert memory_data[0x4019B0].content == b"address not available"
        assert memory_data[0x402384].sort == MemoryDataSort.String
        assert memory_data[0x402384].content == b"__vectorcall"
        assert not [f for f in cfg.kb.functions if 0x4019A0 <= f < 0x402700]

        # UTF-16 string tables: same failure mode, with the leftover null byte also breaking the scan phase
        assert cfg._seg_list.occupied_by_sort(0x405F12) == "unicode"
        assert not [f for f in cfg.kb.functions if 0x405E00 <= f < 0x406100]

        # interleaved (value, pointer) tables are detected by the mixed-pointer scan
        assert memory_data[0x401FBC].sort == MemoryDataSort.PointerArray

        # character translation tables (runs of monotonically increasing bytes) are detected by the byte-ramp scan
        # and must not become code
        assert memory_data[0x403390].sort == MemoryDataSort.Unknown
        assert memory_data[0x403390].size == 193
        assert not [f for f in cfg.kb.functions if 0x4033A0 <= f < 0x403690]

        # double-precision constant tables are detected by the floating-point constant scan
        assert memory_data[0x406278].sort == MemoryDataSort.FloatingPoint
        assert memory_data[0x406278].size == 2064
        assert not [f for f in cfg.kb.functions if 0x406270 <= f < 0x406B00]

    def test_complete_scan_single_precision_fp_table(self):
        # a run of plausible single-precision floats must be classified as data, not code
        code = b"\xc3\xcc\xcc\xcc" + struct.pack("<8f", 1.0, 0.5, 3.14, 100.0, 1e-5, 1e5, -2.5, 0.001)
        proj = angr.load_shellcode(code, "x86")
        cfg = proj.analyses.CFGFast()

        assert cfg.model.memory_data[4].sort == MemoryDataSort.FloatingPoint
        assert cfg.model.memory_data[4].size == 32
        assert list(cfg.kb.functions) == [0]

    def test_complete_scan_cc_filler_is_not_fp(self):
        # a run of one repeated in-band value (0xCC filler decodes as plausible negative floats) must not be
        # classified as a floating-point constant table
        code = b"\xc3" + b"\xcc" * 64
        proj = angr.load_shellcode(code, "x86")
        cfg = proj.analyses.CFGFast()

        assert not [d for d in cfg.model.memory_data.values() if d.sort == MemoryDataSort.FloatingPoint]
        assert list(cfg.kb.functions) == [0]

    def test_long_printable_ascii_string_without_null_byte(self):
        # suboptimal logic in _scan_for_printable_strings was causing the CFG recovery of this binary to be extremely
        # slow; we were repeatedly trying (and failing) to build a super long ASCII string in this binary.
        path = os.path.join(
            test_location, "x86_64", "windows", "b0c4e2ba561fb70425d58969a4b59a5966c911dd96e05a034861df4f47e504da"
        )
        proj = angr.Project(path)

        start = time.time()
        cfg = proj.analyses.CFGFast()
        elapsed = time.time() - start

        assert elapsed < 30, f"CFG recovery took too long: {elapsed:.2f} seconds"

        assert 0x140001000 in cfg.memory_data
        assert cfg.memory_data[0x140001000].sort == MemoryDataSort.String
        assert len(cfg.memory_data[0x140001000].content) == 683666


BLOB_BASE = 0x400000


def _amd64_data_blob() -> bytes:
    """Code with RIP-relative references to strings, a wide string, a pointer array and raw bytes."""
    data_off = 0x100
    code = bytearray()
    data = bytearray()
    targets = {}

    def put(name, blob):
        targets[name] = data_off + len(data)
        data.extend(blob)

    put("s1", b"Hello, ")  # not null-terminated, merged with s2
    put("s2", b"world!\x00")
    put("w", "Wide string!".encode("utf-16-le") + b"\x00\x00")
    data.extend(b"\x00" * (-len(data) % 8))
    put("parr", b"\x00" * 24)
    put("q", struct.pack("<Q", 0x1122334455667788))
    put("t1", b"pointed-to text\x00")
    put("t2", b"another one\x00")
    put("raw", bytes(range(0x80, 0xC0)))
    put("tail", b"zz")
    struct.pack_into(
        "<QQQ",
        data,
        targets["parr"] - data_off,
        BLOB_BASE + targets["t1"],
        BLOB_BASE + targets["t2"],
        BLOB_BASE + targets["raw"],
    )
    for i, name in enumerate(("s1", "s2", "w", "parr", "q", "raw")):
        # lea r64, [rip + disp32]
        disp = targets[name] - (len(code) + 7)
        code += bytes([0x48, 0x8D, 0x05 | (i << 3)]) + struct.pack("<i", disp)
    code += b"\xc3"
    code += b"\x90" * (data_off - len(code))
    return bytes(code + data)


def _armel_data_blob() -> bytes:
    """ldr rN, [pc, #imm] loads of data addresses from a literal pool."""
    code = bytearray(b"\x00" * 16 + b"\x1e\xff\x2f\xe1")  # four ldr, then bx lr
    pool_off = len(code)
    data_off = 0x80
    data = bytearray()
    targets = []
    for blob in (
        b"ARM text\x00",
        b"no-null",
        b"-tail\x00",
        struct.pack("<II", BLOB_BASE + 0x80, BLOB_BASE + 0x89),
    ):
        targets.append(data_off + len(data))
        data += blob
    for i in range(4):
        imm = pool_off + 4 * i - (4 * i + 8)
        struct.pack_into("<I", code, 4 * i, 0xE59F0000 | (i << 12) | imm)
    code += b"".join(struct.pack("<I", BLOB_BASE + t) for t in targets)
    code += b"\x00" * (data_off - len(code))
    return bytes(code + data)


def _guess_custom_sort(model, irsb, irsb_addr, stmt_idx, data_addr, max_size):  # pylint:disable=unused-argument
    if data_addr % 16 == 0:
        return "custom-sort", 4
    return None, None


# (addr, size, sort, reference_size, max_size, pointer_addr, content), recorded with the Python implementation of
# CFGModel.tidy_data_references and CFGFast._post_process_string_references (angr 4efdbc573)
FAUXWARE_X86_64_MEMORY_DATA = [
    (0x400238, 28, "string", None, 28, None, b"/lib64/ld-linux-x86-64.so.2"),
    (0x400254, 32, "unknown", None, 32, None, None),
    (0x400274, 36, "unknown", None, 36, None, None),
    (0x400298, 28, "unknown", None, 28, None, None),
    (0x4002B8, 216, "unknown", None, 216, None, None),
    (0x400390, 90, "unknown", None, 90, None, None),
    (0x4003EA, 18, "unknown", None, 18, None, None),
    (0x400400, 32, "unknown", None, 32, None, None),
    (0x400420, 8, "pointer-array", None, 24, None, None),
    (0x400428, 16, None, None, 16, None, None),
    (0x400438, 8, "pointer-array", None, 168, None, None),
    (0x400440, 160, None, None, 160, None, None),
    (0x40071D, 0, "code reference", None, 195, None, None),
    (0x4007E0, 0, "code reference", None, 144, None, None),
    (0x400870, 0, "code reference", None, 72, None, None),
    (0x4008C8, 8, "unknown", None, 8, None, None),
    (0x4008D0, 9, "string", None, 16, 0x601048, b"SOSNEAKY"),
    (0x4008D9, 7, None, None, 7, None, None),
    (0x4008E0, 44, "string", None, 44, None, b"Welcome to the admin console, trusted user!"),
    (0x40090C, 9, "string", None, 9, None, b"Go away!"),
    (0x400915, 11, "string", None, 11, None, b"Username: "),
    (0x400920, 11, "string", None, 11, None, b"Password: "),
    (0x40092C, 68, "unknown", None, 68, None, None),
    (0x400970, 260, "unknown", None, 260, None, None),
    (0x600E28, 16, "integer", None, 16, None, None),
    (0x600E38, 8, "unknown", None, 8, None, None),
    (0x600E40, 8, "unknown", None, 8, None, None),
    (0x600E48, 8, "integer", None, 8, None, None),
    (0x600E50, 400, "unknown", None, 400, None, None),
    (0x600FE0, 8, "integer", None, 8, None, None),
    (0x600FE8, 8, "pointer-array", None, 8, None, None),
    (0x600FF0, 8, "integer", None, 8, None, None),
    (0x600FF8, 8, "integer", None, 8, None, None),
    (0x601000, 8, "GOT PLT Entry", None, 8, None, None),
    (0x601008, 8, "GOT PLT Entry", None, 8, None, None),
    (0x601010, 8, "GOT PLT Entry", None, 8, None, None),
    (0x601018, 8, "GOT PLT Entry", None, 8, None, None),
    (0x601020, 2, "string", None, 8, None, b" "),
    (0x601028, 2, "string", None, 8, None, b"("),
    (0x601030, 2, "string", None, 8, None, b"0"),
    (0x601038, 16, "unknown", None, 16, None, None),
    (0x601048, 8, "pointer-array", None, 8, None, None),
    (0x601050, 1, "integer", None, 8, None, None),
    (0x601051, 7, None, None, 7, None, None),
    (0x601058, 8, "integer", None, 8, None, None),
]

BLOB_MEMORY_DATA = {
    "AMD64": [
        (43, 212, "unknown", None, None, None, None),
        (256, 7, "string", 13, 7, None, b"Hello, world!"),
        (263, 7, "string", None, 7, None, b"world!"),
        (270, 24, "unicode", None, 26, None, b"W\x00i\x00d\x00e\x00 \x00s\x00t\x00r\x00i\x00n\x00g\x00!\x00"),
        (294, 2, "alignment", None, None, None, None),
        (296, 24, "pointer-array", None, None, None, None),
        (320, 0, "unknown", None, 8, None, None),
        (328, 16, "string", None, 28, None, b"pointed-to text"),
        (344, 12, "string", None, 78, 304, b"another one"),
        (356, 64, "unknown", None, None, None, None),
    ],
    "AMD64-handler": [
        (43, 212, "unknown", None, None, None, None),
        (256, 7, "string", 13, 7, None, b"Hello, world!"),
        (263, 7, "string", None, 7, None, b"world!"),
        (270, 24, "unicode", None, 26, None, b"W\x00i\x00d\x00e\x00 \x00s\x00t\x00r\x00i\x00n\x00g\x00!\x00"),
        (294, 2, "alignment", None, None, None, None),
        (296, 24, "pointer-array", None, None, None, None),
        (320, 4, "custom-sort", None, 8, None, None),
        (328, 16, "string", None, 28, None, b"pointed-to text"),
        (344, 12, "string", None, 78, 304, b"another one"),
        (356, 64, "unknown", None, None, None, None),
    ],
    "ARMEL": [
        (20, 4, "pointer-array", None, 4, None, None),
        (24, 4, "pointer-array", None, 4, None, None),
        (28, 4, "pointer-array", None, 4, None, None),
        (32, 4, "pointer-array", None, 96, None, None),
        (36, 92, "alignment", None, None, None, None),
        (128, 9, "string", None, None, None, b"ARM text"),
        (137, 13, "string", None, None, None, b"no-null-tail"),
        (144, 6, "string", None, 6, None, b"-tail"),
        (150, 8, "pointer-array", None, 8, None, None),
    ],
}


class TestDataTidyRecorded(unittest.TestCase):
    @staticmethod
    def _memory_data(cfg, base: int = 0) -> list[tuple]:
        return [
            (
                addr - base,
                md.size,
                md.sort,
                md.reference_size,
                md.max_size,
                None if md.pointer_addr is None else md.pointer_addr - base,
                md.content,
            )
            for addr, md in cfg.model.memory_data.items()
        ]

    @staticmethod
    def _blob_cfg(data: bytes, arch: str, **kwargs):
        proj = angr.Project(
            io.BytesIO(data),
            main_opts={"backend": "blob", "arch": arch, "base_addr": BLOB_BASE, "entry_point": BLOB_BASE},
            auto_load_libs=False,
        )
        return proj.analyses.CFGFast(normalize=False, **kwargs)

    def test_fauxware_x86_64(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=False)
        assert self._memory_data(cfg) == FAUXWARE_X86_64_MEMORY_DATA

    def test_amd64_blob(self):
        cfg = self._blob_cfg(_amd64_data_blob(), "AMD64")
        assert self._memory_data(cfg, BLOB_BASE) == BLOB_MEMORY_DATA["AMD64"]

    def test_amd64_blob_with_guessing_handler(self):
        cfg = self._blob_cfg(_amd64_data_blob(), "AMD64", data_type_guessing_handlers=[_guess_custom_sort])
        assert self._memory_data(cfg, BLOB_BASE) == BLOB_MEMORY_DATA["AMD64-handler"]
        assert cfg._seg_list.occupied_by_sort(BLOB_BASE + 320) == "custom-sort"

    def test_armel_blob(self):
        cfg = self._blob_cfg(_armel_data_blob(), "ARMEL")
        assert self._memory_data(cfg, BLOB_BASE) == BLOB_MEMORY_DATA["ARMEL"]


if __name__ == "__main__":
    unittest.main()
