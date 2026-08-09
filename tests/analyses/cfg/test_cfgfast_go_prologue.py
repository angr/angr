#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import struct
import unittest

import angr
from angr.analyses.cfg.go_prologue import find_go_stack_check_preambles
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

BODY = b"\x55\x48\x89\xe5\x31\xc0\x5d\xc3"  # push rbp; mov rbp, rsp; xor eax, eax; pop rbp; ret

# the preamble encodings emitted by the Go compiler on amd64, parameterized by the jbe displacement
PREAMBLES = [
    lambda d: b"\x49\x3b\x66\x10\x76" + bytes([d]),
    lambda d: b"\x49\x3b\x66\x10\x0f\x86" + struct.pack("<i", d),
    lambda d: b"\x4c\x8d\x64\x24\xf8\x4d\x3b\x66\x10\x76" + bytes([d]),
    lambda d: b"\x4c\x8d\x64\x24\xf8\x4d\x3b\x66\x10\x0f\x86" + struct.pack("<i", d),
    lambda d: b"\x4c\x8d\xa4\x24\x00\xff\xff\xff\x4d\x3b\x66\x10\x76" + bytes([d]),
    lambda d: b"\x4c\x8d\xa4\x24\x00\xff\xff\xff\x4d\x3b\x66\x10\x0f\x86" + struct.pack("<i", d),
]

BASE = 0x400000


def _go_blob() -> tuple[bytes, list[int], list[int]]:
    """
    Build a blob holding one Go-style function per preamble encoding. Returns the blob, the function
    entries, and the offset of the conventional prologue within each function.
    """

    blob = bytearray(b"\x31\xc0\xc3")  # entry stub
    entries, deltas = [], []
    for make_preamble in PREAMBLES:
        blob += b"\xcc" * (-len(blob) % 16)
        entry = len(blob)
        preamble = make_preamble(len(BODY))
        entries.append(BASE + entry)
        deltas.append(len(preamble))
        blob += preamble + BODY
        # the morestack trampoline the stack check branches to
        blob += b"\xeb" + bytes([(entry - (len(blob) + 2)) & 0xFF])
    return bytes(blob), entries, deltas


class TestCFGFastGoPrologue(unittest.TestCase):
    def test_preamble_encodings(self):
        blob, entries, deltas = _go_blob()
        found = {start: end for start, end, _ in find_go_stack_check_preambles(blob)}
        assert sorted(found) == [e - BASE for e in entries]
        assert [found[e - BASE] - (e - BASE) for e in entries] == deltas
        assert deltas == [6, 10, 11, 15, 14, 18]

    def test_backward_branch_is_rejected(self):
        # a backward jbe cannot be a stack-growth branch
        assert not list(find_go_stack_check_preambles(b"\x49\x3b\x66\x10\x76\xfe" + BODY))
        assert not list(find_go_stack_check_preambles(b"\x49\x3b\x66\x10\x76\x00" + BODY))

    def test_prologue_scan_reports_go_function_entry(self):
        blob, entries, deltas = _go_blob()
        proj = angr.load_shellcode(blob, "AMD64", load_address=BASE)
        # prologue scanning is the only source of function starts here
        cfg = proj.analyses.CFGFast(
            symbols=False, function_prologues=True, force_smart_scan=False, force_complete_scan=False
        )
        funcs = set(cfg.kb.functions)
        assert funcs.issuperset(entries)
        assert not funcs.intersection(e + d for e, d in zip(entries, deltas))

    def test_go_preambles_land_on_real_entries(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "langdetect_go"), auto_load_libs=False)
        obj = proj.loader.main_object
        symbols = {s.rebased_addr for s in obj.symbols if s.is_function}
        starts = {
            obj.mapped_base + backer_rva + start
            for backer_rva, backer in obj.memory.backers()
            for start, _, _ in find_go_stack_check_preambles(backer)
        }
        assert len(starts) > 1000
        assert not starts - symbols

    def test_non_go_binary_has_no_preambles(self):
        for binary in ("fauxware", "true"):
            proj = angr.Project(os.path.join(test_location, "x86_64", binary), auto_load_libs=False)
            for _, backer in proj.loader.main_object.memory.backers():
                assert not list(find_go_stack_check_preambles(backer))

    def test_scoped_cfg_recovers_go_entries(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "langdetect_go"), auto_load_libs=False)
        symbols = {s.rebased_addr for s in proj.loader.main_object.symbols if s.is_function}
        start, end = 0x45D100, 0x45E100
        cfg = proj.analyses.CFGFast(
            regions=[(start, end)], symbols=False, force_smart_scan=False, force_complete_scan=False
        )
        in_region = {a for a in cfg.kb.functions if start <= a < end}
        assert len(in_region) >= 30
        assert not in_region - symbols


if __name__ == "__main__":
    unittest.main()
