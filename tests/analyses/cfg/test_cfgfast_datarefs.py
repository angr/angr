#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import logging
import os
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

        cfg = proj.analyses.CFGFast()
        cfg_model = cfg.model
        assert cfg._seg_list.is_occupied(0x100018BC) is True
        assert cfg._seg_list.occupied_by_sort(0x100018BC) == "pointer-array"
        assert cfg_model.memory_data[0x100018BC].size == 4
        assert cfg_model.memory_data[0x100018BC].sort == MemoryDataSort.PointerArray
        assert cfg._seg_list.is_occupied(0x10001004) is True
        assert cfg._seg_list.occupied_by_sort(0x10001004) == "pointer-array"
        assert cfg_model.memory_data[0x10001004].size == 228
        assert cfg_model.memory_data[0x10001004].sort == MemoryDataSort.PointerArray

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


if __name__ == "__main__":
    unittest.main()
