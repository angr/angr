# pylint:disable=no-self-use,missing-class-docstring
from __future__ import annotations

import os.path
from unittest import TestCase, main

import angr
from angr.analyses.codecave import CodeCaveClassification
from angr.knowledge_plugins.cfg import MemoryDataSort

TEST_LOCATION = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "binaries", "tests")
FAUXWARE = os.path.join(TEST_LOCATION, "x86_64", "fauxware")


class TestCodeCaveAnalysis(TestCase):
    def test_function_aligments(self):
        p = angr.Project(FAUXWARE, auto_load_libs=False)
        p.analyses.CFGFast(normalize=True)
        result = p.analyses.CodeCaves()
        assert [
            c for c in result.codecaves if c.addr == 0x400634 and c.classification == CodeCaveClassification.ALIGNMENT
        ]

    def test_xfg_hash_is_not_a_code_cave(self):
        p = angr.Project(os.path.join(TEST_LOCATION, "x86_64", "windows", "ipnathlp.dll"), auto_load_libs=False)
        cfg = p.analyses.CFGFast(
            normalize=True,
            regions=[(0x18000A780, 0x18000A7C0), (0x18003CA70, 0x180040A70)],
            start_at_entry=False,
            function_starts=[0x18003CA70],
            force_smart_scan=True,
        )
        hash_addr = 0x18000A798
        data = cfg.model.memory_data[hash_addr]
        assert data.sort == MemoryDataSort.Alignment and data.size == 8
        assert not any(c.addr <= hash_addr < c.addr + c.size for c in p.analyses.CodeCaves().codecaves)

    def test_unreachable(self):
        p = angr.load_shellcode(
            """
            _start:
                push rbp
                mov rbp, rsp
                call func_1
                pop rbp
                ret

            func_0:
                xor rax, rax
                ret

            func_1:
                mov rax, 1
                ret
            """,
            "amd64",
        )
        p.analyses.CFGFast()
        result = p.analyses.CodeCaves()
        assert len([c for c in result.codecaves if c.classification == CodeCaveClassification.UNREACHABLE]) == 1


if __name__ == "__main__":
    main()
