#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses import Decompiler
from tests.common import bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestDegenerateJumpTable(unittest.TestCase):
    """
    Every entry of the jump table in address_of() names the block right after the dispatch. The source is
    binaries/tests_src/decompiler/degenerate_jump_table.c.
    """

    @staticmethod
    def _decompile(func_name: str) -> str:
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "degenerate_jump_table")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        d = proj.analyses[Decompiler].prep(fail_fast=True)(proj.kb.functions[func_name], cfg=cfg.model)
        print_decompilation_result(d)
        assert d.codegen is not None and d.codegen.text is not None
        return d.codegen.text

    def test_dispatch_merged_with_following_code(self):
        # the dispatch block is merged with the code after it, which must not be absorbed into a switch over the
        # degenerate table
        text = self._decompile("describe")
        assert text.count("report(") == 2
        for callee in ("print_wild", "print_shadow", "print_heap", "print_stack", "print_global"):
            assert f"{callee}(" in text
        assert text.count("switch (") == 1

    def test_dispatch_block_alone(self):
        # the dispatch block is a node of its own, so the switch over the degenerate table is still built
        text = self._decompile("describe_kind")
        assert text.count("report(") == 1
        assert text.count("switch (") == 2


if __name__ == "__main__":
    unittest.main()
