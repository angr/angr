#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import re
import unittest

from angr.ailment.expression import Phi
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.decompiler import Decompiler
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring, no-self-use
class TestAlignmentEntryBlock(unittest.TestCase):
    def test_padding_entry_before_a_loop_header(self):
        # 0x477a19's entry block holds nothing but padding. Its successor, 0x477a20, is the header of a loop that walks
        # a pointer backwards one byte at a time.
        bin_path = os.path.join(test_location, "x86_64", "elf_with_static_libc_ubuntu_2004_stripped")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x477A19, run_ccc=False)

        func = cfg.functions[0x477A19]
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        # An AIL temporary that ssailification never rewrote prints verbatim, e.g. tmp_7.
        assert re.search(r"\btmp_\d+\b", dec.codegen.text) is None

        # The loop header merges the pointer from the entry with the one coming back around the loop.
        assert dec.clinic is not None and dec.clinic.graph is not None
        header = next(node for node in dec.clinic.graph if node.addr == 0x477A20)
        back_edge_sources = [
            src
            for stmt in header.statements
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi)
            for src, _ in stmt.src.src_and_vvars
            if src == (header.addr, header.idx)
        ]
        assert back_edge_sources


if __name__ == "__main__":
    unittest.main()
