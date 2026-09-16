#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os.path
import re
import unittest

from angr.analyses.decompiler.decompiler import Decompiler
from tests.common import bin_location, load_project_with_scoped_cfg, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring, no-self-use
class TestSSAMovedEntry(unittest.TestCase):
    def test_ssa_runs_when_the_entry_block_is_padding(self):
        # 0x477a19's entry block holds nothing but padding, so Clinic drops it and moves the entry to
        # its successor, which is a loop header and therefore keeps a predecessor. The AIL graph then
        # has no node without predecessors and no node at function.addr, which used to leave
        # ssailification with nothing to seed its traversal from.
        bin_path = os.path.join(test_location, "x86_64", "elf_with_static_libc_ubuntu_2004_stripped")
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x477A19, run_ccc=False)

        func = cfg.functions[0x477A19]
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        # An AIL register that ssailification never rewrote prints verbatim, e.g. reg16<64>.
        assert re.search(r"\breg\d+<\d+>", dec.codegen.text) is None


if __name__ == "__main__":
    unittest.main()
