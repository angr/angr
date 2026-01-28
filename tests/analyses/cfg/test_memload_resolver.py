#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import unittest
import os.path

import angr

from tests.common import bin_location, WORKER

test_location = os.path.join(bin_location, "tests")


class TestMemloadResolver(unittest.TestCase):
    def test_indirect_jump_should_start_new_functions(self):
        bin_path = os.path.join(test_location, "x86_64", "fmt-rust-stripped")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True, show_progressbar=not WORKER)
        # function 0x566a50 should be a separate function
        node = cfg.model.get_any_node(0x566A50)
        assert node is not None
        assert node.function_address == 0x566A50
        # function 0x49C4D0 should include many blocks, including 0x49C50A
        func = cfg.kb.functions[0x49C4D0]
        assert func is not None
        assert 0x49C50A in func.block_addrs_set
        assert not cfg.kb.functions.contains_addr(0x49C50A)


if __name__ == "__main__":
    unittest.main()
