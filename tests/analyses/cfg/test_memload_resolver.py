#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os.path
import unittest

import angr
from tests.common import WORKER, bin_location

test_location = os.path.join(bin_location, "tests")


class TestMemloadResolver(unittest.TestCase):
    def test_indirect_jump_should_start_new_functions(self):
        bin_path = os.path.join(test_location, "x86_64", "fmt-rust-stripped")
        proj = angr.Project(bin_path, auto_load_libs=False)
        # a whole-binary CFG of this 1.5 MB binary costs ~40s; every address under test lives in one of
        # these three windows, and the function splitting under test is decided locally
        func_addrs = [0x496030, 0x49C4D0, 0x566A50]
        cfg = proj.analyses.CFGFast(
            normalize=True,
            regions=[(addr, addr + 0x4000) for addr in func_addrs],
            start_at_entry=False,
            function_starts=func_addrs,
            force_smart_scan=False,
            show_progressbar=not WORKER,
        )
        # function 0x566a50 should be a separate function
        node = cfg.model.get_any_node(0x566A50)
        assert node is not None
        assert node.function_address == 0x566A50
        # function 0x498930 should be a separate function
        node = cfg.model.get_any_node(0x496030)
        assert node is not None
        assert node.function_address == 0x496030
        # function 0x49C4D0 should include many blocks, including 0x49C50A
        func = cfg.kb.functions[0x49C4D0]
        assert func is not None
        assert 0x49C50A in func.block_addrs_set
        assert not cfg.kb.functions.contains_addr(0x49C50A)


if __name__ == "__main__":
    unittest.main()
