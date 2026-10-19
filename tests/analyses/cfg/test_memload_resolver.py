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
        # CFG recovery is scoped to the code the assertions depend on: the function 0x495fe0 that tail-jumps to the
        # thunk 0x496030, the thunk's own target 0x498930 (without it the thunk is dropped), the thunk 0x4965c0 whose
        # memory-load jump reaches 0x566a50, the function 0x496920 that jumps to 0x49c4d0, and the two asserted
        # functions themselves. None of the asserted addresses is seeded as a function start: they must be discovered.
        cfg = proj.analyses.CFG(
            normalize=True,
            show_progressbar=not WORKER,
            regions=[
                (0x495FE0, 0x496040),
                (0x4965C0, 0x4965D0),
                (0x496920, 0x496DA0),
                (0x498930, 0x498A40),
                (0x49C4D0, 0x49CC10),
                (0x566A50, 0x566BD0),
            ],
            function_starts=[0x495FE0, 0x4965C0, 0x496920],
            start_at_entry=False,
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
