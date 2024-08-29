#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import unittest
import os.path

import angr

from ...common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestConstResolver(unittest.TestCase):
    def test_resolving_arm_bx_r9(self):
        bin_path = os.path.join(test_location, "armhf", "amp_challenge_10.gcc")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(
            regions=[(0x40400C, 0x4041EE), (0x404F04, 0x404F20)], function_starts=[0x40400D], start_at_entry=False
        )

        b0 = cfg.model.get_any_node(0x404F15)
        assert b0 is not None
        b0_successors = list(cfg.model.get_successors(b0))
        assert len(b0_successors) == 1
        assert b0_successors[0].addr == 0x404133

        b1 = cfg.model.get_any_node(0x404F1B)
        assert b1 is not None
        b1_successors = list(cfg.model.get_successors(b1))
        assert len(b1_successors) == 1
        assert b1_successors[0].addr == 0x40402D


if __name__ == "__main__":
    unittest.main()
