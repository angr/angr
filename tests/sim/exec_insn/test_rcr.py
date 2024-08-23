#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.sim.exec_insn"  # pylint:disable=redefined-builtin

import os
import unittest

import claripy

import angr

from ...common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestRcr(unittest.TestCase):
    def test_rcr(self):
        p = angr.Project(os.path.join(test_location, "i386", "rcr_test"), auto_load_libs=False)
        result = p.factory.successors(p.factory.entry_state()).successors[0]
        assert claripy.is_true(result.regs.cl == 8)


if __name__ == "__main__":
    unittest.main()
