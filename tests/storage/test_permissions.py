#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.storage"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestPermissions(unittest.TestCase):
    def test_nx(self):
        nx_amd64 = angr.Project(os.path.join(test_location, "x86_64", "memmove"), auto_load_libs=False)
        es = nx_amd64.factory.entry_state()

        # .text should be PROT_READ|PROT_EXEC
        assert es.solver.eval(es.memory.permissions(nx_amd64.entry)) == 5

        # load stack to initialize page
        es.memory.load(es.regs.sp, 4)

        # stack should be PROT_READ|PROT_WRITE
        assert es.solver.eval(es.memory.permissions(es.regs.sp)) == 3


if __name__ == "__main__":
    unittest.main()
