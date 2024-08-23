#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestStaticHooker(unittest.TestCase):
    def test_static_hooker(self):
        test_file = os.path.join(test_location, "x86_64", "static")
        p = angr.Project(test_file, auto_load_libs=False)
        sh = p.analyses.StaticHooker("libc.so.6")

        assert 4197616 in sh.results
        assert type(sh.results[4197616]) is angr.SIM_PROCEDURES["glibc"]["__libc_start_main"]
        assert type(p.hooked_by(4197616)) is angr.SIM_PROCEDURES["glibc"]["__libc_start_main"]


if __name__ == "__main__":
    unittest.main()
