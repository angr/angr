#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.sim.exec_insn"  # pylint:disable=redefined-builtin

import os
from unittest import main, TestCase

import angr

from tests.common import bin_location, run_simple_unicorn_congruency_check


class TestSignedDiv(TestCase):  # pylint:disable=missing-class-docstring
    def test_signed_div(self):
        test_bin = os.path.join(bin_location, "tests", "x86_64", "test_signed_div")
        b = angr.Project(test_bin, auto_load_libs=False)

        run_simple_unicorn_congruency_check(b)


if __name__ == "__main__":
    main()
