#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.sim.exec_insn"  # pylint:disable=redefined-builtin

import os
import subprocess
import sys
from unittest import main, skipUnless, TestCase

import angr

from ...common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestSignedDiv(TestCase):
    @skipUnless(sys.platform.startswith("linux"), "linux only")
    def test_signed_div(self):
        test_bin = os.path.join(test_location, "x86_64", "test_signed_div")
        b = angr.Project(test_bin, auto_load_libs=False)

        pg = b.factory.simulation_manager()
        pg.explore()
        out_angr = pg.deadended[0].posix.dumps(1)
        with subprocess.Popen(test_bin, stdout=subprocess.PIPE) as proc:
            stdout_real, _ = proc.communicate()

        assert out_angr == stdout_real


if __name__ == "__main__":
    main()
