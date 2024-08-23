#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.sim"  # pylint:disable=redefined-builtin

import os
import unittest

import angr

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestEcho(unittest.TestCase):
    def _run_echo_haha(self, arch):
        # auto_load_libs can't be disabled as the test fails
        p = angr.Project(os.path.join(test_location, arch, "echo"), use_sim_procedures=False)
        s = p.factory.full_init_state(
            mode="symbolic_approximating", args=["echo", "haha"], add_options={angr.options.STRICT_PAGE_ACCESS}
        )
        pg = p.factory.simulation_manager(s)
        pg.run(until=lambda lpg: len(lpg.active) != 1)

        assert len(pg.deadended) == 1
        assert len(pg.active) == 0
        # Need to dump by path because the program closes stdout
        assert pg.deadended[0].posix.stdout.concretize() == [b"haha\n"]

    def test_echo_haha(self):
        self._run_echo_haha("x86_64")


if __name__ == "__main__":
    unittest.main()
