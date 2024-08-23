#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.exploration_techniques"  # pylint:disable=redefined-builtin

import os
import platform
import sys
import unittest

import angr

from .test_tracer import tracer_cgc
from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


@unittest.skipIf(platform.system() == "Darwin" and platform.machine() == "arm64", "Broken on apple silicon")
class TestDrillerCore(unittest.TestCase):
    @unittest.skipIf(sys.platform == "win32", "broken on windows")
    def test_cgc(self):
        binary = os.path.join(test_location, "cgc", "sc1_0b32aa01_01")
        simgr, tracer = tracer_cgc(binary, "driller_core_cgc", b"AAAA", copy_states=True, follow_unsat=True)
        simgr.use_technique(angr.exploration_techniques.DrillerCore(tracer._trace))
        simgr.run()

        assert "diverted" in simgr.stashes
        assert len(simgr.diverted) == 3

    def test_simprocs(self):
        binary = os.path.join(test_location, "i386", "driller_simproc")
        memcmp = angr.SIM_PROCEDURES["libc"]["memcmp"]()

        simgr, tracer = tracer_cgc(binary, "driller_core_simprocs", b"A" * 128, copy_states=True, follow_unsat=True)
        p = simgr._project
        p.hook(0x8048200, memcmp)

        d = angr.exploration_techniques.DrillerCore(tracer._trace)
        simgr.use_technique(d)

        simgr.run()
        assert "diverted" in simgr.stashes
        assert len(simgr.diverted) > 0


if __name__ == "__main__":
    unittest.main()
