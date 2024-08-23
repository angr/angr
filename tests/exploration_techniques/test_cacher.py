#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.exploration_techniques"  # pylint:disable=redefined-builtin

import tempfile
import os
import logging
import unittest

import angr

from ..common import bin_location, broken


test_location = os.path.join(bin_location, "tests")
l = logging.getLogger("angr_tests.managers")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestCacher(unittest.TestCase):
    @broken
    def test_cacher(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), load_options={"auto_load_libs": False})

        tmp_dir = tempfile.mkdtemp(prefix="test_cacher_container")
        container = os.path.join(tmp_dir, f"{os.path.basename(p.filename)}.cache")

        pg = p.factory.simulation_manager()
        pg.use_technique(angr.exploration_techniques.Cacher(when=0x4006EE, container=container))
        pg.run()

        pg2 = p.factory.simulation_manager()
        pg2.use_technique(angr.exploration_techniques.Cacher(container=container))
        assert pg2.active[0].addr == 0x4006ED

        pg2.run()

        assert len(pg2.deadended) == len(pg.deadended)
        assert pg2.deadended[0].addr in [s.addr for s in pg.deadended]
        assert pg2.deadended[1].addr in [s.addr for s in pg.deadended]
        assert pg2.deadended[2].addr in [s.addr for s in pg.deadended]


if __name__ == "__main__":
    unittest.main()
