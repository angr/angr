#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.exploration_techniques"  # pylint:disable=redefined-builtin

import unittest
import os
import sys

import angr

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


def _ultra_oppologist(p, s):
    old_ops = dict(angr.engines.vex.claripy.irop.operations)
    try:
        angr.engines.vex.claripy.irop.operations.clear()
        angr.engines.vex.claripy.irop.operations["Iop_Add32"] = old_ops["Iop_Add32"]

        pg = p.factory.simulation_manager(s)
        pg.use_technique(angr.exploration_techniques.Oppologist())
        pg.explore()

        return pg
    finally:
        angr.engines.vex.claripy.irop.operations.update(old_ops)


@unittest.skipIf(sys.platform == "win32", "broken on windows")
class TestOppologist(unittest.TestCase):
    def test_fauxware_oppologist(self):
        p = angr.Project(os.path.join(test_location, "i386", "fauxware"))
        s = p.factory.full_init_state(remove_options={angr.options.LAZY_SOLVES, angr.options.EXTENDED_IROP_SUPPORT})

        pg = _ultra_oppologist(p, s)
        assert len(pg.deadended) == 1
        assert len(pg.deadended[0].posix.dumps(0)) == 18
        stdout = pg.deadended[0].posix.dumps(1)
        if b"trusted user" in stdout:
            assert stdout.count(b"\n") == 3
        else:
            assert stdout.count(b"\n") == 2

    def test_cromu_70(self):
        p = angr.Project(os.path.join(test_location, "cgc", "CROMU_00070"))
        inp = bytes.fromhex(
            "030e000001000001001200010000586d616ce000000600030000040dd0000000000600000606000006030e000001000001003200010000586d616ce0030000000000030e000001000001003200010000586d616ce003000000000006000006030e000001000001003200010000586d616ce0030000df020000"
        )
        s = p.factory.full_init_state(
            add_options={angr.options.UNICORN},
            remove_options={angr.options.LAZY_SOLVES, angr.options.SUPPORT_FLOATING_POINT},
            stdin=inp,
        )

        pg = p.factory.simulation_manager(s)
        pg.use_technique(angr.exploration_techniques.Oppologist())
        pg.run(n=50)
        assert pg.one_active.history.block_count > 1500


if __name__ == "__main__":
    unittest.main()
