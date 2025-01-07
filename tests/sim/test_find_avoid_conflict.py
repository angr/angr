from __future__ import annotations

import os
import unittest

import angr

from tests.common import bin_location


# pylint: disable=missing-class-docstring


# While exploring, if the 'find' and 'avoid' addresses occur in the same run
# the path is added to find_stash even if the avoid address occurs first.
# This is not an entirely trivial issue since a run can span several basic
# blocks. In the following example, main contains an if-then-else statement.
# We want to reach the end of main while avoiding the else branch. It is not
# rejected by angr because there is no control flow instruction at the assembly
# level between the start of the else branch and the target address.
class TestFindAvoidConflict(unittest.TestCase):
    def test_find_avoid_conflict(self):
        proj = angr.Project(os.path.join(bin_location, "tests", "i386", "ite_FindAvoidConflict-O3"))
        initial_state = proj.factory.blank_state()
        sm = proj.factory.simulation_manager(initial_state)

        targetAddr = 0x8048390
        avoidAddr = 0x804838B

        while len(sm.active) > 0:
            sm.explore(find=targetAddr, avoid=avoidAddr)

        for state in sm.found:
            for addr in state.history.bbl_addrs:
                try:
                    instAddrs = set(proj.factory.block(addr).instruction_addrs)
                except angr.errors.AngrError:
                    instAddrs = {}
                self.assertNotIn(avoidAddr, instAddrs)


if __name__ == "__main__":
    unittest.main()
