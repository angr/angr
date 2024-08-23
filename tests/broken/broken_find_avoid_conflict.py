from __future__ import annotations
import angr

import os

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


# While exploring, if the 'find' and 'avoid' addresses occur in the same run
# the path is added to find_stash even if the avoid address occurs first.
# This is not an entirely trivial issue since a run can span several basic
# blocks. In the following example, main contains an if-then-else statement.
# We want to reach the end of main while avoiding the else branch. It is not
# rejected by angr because there is no control flow instruction at the assembly
# level between the start of the else branch and the target address.
def test_FindAvoidConflict():
    proj = angr.Project(os.path.join(test_location, "i386", "ite_FindAvoidConflict-O3"))
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
            assert avoidAddr not in instAddrs


if __name__ == "__main__":
    test_FindAvoidConflict()
