import os
from unittest import TestCase

import angr

from common import bin_location


class TestPyVEX(TestCase):
    def test_full_binary(self):
        p = angr.Project(
            os.path.join(bin_location, "tests", "armel", "RTOSDemo.axf.issue_685"),
            arch="ARMEL",
            auto_load_libs=False,
        )
        st = p.factory.call_state(0x000013CE + 1)
        b = st.block().vex
        simgr = p.factory.simulation_manager(st)
        simgr.step()
        assert b.jumpkind == "Ijk_Sys_syscall"
        assert simgr.active[0].regs.ip_at_syscall.args[0] == 0x13FB
