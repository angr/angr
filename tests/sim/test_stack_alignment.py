#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.sim"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

from archinfo import all_arches, ArchAMD64, ArchSoot

from angr.calling_conventions import DEFAULT_CC, default_cc, SimCCUnknown
from angr import SimState, sim_options as o, Project

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")

log = logging.getLogger(__name__)


class TestStackAlignment(unittest.TestCase):
    def test_alignment(self):
        for arch in all_arches:
            if arch.name in DEFAULT_CC and default_cc(arch.name, platform="Linux") is not SimCCUnknown:
                # There is nothing to test for soot about stack alignment
                if isinstance(arch, ArchSoot):
                    continue
                log.info("Testing stack alignment for %s", arch.name)
                st = SimState(arch=arch)
                cc = default_cc(arch.name, platform="Linux")(arch=arch)

                st.regs.sp = -1

                # setup callsite with one argument (0x1337), "returning" to 0
                cc.setup_callsite(st, 0, [0x1337], "void foo(int x)")

                # ensure stack alignment is correct
                assert st.solver.is_true(
                    (st.regs.sp + cc.STACKARG_SP_DIFF) % cc.STACK_ALIGNMENT == 0
                ), f"non-zero stack alignment after setup_callsite for {cc}"

    def test_sys_v_abi_compliance(self):
        arch = ArchAMD64()
        st = SimState(arch=arch)
        cc = default_cc(arch.name, platform="Linux")(arch=arch)

        st.regs.sp = -1

        # setup callsite with one argument (0x1337), "returning" to 0
        cc.setup_callsite(st, 0, [0x1337], "void foo(int x)")

        # (rsp+8) must be aligned to 16 as required by System V ABI.
        # ref: https://raw.githubusercontent.com/wiki/hjl-tools/x86-psABI/x86-64-psABI-1.0.pdf , page 18t
        assert st.solver.is_true((st.regs.rsp + 8) % 16 == 0), "System V ABI calling convention violated!"

    def test_initial_allocation(self):
        # not strictly about alignment but it's about stack initialization so whatever
        p = Project(os.path.join(test_location, "x86_64", "true"), auto_load_libs=False)
        s = p.factory.entry_state(add_options={o.STRICT_PAGE_ACCESS})
        s.memory.load(s.regs.sp - 0x10000, size=4)


if __name__ == "__main__":
    unittest.main()
