import logging
import os

from angr.calling_conventions import DEFAULT_CC, SimCCUnknown
from angr import SimState, sim_options as o, Project
from archinfo import all_arches, ArchAMD64, ArchSoot

l = logging.getLogger("angr.tests.test_stack_alignment")


def test_alignment():
    for arch in all_arches:
        if arch.name in DEFAULT_CC and DEFAULT_CC[arch.name] is not SimCCUnknown:
            # There is nothing to test for soot about stack alignment
            if isinstance(arch, ArchSoot):
                continue
            l.info("Testing stack alignment for %s", arch.name)
            st = SimState(arch=arch)
            cc = DEFAULT_CC[arch.name](arch=arch)

            st.regs.sp = -1

            # setup callsite with one argument (0x1337), "returning" to 0
            cc.setup_callsite(st, 0, [0x1337], "void foo(int x)")

            # ensure stack alignment is correct
            assert st.solver.is_true((st.regs.sp + cc.STACKARG_SP_DIFF) % cc.STACK_ALIGNMENT == 0), (
                "non-zero stack alignment after setup_callsite for %s" % cc
            )


def test_sys_v_abi_compliance():
    arch = ArchAMD64()
    st = SimState(arch=arch)
    cc = DEFAULT_CC[arch.name](arch=arch)

    st.regs.sp = -1

    # setup callsite with one argument (0x1337), "returning" to 0
    cc.setup_callsite(st, 0, [0x1337], "void foo(int x)")

    # (rsp+8) must be aligned to 16 as required by System V ABI.
    # ref: https://raw.githubusercontent.com/wiki/hjl-tools/x86-psABI/x86-64-psABI-1.0.pdf , page 18t
    assert st.solver.is_true((st.regs.rsp + 8) % 16 == 0), "System V ABI calling convention violated!"


def test_initial_allocation():
    # not strictly about alignment but it's about stack initialization so whatever
    p = Project(
        os.path.join(os.path.dirname(__file__), "../../binaries/tests/x86_64/true"),
        auto_load_libs=False,
    )
    s = p.factory.entry_state(add_options={o.STRICT_PAGE_ACCESS})
    s.memory.load(s.regs.sp - 0x10000, size=4)


if __name__ == "__main__":
    test_alignment()
    test_sys_v_abi_compliance()
