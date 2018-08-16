import logging
import nose

from angr.calling_conventions import DEFAULT_CC
from angr import SimState
from archinfo import all_arches, ArchAMD64

l = logging.getLogger('angr.tests.test_stack_alignment')


def test_alignment():
    for arch in all_arches:
        if arch.name in DEFAULT_CC:
            l.info("Testing stack alignment for %s", arch.name)
            st = SimState(arch=arch)
            cc = DEFAULT_CC[arch.name](arch=arch)

            st.regs.sp = -1

            # setup callsite with one argument (0x1337), "returning" to 0
            cc.setup_callsite(st, 0, [0x1337])

            # ensure stack alignment is correct
            nose.tools.assert_true(st.solver.is_true(((st.regs.sp + cc.STACKARG_SP_DIFF) % cc.STACK_ALIGNMENT == 0)),
                                   'non-zero stack alignment after setup_callsite for %s'%cc)


def test_sys_v_abi_compliance():
    arch = ArchAMD64()
    st = SimState(arch=arch)
    cc = DEFAULT_CC[arch.name](arch=arch)

    st.regs.sp = -1

    # setup callsite with one argument (0x1337), "returning" to 0
    cc.setup_callsite(st, 0, [0x1337])

    # (rsp+8) must be aligned to 16 as required by System V ABI.
    # ref: https://raw.githubusercontent.com/wiki/hjl-tools/x86-psABI/x86-64-psABI-1.0.pdf , page 18t
    nose.tools.assert_true(st.solver.is_true(((st.regs.rsp + 8) % 16 == 0)),
                           'System V ABI calling convention violated!')

if __name__ == "__main__":
    test_alignment()
    test_sys_v_abi_compliance()
