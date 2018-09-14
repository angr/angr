import nose
from angr import SimState, SIM_PROCEDURES

FAKE_ADDR = 0x100000

def test_calling_conventions():

    #
    # SimProcedures
    #

    from angr.calling_conventions import SimCCCdecl

    args = [ 1, 2, 3, 4, 5, 6, 7, 8, 9, 1000, 100000, 1000000, 2000000, 14, 15, 16 ]
    arches = [
        ('X86', SimCCCdecl),
        ('AMD64', None),
        ('ARMEL', None),
        ('MIPS32', None),
        ('PPC32', None),
        ('PPC64', None),
    ]

    # x86, cdecl
    for arch, cc in arches:
        s = SimState(arch=arch)
        for reg, val, _, _ in s.arch.default_register_values:
            s.registers.store(reg, val)

        if cc is not None:
            manyargs = SIM_PROCEDURES['testing']['manyargs'](cc=cc(s.arch)).execute(s)
        else:
            manyargs = SIM_PROCEDURES['testing']['manyargs']().execute(s)

        # Simulate a call
        if s.arch.call_pushes_ret:
            s.regs.sp = s.regs.sp + s.arch.stack_change
        manyargs.set_args(args)


        for index, arg in enumerate(args):
            nose.tools.assert_true(s.solver.is_true(manyargs.arg(index) == arg))

if __name__ == '__main__':
    test_calling_conventions()
