import nose
from simuvex import SimState, SimProcedures

def test_calling_conventions():

    #
    # SimProcedures
    #

    from simuvex.s_cc import SimCCCdecl

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
            manyargs = SimProcedures['testing']['manyargs'](s, inline=True, convention=cc(s.arch))
        else:
            manyargs = SimProcedures['testing']['manyargs'](s, inline=True)

        # Simulate a call
        if s.arch.call_pushes_ret:
            manyargs.state.registers.store(s.arch.sp_offset, manyargs.state.regs.sp + s.arch.stack_change)
        manyargs.set_args(args)


        for index, arg in enumerate(args):
            nose.tools.assert_true(s.se.is_true(manyargs.arg(index) == arg))

if __name__ == '__main__':
    test_calling_conventions()
