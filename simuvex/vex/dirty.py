import logging
l = logging.getLogger("s_dirty")

#####################
# Dirty calls
#####################

# Reference:
# http://www-inteng.fnal.gov/Integrated_Eng/GoodwinDocs/pdf/Sys%20docs/PowerPC/PowerPC%20Elapsed%20Time.pdf
# and
# http://www.cap-lore.com/code/TB/
def ppcg_dirtyhelper_MFTB(state):
    # TODO: This is an incorrect implementation. Fix it later!
    return state.BVV(0x200, 64), [ ]

def ppc32g_dirtyhelper_MFSPR_287(state):
    return state.BVV(0x200, 32), [ ]

# Copied basically directly from the vex source
def amd64g_dirtyhelper_CPUID_baseline(state, _):
    lowdword = state.regs.rax[31:0]
    def SET_ABCD(a, b, c, d, condition=None):
        if condition is None:
            state.regs.rax = a
            state.regs.rbx = b
            state.regs.rcx = c
            state.regs.rdx = d
        else:
            state.store_reg('rax', a, length=8, condition=(lowdword == condition))
            state.store_reg('rbx', b, length=8, condition=(lowdword == condition))
            state.store_reg('rcx', c, length=8, condition=(lowdword == condition))
            state.store_reg('rdx', d, length=8, condition=(lowdword == condition))

    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000)
    SET_ABCD(0x00000001, 0x68747541, 0x444d4163, 0x69746e65, 0)
    SET_ABCD(0x00000f5a, 0x01000800, 0x00000000, 0x078bfbff, 1)
    SET_ABCD(0x80000018, 0x68747541, 0x444d4163, 0x69746e65, 0x80000000)
    SET_ABCD(0x00000f5a, 0x00000505, 0x00000000, 0x21d3fbff, 0x80000001)
    SET_ABCD(0x20444d41, 0x6574704f, 0x206e6f72, 0x296d7428, 0x80000002)
    SET_ABCD(0x6f725020, 0x73736563, 0x3820726f, 0x00003834, 0x80000003)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000004)
    SET_ABCD(0xff08ff08, 0xff20ff20, 0x40020140, 0x40020140, 0x80000005)
    SET_ABCD(0x00000000, 0x42004200, 0x04008140, 0x00000000, 0x80000006)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x0000000f, 0x80000007)
    SET_ABCD(0x00003028, 0x00000000, 0x00000000, 0x00000000, 0x80000008)

    return None, [ ]

def amd64g_dirtyhelper_CPUID_avx_and_cx16(state, _):
    old_eax = state.regs.rax[31:0]
    old_ecx = state.regs.rcx[31:0]
    def SET_ABCD(a, b, c, d, condition=None, condition2=None):
        if condition is None:
            state.regs.rax = a
            state.regs.rbx = b
            state.regs.rcx = c
            state.regs.rdx = d
        elif condition2 is None:
            state.store_reg('rax', a, length=8, condition=(old_eax == condition))
            state.store_reg('rbx', b, length=8, condition=(old_eax == condition))
            state.store_reg('rcx', c, length=8, condition=(old_eax == condition))
            state.store_reg('rdx', d, length=8, condition=(old_eax == condition))
        else:
            And = state.se._claripy.And
            state.store_reg('rax', a, length=8, condition=(And(old_eax == condition, old_ecx == condition2)))
            state.store_reg('rbx', b, length=8, condition=(And(old_eax == condition, old_ecx == condition2)))
            state.store_reg('rcx', c, length=8, condition=(And(old_eax == condition, old_ecx == condition2)))
            state.store_reg('rdx', d, length=8, condition=(And(old_eax == condition, old_ecx == condition2)))

    SET_ABCD(0x0000000d, 0x756e6547, 0x6c65746e, 0x49656e69, 0x00000000)
    SET_ABCD(0x000206a7, 0x00100800, 0x1f9ae3bf, 0xbfebfbff, 0x00000001)
    SET_ABCD(0x76035a01, 0x00f0b0ff, 0x00000000, 0x00ca0000, 0x00000002)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000003)
    SET_ABCD(0x1c004121, 0x01c0003f, 0x0000003f, 0x00000000, 0x00000004, 0x00000000)
    SET_ABCD(0x1c004122, 0x01c0003f, 0x0000003f, 0x00000000, 0x00000004, 0x00000001)
    SET_ABCD(0x1c004143, 0x01c0003f, 0x000001ff, 0x00000000, 0x00000004, 0x00000002)
    SET_ABCD(0x1c03c163, 0x02c0003f, 0x00001fff, 0x00000006, 0x00000004, 0x00000003)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000004)
    SET_ABCD(0x00000040, 0x00000040, 0x00000003, 0x00001120, 0x00000005)
    SET_ABCD(0x00000077, 0x00000002, 0x00000009, 0x00000000, 0x00000006)
    SET_ABCD(0x00000000, 0x00000800, 0x00000000, 0x00000000, 0x00000007)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000008)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000009)
    SET_ABCD(0x07300803, 0x00000000, 0x00000000, 0x00000603, 0x0000000a)
    SET_ABCD(0x00000001, 0x00000001, 0x00000100, 0x00000000, 0x0000000b, 0x00000000)
    SET_ABCD(0x00000004, 0x00000004, 0x00000201, 0x00000000, 0x0000000b, 0x00000001)
    SET_ABCD(0x00000000, 0x00000000, old_ecx,    0x00000000, 0x0000000b)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x0000000c)
    SET_ABCD(0x00000007, 0x00000340, 0x00000340, 0x00000000, 0x0000000d, 0x00000000)
    SET_ABCD(0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x0000000d, 0x00000001)
    SET_ABCD(0x00000100, 0x00000240, 0x00000000, 0x00000000, 0x0000000d, 0x00000002)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x0000000d)
    SET_ABCD(0x00000007, 0x00000340, 0x00000340, 0x00000000, 0x0000000e)
    SET_ABCD(0x00000007, 0x00000340, 0x00000340, 0x00000000, 0x0000000f)
    SET_ABCD(0x80000008, 0x00000000, 0x00000000, 0x00000000, 0x80000000)
    SET_ABCD(0x00000000, 0x00000000, 0x00000001, 0x28100800, 0x80000001)
    SET_ABCD(0x20202020, 0x20202020, 0x65746e49, 0x2952286c, 0x80000002)
    SET_ABCD(0x726f4320, 0x4d542865, 0x35692029, 0x3033322d, 0x80000003)
    SET_ABCD(0x50432030, 0x20402055, 0x30382e32, 0x007a4847, 0x80000004)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x80000005)
    SET_ABCD(0x00000000, 0x00000000, 0x01006040, 0x00000000, 0x80000006)
    SET_ABCD(0x00000000, 0x00000000, 0x00000000, 0x00000100, 0x80000007)
    SET_ABCD(0x00003024, 0x00000000, 0x00000000, 0x00000000, 0x80000008)
    SET_ABCD(0x00000007, 0x00000340, 0x00000340, 0x00000000)

    return None, [ ]
