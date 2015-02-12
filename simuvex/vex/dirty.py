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
def amd64g_dirtyhelper_CPUID_baseline(state):
    lowdword = state.reg_expr('rax')[31:0]
    def SET_ABCD(a, b, c, d, condition=None):
        if condition is None:
            state.store_reg('rax', a, length=64)
            state.store_reg('rbx', b, length=64)
            state.store_reg('rcx', c, length=64)
            state.store_reg('rdx', d, length=64)
        else:
            state.store_reg('rax', a, length=64, condition=(lowdword == condition))
            state.store_reg('rbx', b, length=64, condition=(lowdword == condition))
            state.store_reg('rcx', c, length=64, condition=(lowdword == condition))
            state.store_reg('rdx', d, length=64, condition=(lowdword == condition))

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
