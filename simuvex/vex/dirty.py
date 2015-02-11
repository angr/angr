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
