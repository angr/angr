from pytcg import *

def helper_cc_compute_c(dst, src1, src2, op):
    if op in [CC_OP_LOGICB, CC_OP_LOGICW, CC_OP_LOGICL, CC_OP_LOGICQ, CC_OP_CLR, CC_OP_POPCNT]:
        return 0
    elif op in [CC_OP_EFLAGS, CC_OP_SARB, CC_OP_SARW, CC_OP_SARW, CC_OP_SARL, CC_OP_SARQ, CC_OP_ADOX]:
        return src1 & 1
    elif op in [CC_OP_INCB, CC_OP_INCW, CC_OP_INCL, CC_OP_INCQ, CC_OP_DECB, CC_OP_DECW, CC_OP_DECL, CC_OP_DECQ]:
        return src1
    elif op in [CC_OP_MULB, CC_OP_MULW, CC_OP_MULL, CC_OP_MULQ]:
        return src1!=0
    elif op in [CC_OP_ADCX, CC_OP_ADCOX]:
        return dst

    elif op in CC_OP_ADDB:
        return compute_c_addb(dst, src1)
    elif op in CC_OP_ADDW:
        return compute_c_addw(dst, src1)
    elif op in CC_OP_ADDL:
        return compute_c_addl(dst, src1)
    elif op in CC_OP_ADDQ:
        return compute_c_addq(dst, src1)

    elif op in CC_OP_ADCB:
        return compute_c_adcb(dst, src1, src2)
    elif op in CC_OP_ADCW:
        return compute_c_adcw(dst, src1, src2)
    elif op in CC_OP_ADCL:
        return compute_c_adcl(dst, src1, src2)
    elif op in CC_OP_ADCQ:
        return compute_c_adcq(dst, src1, src2)

    elif op in CC_OP_SUBB:
        return compute_c_subb(dst, src1)
    elif op in CC_OP_SUBW:
        return compute_c_subw(dst, src1)
    elif op in CC_OP_SUBL:
        return compute_c_subl(dst, src1)

    elif op in CC_OP_SBBB:
        return compute_c_sbbb(dst, src1, src2)
    elif op in CC_OP_SBBW:
        return compute_c_sbbw(dst, src1, src2)
    elif op in CC_OP_SBBL:
        return compute_c_sbbl(dst, src1, src2)
    elif op in CC_OP_SBBQ:
        return compute_c_sbbq(dst, src1, src2)

    elif op in CC_OP_SHLB:
        return compute_c_shlb(dst, src1)
    elif op in CC_OP_SHLW:
        return compute_c_shlw(dst, src1)
    elif op in CC_OP_SHLL:
        return compute_c_shll(dst, src1)
    elif op in CC_OP_SHLQ:
        return compute_c_shlq(dst, src1)

    elif op in CC_OP_BMILGB:
        return compute_c_bmilgb(dst, src1)
    elif op in CC_OP_BMILGW:
        return compute_c_bmilgw(dst, src1)
    elif op in CC_OP_BMILGL:
        return compute_c_bmilgl(dst, src1)
    elif op in CC_OP_BMILGQ:
        return compute_c_bmilgq(dst, src1)
