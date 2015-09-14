#!/usr/bin/env python

import logging
l = logging.getLogger("simuvex.vex.ccall")
#l.setLevel(logging.DEBUG)

# pylint: disable=R0911
# pylint: disable=W0613
# pylint: disable=W0612

###############
### Helpers ###
###############

# There might be a better way of doing this
def calc_paritybit(state, p, msb=7, lsb=0):
    if len(p) > msb:
        p_part = p[msb:lsb]
    else:
        p_part = p

    b = state.se.BitVecVal(1, 1)
    for i in xrange(p_part.size()):
        b = b ^ p_part[i]
    return b

def calc_zerobit(state, p):
    return state.se.If(p == 0, state.se.BitVecVal(1, 1), state.se.BitVecVal(0, 1))

def boolean_extend(state, O, a, b, size):
    return state.se.If(O(a, b), state.se.BitVecVal(1, size), state.se.BitVecVal(0, size))

def flag_concretize(state, flag):
    return state.se.exactly_n_int(flag, 1)[0]

##################
### x86* data ###
##################

data = {
    'AMD64': {
        'CondTypes': { },
        'CondBitOffsets': { },
        'CondBitMasks': { },
        'OpTypes': { }
    }, 'X86': {
        'CondTypes': { },
        'CondBitOffsets': { },
        'CondBitMasks': { },
        'OpTypes': { }
    }
}

# condition types
data['AMD64']['CondTypes']['CondO']      = 0  # /* overflow           */
data['AMD64']['CondTypes']['CondNO']     = 1  # /* no overflow        */
data['AMD64']['CondTypes']['CondB']      = 2  # /* below              */
data['AMD64']['CondTypes']['CondNB']     = 3  # /* not below          */
data['AMD64']['CondTypes']['CondZ']      = 4  # /* zero               */
data['AMD64']['CondTypes']['CondNZ']     = 5  # /* not zero           */
data['AMD64']['CondTypes']['CondBE']     = 6  # /* below or equal     */
data['AMD64']['CondTypes']['CondNBE']    = 7  # /* not below or equal */
data['AMD64']['CondTypes']['CondS']      = 8  # /* negative           */
data['AMD64']['CondTypes']['CondNS']     = 9  # /* not negative       */
data['AMD64']['CondTypes']['CondP']      = 10 # /* parity even        */
data['AMD64']['CondTypes']['CondNP']     = 11 # /* not parity even    */
data['AMD64']['CondTypes']['CondL']      = 12 # /* jump less          */
data['AMD64']['CondTypes']['CondNL']     = 13 # /* not less           */
data['AMD64']['CondTypes']['CondLE']     = 14 # /* less or equal      */
data['AMD64']['CondTypes']['CondNLE']    = 15 # /* not less or equal  */

# condition bit offsets
data['AMD64']['CondBitOffsets']['G_CC_SHIFT_O'] = 11
data['AMD64']['CondBitOffsets']['G_CC_SHIFT_S'] = 7
data['AMD64']['CondBitOffsets']['G_CC_SHIFT_Z'] = 6
data['AMD64']['CondBitOffsets']['G_CC_SHIFT_A'] = 4
data['AMD64']['CondBitOffsets']['G_CC_SHIFT_C'] = 0
data['AMD64']['CondBitOffsets']['G_CC_SHIFT_P'] = 2

# masks
data['AMD64']['CondBitMasks']['G_CC_MASK_O'] = (1 << data['AMD64']['CondBitOffsets']['G_CC_SHIFT_O'])
data['AMD64']['CondBitMasks']['G_CC_MASK_S'] = (1 << data['AMD64']['CondBitOffsets']['G_CC_SHIFT_S'])
data['AMD64']['CondBitMasks']['G_CC_MASK_Z'] = (1 << data['AMD64']['CondBitOffsets']['G_CC_SHIFT_Z'])
data['AMD64']['CondBitMasks']['G_CC_MASK_A'] = (1 << data['AMD64']['CondBitOffsets']['G_CC_SHIFT_A'])
data['AMD64']['CondBitMasks']['G_CC_MASK_C'] = (1 << data['AMD64']['CondBitOffsets']['G_CC_SHIFT_C'])
data['AMD64']['CondBitMasks']['G_CC_MASK_P'] = (1 << data['AMD64']['CondBitOffsets']['G_CC_SHIFT_P'])

# operation types
data['AMD64']['OpTypes']['G_CC_OP_COPY'] = 0
data['AMD64']['OpTypes']['G_CC_OP_ADDB'] = 1
data['AMD64']['OpTypes']['G_CC_OP_ADDW'] = 2
data['AMD64']['OpTypes']['G_CC_OP_ADDL'] = 3
data['AMD64']['OpTypes']['G_CC_OP_ADDQ'] = 4
data['AMD64']['OpTypes']['G_CC_OP_SUBB'] = 5
data['AMD64']['OpTypes']['G_CC_OP_SUBW'] = 6
data['AMD64']['OpTypes']['G_CC_OP_SUBL'] = 7
data['AMD64']['OpTypes']['G_CC_OP_SUBQ'] = 8
data['AMD64']['OpTypes']['G_CC_OP_ADCB'] = 9
data['AMD64']['OpTypes']['G_CC_OP_ADCW'] = 10
data['AMD64']['OpTypes']['G_CC_OP_ADCL'] = 11
data['AMD64']['OpTypes']['G_CC_OP_ADCQ'] = 12
data['AMD64']['OpTypes']['G_CC_OP_SBBB'] = 13
data['AMD64']['OpTypes']['G_CC_OP_SBBW'] = 14
data['AMD64']['OpTypes']['G_CC_OP_SBBL'] = 15
data['AMD64']['OpTypes']['G_CC_OP_SBBQ'] = 16
data['AMD64']['OpTypes']['G_CC_OP_LOGICB'] = 17
data['AMD64']['OpTypes']['G_CC_OP_LOGICW'] = 18
data['AMD64']['OpTypes']['G_CC_OP_LOGICL'] = 19
data['AMD64']['OpTypes']['G_CC_OP_LOGICQ'] = 20
data['AMD64']['OpTypes']['G_CC_OP_INCB'] = 21
data['AMD64']['OpTypes']['G_CC_OP_INCW'] = 22
data['AMD64']['OpTypes']['G_CC_OP_INCL'] = 23
data['AMD64']['OpTypes']['G_CC_OP_INCQ'] = 24
data['AMD64']['OpTypes']['G_CC_OP_DECB'] = 25
data['AMD64']['OpTypes']['G_CC_OP_DECW'] = 26
data['AMD64']['OpTypes']['G_CC_OP_DECL'] = 27
data['AMD64']['OpTypes']['G_CC_OP_DECQ'] = 28
data['AMD64']['OpTypes']['G_CC_OP_SHLB'] = 29
data['AMD64']['OpTypes']['G_CC_OP_SHLW'] = 30
data['AMD64']['OpTypes']['G_CC_OP_SHLL'] = 31
data['AMD64']['OpTypes']['G_CC_OP_SHLQ'] = 32
data['AMD64']['OpTypes']['G_CC_OP_SHRB'] = 33
data['AMD64']['OpTypes']['G_CC_OP_SHRW'] = 34
data['AMD64']['OpTypes']['G_CC_OP_SHRL'] = 35
data['AMD64']['OpTypes']['G_CC_OP_SHRQ'] = 36
data['AMD64']['OpTypes']['G_CC_OP_ROLB'] = 37
data['AMD64']['OpTypes']['G_CC_OP_ROLW'] = 38
data['AMD64']['OpTypes']['G_CC_OP_ROLL'] = 39
data['AMD64']['OpTypes']['G_CC_OP_ROLQ'] = 40
data['AMD64']['OpTypes']['G_CC_OP_RORB'] = 41
data['AMD64']['OpTypes']['G_CC_OP_RORW'] = 42
data['AMD64']['OpTypes']['G_CC_OP_RORL'] = 43
data['AMD64']['OpTypes']['G_CC_OP_RORQ'] = 44
data['AMD64']['OpTypes']['G_CC_OP_UMULB'] = 45
data['AMD64']['OpTypes']['G_CC_OP_UMULW'] = 46
data['AMD64']['OpTypes']['G_CC_OP_UMULL'] = 47
data['AMD64']['OpTypes']['G_CC_OP_UMULQ'] = 48
data['AMD64']['OpTypes']['G_CC_OP_SMULB'] = 49
data['AMD64']['OpTypes']['G_CC_OP_SMULW'] = 50
data['AMD64']['OpTypes']['G_CC_OP_SMULL'] = 51
data['AMD64']['OpTypes']['G_CC_OP_SMULQ'] = 52
data['AMD64']['OpTypes']['G_CC_OP_NUMBER'] = 53

data['X86']['CondTypes']['CondO']      = 0
data['X86']['CondTypes']['CondNO']     = 1
data['X86']['CondTypes']['CondB']      = 2
data['X86']['CondTypes']['CondNB']     = 3
data['X86']['CondTypes']['CondZ']      = 4
data['X86']['CondTypes']['CondNZ']     = 5
data['X86']['CondTypes']['CondBE']     = 6
data['X86']['CondTypes']['CondNBE']    = 7
data['X86']['CondTypes']['CondS']      = 8
data['X86']['CondTypes']['CondNS']     = 9
data['X86']['CondTypes']['CondP']      = 10
data['X86']['CondTypes']['CondNP']     = 11
data['X86']['CondTypes']['CondL']      = 12
data['X86']['CondTypes']['CondNL']     = 13
data['X86']['CondTypes']['CondLE']     = 14
data['X86']['CondTypes']['CondNLE']    = 15
data['X86']['CondTypes']['CondAlways'] = 16

data['X86']['CondBitOffsets']['G_CC_SHIFT_O'] = 11
data['X86']['CondBitOffsets']['G_CC_SHIFT_S'] = 7
data['X86']['CondBitOffsets']['G_CC_SHIFT_Z'] = 6
data['X86']['CondBitOffsets']['G_CC_SHIFT_A'] = 4
data['X86']['CondBitOffsets']['G_CC_SHIFT_C'] = 0
data['X86']['CondBitOffsets']['G_CC_SHIFT_P'] = 2

# masks
data['X86']['CondBitMasks']['G_CC_MASK_O'] = (1 << data['X86']['CondBitOffsets']['G_CC_SHIFT_O'])
data['X86']['CondBitMasks']['G_CC_MASK_S'] = (1 << data['X86']['CondBitOffsets']['G_CC_SHIFT_S'])
data['X86']['CondBitMasks']['G_CC_MASK_Z'] = (1 << data['X86']['CondBitOffsets']['G_CC_SHIFT_Z'])
data['X86']['CondBitMasks']['G_CC_MASK_A'] = (1 << data['X86']['CondBitOffsets']['G_CC_SHIFT_A'])
data['X86']['CondBitMasks']['G_CC_MASK_C'] = (1 << data['X86']['CondBitOffsets']['G_CC_SHIFT_C'])
data['X86']['CondBitMasks']['G_CC_MASK_P'] = (1 << data['X86']['CondBitOffsets']['G_CC_SHIFT_P'])

data['X86']['OpTypes']['G_CC_OP_COPY'] = 0
data['X86']['OpTypes']['G_CC_OP_ADDB'] = 1
data['X86']['OpTypes']['G_CC_OP_ADDW'] = 2
data['X86']['OpTypes']['G_CC_OP_ADDL'] = 3
data['X86']['OpTypes']['G_CC_OP_SUBB'] = 4
data['X86']['OpTypes']['G_CC_OP_SUBW'] = 5
data['X86']['OpTypes']['G_CC_OP_SUBL'] = 6
data['X86']['OpTypes']['G_CC_OP_ADCB'] = 7
data['X86']['OpTypes']['G_CC_OP_ADCW'] = 8
data['X86']['OpTypes']['G_CC_OP_ADCL'] = 9
data['X86']['OpTypes']['G_CC_OP_SBBB'] = 10
data['X86']['OpTypes']['G_CC_OP_SBBW'] = 11
data['X86']['OpTypes']['G_CC_OP_SBBL'] = 12
data['X86']['OpTypes']['G_CC_OP_LOGICB'] = 13
data['X86']['OpTypes']['G_CC_OP_LOGICW'] = 14
data['X86']['OpTypes']['G_CC_OP_LOGICL'] = 15
data['X86']['OpTypes']['G_CC_OP_INCB'] = 16
data['X86']['OpTypes']['G_CC_OP_INCW'] = 17
data['X86']['OpTypes']['G_CC_OP_INCL'] = 18
data['X86']['OpTypes']['G_CC_OP_DECB'] = 19
data['X86']['OpTypes']['G_CC_OP_DECW'] = 20
data['X86']['OpTypes']['G_CC_OP_DECL'] = 21
data['X86']['OpTypes']['G_CC_OP_SHLB'] = 22
data['X86']['OpTypes']['G_CC_OP_SHLW'] = 23
data['X86']['OpTypes']['G_CC_OP_SHLL'] = 24
data['X86']['OpTypes']['G_CC_OP_SHRB'] = 25
data['X86']['OpTypes']['G_CC_OP_SHRW'] = 26
data['X86']['OpTypes']['G_CC_OP_SHRL'] = 27
data['X86']['OpTypes']['G_CC_OP_ROLB'] = 28
data['X86']['OpTypes']['G_CC_OP_ROLW'] = 29
data['X86']['OpTypes']['G_CC_OP_ROLL'] = 30
data['X86']['OpTypes']['G_CC_OP_RORB'] = 31
data['X86']['OpTypes']['G_CC_OP_RORW'] = 32
data['X86']['OpTypes']['G_CC_OP_RORL'] = 33
data['X86']['OpTypes']['G_CC_OP_UMULB'] = 34
data['X86']['OpTypes']['G_CC_OP_UMULW'] = 35
data['X86']['OpTypes']['G_CC_OP_UMULL'] = 36
data['X86']['OpTypes']['G_CC_OP_SMULB'] = 37
data['X86']['OpTypes']['G_CC_OP_SMULW'] = 38
data['X86']['OpTypes']['G_CC_OP_SMULL'] = 39
data['X86']['OpTypes']['G_CC_OP_NUMBER'] = 40

data['X86']['OpTypes']['G_CC_OP_SMULQ'] = None
data['X86']['OpTypes']['G_CC_OP_UMULQ'] = None
data['X86']['OpTypes']['G_CC_OP_RORQ'] = None
data['X86']['OpTypes']['G_CC_OP_ROLQ'] = None
data['X86']['OpTypes']['G_CC_OP_SHRQ'] = None
data['X86']['OpTypes']['G_CC_OP_SHLQ'] = None
data['X86']['OpTypes']['G_CC_OP_DECQ'] = None
data['X86']['OpTypes']['G_CC_OP_INCQ'] = None
data['X86']['OpTypes']['G_CC_OP_LOGICQ'] = None
data['X86']['OpTypes']['G_CC_OP_SBBQ'] = None
data['X86']['OpTypes']['G_CC_OP_ADCQ'] = None
data['X86']['OpTypes']['G_CC_OP_SUBQ'] = None
data['X86']['OpTypes']['G_CC_OP_ADDQ'] = None

data_inverted = { k_arch: { k_data_class: {y:x for (x,y) in d_data_class.iteritems()} for k_data_class, d_data_class in d_arch.iteritems() } for k_arch,d_arch in data.iteritems() }

data['AMD64']['size'] = 64
data['X86']['size'] = 32

#
# AMD64 internal helpers
#
def pc_preamble(state, nbits, platform=None):
    data_mask = state.se.BitVecVal(2 ** nbits - 1, nbits)
    sign_mask = 1 << (nbits - 1)
    return data_mask, sign_mask

def pc_make_rdata(nbits, cf, pf, af, zf, sf, of, platform=None):
    return cf, pf, af, zf, sf, of

def pc_make_rdata_if_necessary(nbits, cf, pf, af, zf, sf, of, platform=None):
    return  cf.zero_extend(nbits - 1) << data[platform]['CondBitOffsets']['G_CC_SHIFT_C'] | \
            pf.zero_extend(nbits - 1) << data[platform]['CondBitOffsets']['G_CC_SHIFT_P'] | \
            af.zero_extend(nbits - 1) << data[platform]['CondBitOffsets']['G_CC_SHIFT_A'] | \
            zf.zero_extend(nbits - 1) << data[platform]['CondBitOffsets']['G_CC_SHIFT_Z'] | \
            sf.zero_extend(nbits - 1) << data[platform]['CondBitOffsets']['G_CC_SHIFT_S'] | \
            of.zero_extend(nbits - 1) << data[platform]['CondBitOffsets']['G_CC_SHIFT_O']

def pc_actions_ADD(state, nbits, arg_l, arg_r, cc_ndep, platform=None):
    data_mask, sign_mask = pc_preamble(state, nbits, platform=platform)
    res = arg_l + arg_r

    cf = state.se.If(state.se.ULT(res, arg_l), state.se.BitVecVal(1, 1), state.se.BitVecVal(0, 1))
    pf = calc_paritybit(state, res)
    af = (res ^ arg_l ^ arg_r)[data[platform]['CondBitOffsets']['G_CC_SHIFT_A']]
    zf = calc_zerobit(state, res)
    sf = res[nbits - 1:nbits - 1]
    of = ((arg_l ^ arg_r ^ data_mask) & (arg_l ^ res))[nbits - 1:nbits - 1]

    return pc_make_rdata(data[platform]['size'], cf, pf, af, zf, sf, of, platform=platform)

def pc_actions_SUB(state, nbits, arg_l, arg_r, cc_ndep, platform=None):
    data_mask, sign_mask = pc_preamble(state, nbits, platform=platform)
    res = arg_l - arg_r

    cf = state.se.If(state.se.ULT(arg_l, arg_r), state.se.BitVecVal(1, 1), state.se.BitVecVal(0, 1))
    pf = calc_paritybit(state, res)
    af = (res ^ arg_l ^ arg_r)[data[platform]['CondBitOffsets']['G_CC_SHIFT_A']]
    zf = calc_zerobit(state, res)
    sf = res[nbits - 1:nbits - 1]
    of = ((arg_l ^ arg_r) & (arg_l ^ res))[nbits - 1:nbits - 1]

    #cf = state.BV("C_BIT", 1)
    #pf = state.BV("P_BIT", 1)
    #af = state.BV("A_BIT", 1)
    #zf = state.BV("Z_BIT", 1)
    #sf = state.BV("S_BIT", 1)
    #of = state.BV("O_BIT", 1)

    return pc_make_rdata(data[platform]['size'], cf, pf, af, zf, sf, of, platform=platform)

def pc_actions_LOGIC(state, nbits, arg_l, arg_r, cc_ndep, platform=None):
    data_mask, sign_mask = pc_preamble(state, nbits, platform=platform)

    cf = state.se.BitVecVal(0, 1)
    pf = calc_paritybit(state, arg_l)
    af = state.se.BitVecVal(0, 1)
    zf = calc_zerobit(state, arg_l)
    sf = arg_l[nbits-1]
    of = state.se.BitVecVal(0, 1)

    return pc_make_rdata(data[platform]['size'], cf, pf, af, zf, sf, of, platform=platform)

def pc_actions_DEC(state, nbits, res, _, cc_ndep, platform=None):
    data_mask, sign_mask = pc_preamble(state, nbits, platform=platform)
    arg_l = res + 1
    arg_r = 1

    cf = (cc_ndep & data[platform]['CondBitMasks']['G_CC_MASK_C'])[data[platform]['CondBitOffsets']['G_CC_SHIFT_C']]
    pf = calc_paritybit(state, res)
    af = (res ^ arg_l ^ 1)[data[platform]['CondBitOffsets']['G_CC_SHIFT_A']]
    zf = calc_zerobit(state, res)
    sf = res[nbits-1]
    of = state.se.If(sf == arg_l[nbits-1], state.se.BitVecVal(0, 1), state.se.BitVecVal(1, 1))
    return pc_make_rdata(data[platform]['size'], cf, pf, af, zf, sf, of, platform=platform)

def pc_actions_ADC(*args, **kwargs):
    l.error("Unsupported flag action ADC")
    raise SimCCallError("Unsupported flag action. Please implement or bug Yan.")
def pc_actions_SBB(*args, **kwargs):
    l.error("Unsupported flag action SBB")
    raise SimCCallError("Unsupported flag action. Please implement or bug Yan.")

def pc_actions_INC(state, nbits, res, _, cc_ndep, platform=None):
    data_mask, sign_mask = pc_preamble(state, nbits, platform=platform)
    arg_l = res - 1
    arg_r = 1

    cf = (cc_ndep & data[platform]['CondBitMasks']['G_CC_MASK_C'])[data[platform]['CondBitOffsets']['G_CC_SHIFT_C']]
    pf = calc_paritybit(state, res)
    af = (res ^ arg_l ^ 1)[data[platform]['CondBitOffsets']['G_CC_SHIFT_A']]
    zf = calc_zerobit(state, res)
    sf = res[nbits-1]
    of = state.se.If(sf == arg_l[nbits-1], state.se.BitVecVal(0, 1), state.se.BitVecVal(1, 1))
    return pc_make_rdata(data[platform]['size'], cf, pf, af, zf, sf, of, platform=platform)

def pc_actions_SHL(*args, **kwargs):
    l.error("Unsupported flag action SHL")
    raise SimCCallError("Unsupported flag action. Please implement or bug Yan.")

def pc_actions_SHR(state, nbits, remaining, shifted, cc_ndep, platform=None):
    cf = state.se.If(shifted & 1 != 0, state.se.BitVecVal(1, 1), state.se.BitVecVal(0, 1))
    pf = calc_paritybit(state, remaining[7:0])
    af = state.se.BitVecVal(0, 1)
    zf = calc_zerobit(state, remaining)
    sf = remaining[nbits-1]
    of = (remaining[0] ^ shifted[0])[0]
    return pc_make_rdata(data[platform]['size'], cf, pf, af, zf, sf, of, platform=platform)

def pc_actions_ROL(*args, **kwargs):
    l.error("Unsupported flag action ROL")
    raise SimCCallError("Unsupported flag action. Please implement or bug Yan.")
def pc_actions_ROR(*args, **kwargs):
    l.error("Unsupported flag action ROR")
    raise SimCCallError("Unsupported flag action. Please implement or bug Yan.")
def pc_actions_UMUL(*args, **kwargs):
    l.error("Unsupported flag action UMUL")
    raise SimCCallError("Unsupported flag action. Please implement or bug Yan.")
def pc_actions_UMULQ(*args, **kwargs):
    l.error("Unsupported flag action UMULQ")
    raise SimCCallError("Unsupported flag action. Please implement or bug Yan.")
def pc_actions_SMUL(state, nbits, cc_dep1, cc_dep2, cc_ndep, platform=None):
    lo = (cc_dep1 * cc_dep2)[nbits - 1:0]
    rr = lo
    hi = (rr >> nbits)[nbits - 1:0]
    cf = state.se.If(hi != (lo >> (nbits - 1)), state.se.BitVecVal(1, 1), state.se.BitVecVal(0, 1));
    zf = calc_zerobit(state, lo)
    pf = calc_paritybit(state, lo)
    af = state.se.BitVecVal(0, 1)
    sf = lo[nbits - 1]
    of = cf
    return pc_make_rdata(data[platform]['size'], cf, pf, af, zf, sf, of, platform=platform)
def pc_actions_SMULQ(*args, **kwargs):
    l.error("Unsupported flag action SMULQ")
    raise SimCCallError("Unsupported flag action. Please implement or bug Yan.")



def pc_calculate_rdata_all_WRK(state, cc_op, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=None):
    # sanity check
    if not isinstance(cc_op, (int, long)):
        cc_op = flag_concretize(state, cc_op)

    if cc_op == data[platform]['OpTypes']['G_CC_OP_COPY']:
        l.debug("cc_op == data[platform]['OpTypes']['G_CC_OP_COPY']")
        return cc_dep1_formal & (data[platform]['CondBitMasks']['G_CC_MASK_O'] | data[platform]['CondBitMasks']['G_CC_MASK_S'] | data[platform]['CondBitMasks']['G_CC_MASK_Z']
              | data[platform]['CondBitMasks']['G_CC_MASK_A'] | data[platform]['CondBitMasks']['G_CC_MASK_C'] | data[platform]['CondBitMasks']['G_CC_MASK_P'])

    cc_str = data_inverted[platform]['OpTypes'][cc_op]

    if cc_str.endswith('B'):
        nbits = 8
    elif cc_str.endswith('W'):
        nbits = 16
    elif cc_str.endswith('L'):
        nbits = 32
    elif cc_str.endswith('Q'):
        nbits = 64
    l.debug("nbits == %d", nbits)

    cc_dep1_formal = cc_dep1_formal[nbits-1:0]
    cc_dep2_formal = cc_dep2_formal[nbits-1:0]
    # TODO: does ndep need to be extracted as well?

    if cc_str in [ 'G_CC_OP_ADDB', 'G_CC_OP_ADDW', 'G_CC_OP_ADDL', 'G_CC_OP_ADDQ' ]:
        l.debug("cc_str: ADD")
        return pc_actions_ADD(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

    if cc_str in [ 'G_CC_OP_ADCB', 'G_CC_OP_ADCW', 'G_CC_OP_ADCL', 'G_CC_OP_ADCQ' ]:
        l.debug("cc_str: ADC")
        return pc_actions_ADC(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

    if cc_str in [ 'G_CC_OP_SUBB', 'G_CC_OP_SUBW', 'G_CC_OP_SUBL', 'G_CC_OP_SUBQ' ]:
        l.debug("cc_str: SUB")
        return pc_actions_SUB(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

    if cc_str in [ 'G_CC_OP_SBBB', 'G_CC_OP_SBBW', 'G_CC_OP_SBBL', 'G_CC_OP_SBBQ' ]:
        l.debug("cc_str: SBB")
        return pc_actions_SBB(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

    if cc_str in [ 'G_CC_OP_LOGICB', 'G_CC_OP_LOGICW', 'G_CC_OP_LOGICL', 'G_CC_OP_LOGICQ' ]:
        l.debug("cc_str: LOGIC")
        return pc_actions_LOGIC(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

    if cc_str in [ 'G_CC_OP_INCB', 'G_CC_OP_INCW', 'G_CC_OP_INCL', 'G_CC_OP_INCQ' ]:
        l.debug("cc_str: INC")
        return pc_actions_INC(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

    if cc_str in [ 'G_CC_OP_DECB', 'G_CC_OP_DECW', 'G_CC_OP_DECL', 'G_CC_OP_DECQ' ]:
        l.debug("cc_str: DEC")
        return pc_actions_DEC(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

    if cc_str in [ 'G_CC_OP_SHLB', 'G_CC_OP_SHLW', 'G_CC_OP_SHLL', 'G_CC_OP_SHLQ' ]:
        l.debug("cc_str: SHL")
        return pc_actions_SHL(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

    if cc_str in [ 'G_CC_OP_SHRB', 'G_CC_OP_SHRW', 'G_CC_OP_SHRL', 'G_CC_OP_SHRQ' ]:
        l.debug("cc_str: SHR")
        return pc_actions_SHR(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

    if cc_str in [ 'G_CC_OP_ROLB', 'G_CC_OP_ROLW', 'G_CC_OP_ROLL', 'G_CC_OP_ROLQ' ]:
        l.debug("cc_str: ROL")
        return pc_actions_ROL(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

    if cc_str in [ 'G_CC_OP_RORB', 'G_CC_OP_RORW', 'G_CC_OP_RORL', 'G_CC_OP_RORQ' ]:
        l.debug("cc_str: ROR")
        return pc_actions_ROR(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

    if cc_str in [ 'G_CC_OP_UMULB', 'G_CC_OP_UMULW', 'G_CC_OP_UMULL', 'G_CC_OP_UMULQ' ]:
        l.debug("cc_str: UMUL")
        return pc_actions_UMUL(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)
    if cc_str == 'G_CC_OP_UMULQ':
        l.debug("cc_str: UMULQ")
        return pc_actions_UMULQ(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)
    if cc_str in [ 'G_CC_OP_SMULB', 'G_CC_OP_SMULW', 'G_CC_OP_SMULL', 'G_CC_OP_SMULQ' ]:
        l.debug("cc_str: SMUL")
        return pc_actions_SMUL(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)
    if cc_str == 'G_CC_OP_SMULQ':
        l.debug("cc_str: SMULQ")
        return pc_actions_SMULQ(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

    l.error("Unsupported cc_op %d in in pc_calculate_rdata_all_WRK", cc_op)
    raise SimCCallError("Unsupported cc_op in pc_calculate_rdata_all_WRK")

# This function returns all the data
def pc_calculate_rdata_all(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform=None):
    rdata_all = pc_calculate_rdata_all_WRK(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform=platform)
    if isinstance(rdata_all, tuple):
        return pc_make_rdata_if_necessary(data[platform]['size'], *rdata_all, platform=platform), [ ]
    else:
        return rdata_all, [ ]

# This function takes a condition that is being checked (ie, zero bit), and basically
# returns that bit
def pc_calculate_condition(state, cond, cc_op, cc_dep1, cc_dep2, cc_ndep, platform=None):
    rdata_all = pc_calculate_rdata_all_WRK(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform=platform)
    if isinstance(rdata_all, tuple):
        cf, pf, af, zf, sf, of = rdata_all
        if state.se.symbolic(cond):
            raise SimError("Hit a symbolic 'cond' in pc_calculate_condition. Panic.")

        v = flag_concretize(state, cond)
        inv = v & 1
        l.debug("inv: %d", inv)

        if v in [ data[platform]['CondTypes']['CondO'], data[platform]['CondTypes']['CondNO'] ]:
            l.debug("CondO")
            #of = state.se.LShR(rdata, data[platform]['G_CC_SHIFT_O'])
            r = 1 & (inv ^ of)

        elif v in [ data[platform]['CondTypes']['CondZ'], data[platform]['CondTypes']['CondNZ'] ]:
            l.debug("CondZ")
            #zf = state.se.LShR(rdata, data[platform]['G_CC_SHIFT_Z'])
            r = 1 & (inv ^ zf)

        elif v in [ data[platform]['CondTypes']['CondB'], data[platform]['CondTypes']['CondNB'] ]:
            l.debug("CondB")
            #cf = state.se.LShR(rdata, data[platform]['G_CC_SHIFT_C'])
            r = 1 & (inv ^ cf)

        elif v in [ data[platform]['CondTypes']['CondBE'], data[platform]['CondTypes']['CondNBE'] ]:
            l.debug("CondBE")
            #cf = state.se.LShR(rdata, data[platform]['G_CC_SHIFT_C'])
            #zf = state.se.LShR(rdata, data[platform]['G_CC_SHIFT_Z'])
            r = 1 & (inv ^ (cf | zf))

        elif v in [ data[platform]['CondTypes']['CondS'], data[platform]['CondTypes']['CondNS'] ]:
            l.debug("CondS")
            #sf = state.se.LShR(rdata, data[platform]['G_CC_SHIFT_S'])
            r = 1 & (inv ^ sf)

        elif v in [ data[platform]['CondTypes']['CondP'], data[platform]['CondTypes']['CondNP'] ]:
            l.debug("CondP")
            #pf = state.se.LShR(rdata, data[platform]['G_CC_SHIFT_P'])
            r = 1 & (inv ^ pf)

        elif v in [ data[platform]['CondTypes']['CondL'], data[platform]['CondTypes']['CondNL'] ]:
            l.debug("CondL")
            #sf = state.se.LShR(rdata, data[platform]['G_CC_SHIFT_S'])
            #of = state.se.LShR(rdata, data[platform]['G_CC_SHIFT_O'])
            r = 1 & (inv ^ (sf ^ of))

        elif v in [ data[platform]['CondTypes']['CondLE'], data[platform]['CondTypes']['CondNLE'] ]:
            l.debug("CondLE")
            #sf = state.se.LShR(rdata, data[platform]['G_CC_SHIFT_S'])
            #of = state.se.LShR(rdata, data[platform]['G_CC_SHIFT_O'])
            #zf = state.se.LShR(rdata, data[platform]['G_CC_SHIFT_Z'])
            r = 1 & (inv ^ ((sf ^ of) | zf))

        return state.se.Concat(state.BVV(0, state.arch.bits-1), r), [ ]
    else:
        rdata = rdata_all
        if state.se.symbolic(cond):
            raise SimError("Hit a symbolic 'cond' in pc_calculate_condition. Panic.")

        v = flag_concretize(state, cond)
        inv = v & 1
        l.debug("inv: %d", inv)


        # THIS IS A FUCKING HACK
        if v == 0xe:
            # jle
            pass
            # import ipdb; ipdb.set_trace()    l.debug("cond value: 0x%x", v)
        if v in [data[platform]['CondTypes']['CondO'], data[platform]['CondTypes']['CondNO']]:
            l.debug("CondO")
            of = state.se.LShR(rdata, data[platform]['CondBitOffsets']['G_CC_SHIFT_O'])
            return 1 & (inv ^ of), []

        if v in [data[platform]['CondTypes']['CondZ'], data[platform]['CondTypes']['CondNZ']]:
            l.debug("CondZ")
            zf = state.se.LShR(rdata, data[platform]['CondBitOffsets']['G_CC_SHIFT_Z'])
            return 1 & (inv ^ zf), []

        if v in [data[platform]['CondTypes']['CondB'], data[platform]['CondTypes']['CondNB']]:
            l.debug("CondB")
            cf = state.se.LShR(rdata, data[platform]['CondBitOffsets']['G_CC_SHIFT_C'])
            return 1 & (inv ^ cf), []

        if v in [data[platform]['CondTypes']['CondBE'], data[platform]['CondTypes']['CondNBE']]:
            l.debug("CondBE")
            cf = state.se.LShR(rdata, data[platform]['CondBitOffsets']['G_CC_SHIFT_C'])
            zf = state.se.LShR(rdata, data[platform]['CondBitOffsets']['G_CC_SHIFT_Z'])
            return 1 & (inv ^ (cf | zf)), []

        if v in [data[platform]['CondTypes']['CondS'], data[platform]['CondTypes']['CondNS']]:
            l.debug("CondS")
            sf = state.se.LShR(rdata, data[platform]['CondBitOffsets']['G_CC_SHIFT_S'])
            return 1 & (inv ^ sf), []

        if v in [data[platform]['CondTypes']['CondP'], data[platform]['CondTypes']['CondNP']]:
            l.debug("CondP")
            pf = state.se.LShR(rdata, data[platform]['CondBitOffsets']['G_CC_SHIFT_P'])
            return 1 & (inv ^ pf), []

        if v in [data[platform]['CondTypes']['CondL'], data[platform]['CondTypes']['CondNL']]:
            l.debug("CondL")
            sf = state.se.LShR(rdata, data[platform]['CondBitOffsets']['G_CC_SHIFT_S'])
            of = state.se.LShR(rdata, data[platform]['CondBitOffsets']['G_CC_SHIFT_O'])
            return 1 & (inv ^ (sf ^ of)), []

        if v in [data[platform]['CondTypes']['CondLE'], data[platform]['CondTypes']['CondNLE']]:
            l.debug("CondLE")
            sf = state.se.LShR(rdata, data[platform]['CondBitOffsets']['G_CC_SHIFT_S'])
            of = state.se.LShR(rdata, data[platform]['CondBitOffsets']['G_CC_SHIFT_O'])
            zf = state.se.LShR(rdata, data[platform]['CondBitOffsets']['G_CC_SHIFT_Z'])
            return 1 & (inv ^ ((sf ^ of) | zf)), []

    l.error("Unsupported condition %d in in pc_calculate_condition", v)
    raise SimCCallError("Unrecognized condition in pc_calculate_condition")

#
# Simplified CCalls
#

"""
Simplified CCalls (whose names look like `pc_actions_<operation>_<condition>`) are a bunch of methods that generate
straight-forward ASTs based on the operation and the condition, instead of blindly following the way that a CPU does
the conditional flags calculation and generating messy and meaningless ASTs. It allows us to have a meaningful AST for
each conditional flag, which greatly helps static analysis (like VSA).
"""

# DEC

def pc_actions_DEC_CondZ(state, arg_l, arg_r, cc_ndep):
    se = state.se

    result = (arg_l - 1 == 0)
    if se.is_true(result):
        r = se.BVV(1, 1)
    elif se.is_false(result):
        r = se.BVV(0, 1)
    else:
        r = se.If(result, se.BitVecVal(1, 1), se.BitVecVal(0, 1))

    return r

# SHR

def pc_actions_SHR_CondZ(state, arg_l, arg_r, cc_ndep):
    se = state.se

    result = (arg_l >> arg_r == 0)
    if se.is_true(result):
        r = se.BVV(1, 1)
    elif se.is_false(result):
        r = se.BVV(0, 1)
    else:
        r = se.If(result, se.BitVecVal(1, 1), se.BitVecVal(0, 1))

    return r

# ADD

# TODO: Implement them

# SUB


def pc_actions_SUB_CondZ(state, arg_l, arg_r, cc_ndep):
    se = state.se

    result = (arg_l == arg_r)
    if se.is_true(result):
        r = se.BVV(1, 1)
    elif se.is_false(result):
        r = se.BVV(0, 1)
    else:
        r = se.If(arg_l == arg_r, se.BitVecVal(1, 1), se.BitVecVal(0, 1))

    return r

def pc_actions_SUB_CondNZ(state, arg_l, arg_r, cc_ndep):
    se = state.se

    result = (arg_l != arg_r)
    if se.is_true(result):
        r = se.BVV(1, 1)
    elif se.is_false(result):
        r = se.BVV(0, 1)
    else:
        r = se.If(arg_l != arg_r, se.BitVecVal(1, 1), se.BitVecVal(0, 1))

    return r

def pc_actions_SUB_CondB(state, arg_l, arg_r, cc_ndep):
    se = state.se

    result = se.ULT(arg_l, arg_r)
    if se.is_true(result):
        r = se.BVV(1, 1)
    elif se.is_false(result):
        r = se.BVV(0, 1)
    else:
        r = se.If(result, se.BitVecVal(1, 1), se.BitVecVal(0, 1))

    return r

def pc_actions_SUB_CondBE(state, arg_l, arg_r, cc_ndep):
    se = state.se

    result = se.ULE(arg_l, arg_r)
    if se.is_true(result):
        r = se.BVV(1, 1)
    elif se.is_false(result):
        r = se.BVV(0, 1)
    else:
        r = se.If(result, se.BitVecVal(1, 1), se.BitVecVal(0, 1))

    return r

def pc_actions_SUB_CondNBE(state, arg_l, arg_r, cc_ndep):
    se = state.se

    result = se.UGT(arg_l, arg_r)
    if se.is_true(result):
        r = se.BVV(1, 1)
    elif se.is_false(result):
        r = se.BVV(0, 1)
    else:
        r = se.If(result, se.BitVecVal(1, 1), se.BitVecVal(0, 1))

    return r

def pc_actions_SUB_CondL(state, arg_l, arg_r, cc_ndep):
    se = state.se

    result = (arg_l < arg_r)
    if se.is_true(result):
        r = se.BVV(1, 1)
    elif se.is_false(result):
        r = se.BVV(0, 1)
    else:
        r = se.If(result, se.BitVecVal(1, 1), se.BitVecVal(0, 1))

    return r

def pc_actions_SUB_CondLE(state, arg_l, arg_r, cc_ndep):
    se = state.se

    result = (arg_l <= arg_r)
    if se.is_true(result):
        r = se.BVV(1, 1)
    elif se.is_false(result):
        r = se.BVV(0, 1)
    else:
        r = se.If(se.ULE(arg_l, arg_r), se.BitVecVal(1, 1), se.BitVecVal(0, 1))

    return r

def pc_actions_SUB_CondNLE(state, arg_l, arg_r, cc_ndep):
    se = state.se

    result = (arg_l > arg_r)
    if se.is_true(result):
        r = se.BVV(1, 1)
    elif se.is_false(result):
        r = se.BVV(0, 1)
    else:
        r = se.If(result, se.BitVecVal(1, 1), se.BitVecVal(0, 1))

    return r

def pc_actions_SUB_CondS(state, arg_l, arg_r, cc_ndep):
    se = state.se

    result = (arg_l - arg_r < 0)
    if se.is_true(result):
        r = se.BVV(1, 1)
    elif se.is_false(result):
        r = se.BVV(0, 1)
    else:
        r = state.se.If(result, se.BitVecVal(1, 1), se.BitVecVal(0, 1))

    return r

# LOGIC

def pc_actions_LOGIC_CondZ(state, arg_l, arg_r, cc_ndep):
    se = state.se

    result = (arg_l == 0)
    if se.is_true(result):
        r = se.BVV(1, 1)
    elif se.is_false(result):
        r = se.BVV(0, 1)
    else:
        r = state.se.If(result, se.BitVecVal(1, 1), se.BitVecVal(0, 1))

    return r

def pc_actions_LOGIC_CondLE(state, arg_l, arg_r, cc_ndep):
    se = state.se

    result = (arg_l <= arg_r)
    if se.is_true(result):
        r = se.BVV(1, 1)
    elif se.is_false(result):
        r = se.BVV(0, 1)
    else:
        r = state.se.If(result, se.BitVecVal(1, 1), se.BitVecVal(0, 1))

    return r
    
def pc_actions_LOGIC_CondNZ(state, arg_l, arg_r, cc_ndep):
    se = state.se

    result = (arg_l != 0)
    if se.is_true(result):
        r = se.BVV(1, 1)
    elif se.is_false(result):
        r = se.BVV(0, 1)
    else:
        r = state.se.If(result, se.BitVecVal(1, 1), se.BitVecVal(0, 1))

    return r

def pc_actions_LOGIC_CondS(state, arg_l, arg_r, cc_ndep):
    se = state.se

    result = (arg_l < 0)
    if se.is_true(result):
        r = se.BVV(1, 1)
    elif se.is_false(result):
        r = se.BVV(0, 1)
    else:
        r = state.se.If(arg_l < 0, se.BitVecVal(1, 1), se.BitVecVal(0, 1))

    return r

def pc_calculate_condition_simple(state, cond, cc_op, cc_dep1, cc_dep2, cc_ndep, platform=None):
    """
    A simplified version of pc_calculate_condition(). Please refer to the documentation of Simplified CCalls above.

    Limitation: symbolic flags are not supported for now.
    """

    if state.se.symbolic(cond):
        raise SimError("Hit a symbolic 'cond' in pc_calculate_condition. Panic.")

    v = flag_concretize(state, cond)

    # Extract the operation
    cc_op = flag_concretize(state, cc_op)
    op = data_inverted[platform]['OpTypes'][cc_op]
    op = op[8 : -1]

    # Extract the condition
    cond = None
    # TODO: Convert it to a table-lookup later
    for key, cond_val in data[platform]['CondTypes'].iteritems():
        if cond_val == v:
            cond = key
            break

    funcname = "pc_actions_%s_%s" % (op, cond)
    if funcname in globals():
        r = globals()[funcname](state, cc_dep1, cc_dep2, cc_ndep)
        return state.se.Concat(state.BVV(0, state.arch.bits - 1), r), []

    # TODO: Fallback to the complex-mode if the target method is not found.
    raise Exception('%s not found.' % funcname)

def pc_calculate_rdata_c(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform=None):
    cc_op = flag_concretize(state, cc_op)

    if cc_op == data[platform]['OpTypes']['G_CC_OP_COPY']:
        return state.se.LShR(cc_dep1, data[platform]['CondBitOffsets']['G_CC_SHIFT_C']) & 1, [ ] # TODO: actual constraints
    elif cc_op in ( data[platform]['OpTypes']['G_CC_OP_LOGICQ'], data[platform]['OpTypes']['G_CC_OP_LOGICL'], data[platform]['OpTypes']['G_CC_OP_LOGICW'], data[platform]['OpTypes']['G_CC_OP_LOGICB'] ):
        return state.se.BitVecVal(0, state.arch.bits), [ ] # TODO: actual constraints

    rdata_all = pc_calculate_rdata_all_WRK(state, cc_op,cc_dep1,cc_dep2,cc_ndep, platform=platform)

    if isinstance(rdata_all, tuple):
        cf, pf, af, zf, sf, of = rdata_all
        return state.se.Concat(state.BVV(0, state.arch.bits-1), cf & 1), [ ]
    else:
        return state.se.LShR(rdata_all, data[platform]['CondBitOffsets']['G_CC_SHIFT_C']) & 1, []

###########################
### AMD64-specific ones ###
###########################
def amd64g_calculate_condition(state, cond, cc_op, cc_dep1, cc_dep2, cc_ndep):
    if USE_SIMPLIFIED_CCALLS in state.options:
        return pc_calculate_condition_simple(state, cond, cc_op, cc_dep1, cc_dep2, cc_ndep, platform='AMD64')
    else:
        return pc_calculate_condition(state, cond, cc_op, cc_dep1, cc_dep2, cc_ndep, platform='AMD64')

def amd64g_calculate_rflags_all(state, cc_op, cc_dep1, cc_dep2, cc_ndep):
    return pc_calculate_rdata_all(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform='AMD64')

def amd64g_calculate_rflags_c(state, cc_op, cc_dep1, cc_dep2, cc_ndep):
    return pc_calculate_rdata_c(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform='AMD64')

###########################
### X86-specific ones ###
###########################
def x86g_calculate_condition(state, cond, cc_op, cc_dep1, cc_dep2, cc_ndep):
    if USE_SIMPLIFIED_CCALLS in state.options:
        return pc_calculate_condition_simple(state, cond, cc_op, cc_dep1, cc_dep2, cc_ndep, platform='X86')
    else:
        return pc_calculate_condition(state, cond, cc_op, cc_dep1, cc_dep2, cc_ndep, platform='X86')

def x86g_calculate_eflags_all(state, cc_op, cc_dep1, cc_dep2, cc_ndep):
    return pc_calculate_rdata_all(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform='X86')

def x86g_calculate_eflags_c(state, cc_op, cc_dep1, cc_dep2, cc_ndep):
    return pc_calculate_rdata_c(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform='X86')

def x86g_check_fldcw(state, fpucw):
    return ((fpucw >> 10) & 3).zero_extend(32), ()

def x86g_create_fpucw(state, fpround):
    return 0x037f | ((fpround & 3) << 10), ()

#
# x86 segment selection
#

# Reference for the GDT entry layout
# http://wiki.osdev.org/Global_Descriptor_Table
def get_segdescr_base(state, descriptor):
    lo = descriptor[31:16]
    mid = descriptor[39:32]
    hi = descriptor[63:56]
    return state.se.Concat(hi, mid, lo)

def get_segdescr_limit(state, descriptor):
    granularity = descriptor[55]
    lo = descriptor[15:0]
    hi = descriptor[51:48]
    limit = state.se.Concat(hi, lo).zero_extend(12)
    if state.se.is_true(granularity == 0):
        return limit
    else:
        return (limit << 12) | 0xfff

def x86g_use_seg_selector(state, ldt, gdt, seg_selector, virtual_addr):
    # TODO Read/write/exec bit handling
    def bad(msg):
        if msg:
            l.warning("x86g_use_seg_selector: " + msg)
        return state.BVV(1 << 32).zero_extend(32), ()

    if state.se.is_true(seg_selector & ~0xFFFF):
        return bad("invalid selector (" + str(seg_selector) + ")")

    seg_selector &= 0x0000FFFF

    # RPL=11 check
    #if state.se.is_true((seg_selector & 3) != 3):
    #    return bad()

    tiBit = (seg_selector >> 2) & 1
    if state.se.is_true(tiBit == 0):
        # GDT access
        gdt_value = state.se.exactly_int(gdt)
        if gdt_value == 0:
            return ((seg_selector << 16) + virtual_addr).zero_extend(32), ()

        seg_selector >>= 3 # bit 3 to 15 are the index in the table
        seg_selector = seg_selector.zero_extend(32)

        gdt_limit = gdt[15:0]
        if state.se.is_true(seg_selector >= gdt_limit.zero_extend(48)):
            return bad("index out of range")

        gdt_base = gdt[47:16]
        gdt_base_value = state.se.exactly_int(gdt_base)
        descriptor = state.memory.load(gdt_base_value + seg_selector * 8, 8, endness='Iend_LE')
    else:
        # LDT access
        ldt_value = state.se.exactly_int(ldt)
        if ldt_value == 0:
            return ((seg_selector << 16) + virtual_addr).zero_extend(32), ()

        seg_selector >>= 3 # bit 3 to 15 are the index in the table
        seg_selector = seg_selector.zero_extend(32)

        ldt_limit = ldt[15:0]
        if state.se.is_true(seg_selector >= ldt_limit.zero_extend(48)):
            return bad("index out of range")

        ldt_base = ldt[47:16]
        ldt_base_value = state.se.exactly_int(ldt_base)

        ldt_value = state.se.exactly_int(ldt_base)
        descriptor = state.memory.load(ldt_value + seg_selector * 8, 8, endness='Iend_LE')

    present = descriptor[47]
    if state.se.is_true(present == 0):
        return bad("present bit set to 0")

    base = get_segdescr_base(state, descriptor)
    limit = get_segdescr_limit(state, descriptor)

    if virtual_addr.length == 16:
        virtual_addr = virtual_addr.zero_extend(16)

    if state.se.is_true(virtual_addr >= limit):
        return bad("virtual_addr >= limit")

    r = (base + virtual_addr).zero_extend(32)
    l.debug("x86g_use_seg_selector: addr=" + str(r))

    return r, ()

#################
### ARM Flags ###
#################

ARMCondEQ = 0 #   /* equal                         : Z=1 */
ARMCondNE = 1 #   /* not equal                     : Z=0 */
ARMCondHS = 2 #   /* >=u (higher or same)          : C=1 */
ARMCondLO = 3 #   /* <u  (lower)                   : C=0 */
ARMCondMI = 4 #   /* minus (negative)              : N=1 */
ARMCondPL = 5 #   /* plus (zero or +ve)            : N=0 */
ARMCondVS = 6 #   /* overflow                      : V=1 */
ARMCondVC = 7 #   /* no overflow                   : V=0 */
ARMCondHI = 8 #   /* >u   (higher)                 : C=1 && Z=0 */
ARMCondLS = 9 #   /* <=u  (lower or same)          : C=0 || Z=1 */
ARMCondGE = 10 #  /* >=s (signed greater or equal) : N=V */
ARMCondLT = 11 #  /* <s  (signed less than)        : N!=V */
ARMCondGT = 12 #  /* >s  (signed greater)          : Z=0 && N=V */
ARMCondLE = 13 #  /* <=s (signed less or equal)    : Z=1 || N!=V */
ARMCondAL = 14 #  /* always (unconditional)        : 1 */
ARMCondNV = 15 #   /* never (unconditional):        : 0 */

ARMG_CC_OP_COPY = 0   # /* DEP1 = NZCV in 31:28, DEP2 = 0, DEP3 = 0 just copy DEP1 to output */
ARMG_CC_OP_ADD = 1    # /* DEP1 = argL (Rn) =  DEP2 = argR (shifter_op) =  DEP3 = 0 */
ARMG_CC_OP_SUB = 2    # /* DEP1 = argL (Rn) =  DEP2 = argR (shifter_op) =  DEP3 = 0 */
ARMG_CC_OP_ADC = 3    # /* DEP1 = argL (Rn) =  DEP2 = arg2 (shifter_op) =  DEP3 = oldC (in LSB) */
ARMG_CC_OP_SBB = 4    # /* DEP1 = argL (Rn) =  DEP2 = arg2 (shifter_op) =  DEP3 = oldC (in LSB) */
ARMG_CC_OP_LOGIC = 5  # /* DEP1 = result =  DEP2 = shifter_carry_out (in LSB) =  DEP3 = old V flag (in LSB) */
ARMG_CC_OP_MUL = 6    # /* DEP1 = result =  DEP2 = 0 =  DEP3 = oldC:old_V (in bits 1:0) */
ARMG_CC_OP_MULL = 7   # /* DEP1 = resLO32 =  DEP2 = resHI32 =  DEP3 = oldC:old_V (in bits 1:0) */
ARMG_CC_OP_NUMBER = 8

ARMG_CC_SHIFT_N = 31
ARMG_CC_SHIFT_Z = 30
ARMG_CC_SHIFT_C = 29
ARMG_CC_SHIFT_V = 28
ARMG_CC_SHIFT_Q = 27

def armg_calculate_flag_n(state, cc_op, cc_dep1, cc_dep2, cc_dep3):
    concrete_op = flag_concretize(state, cc_op)
    flag = None

    if concrete_op == ARMG_CC_OP_COPY:
        flag = state.se.LShR(cc_dep1, ARMG_CC_SHIFT_N) & 1
    elif concrete_op == ARMG_CC_OP_ADD:
        res = cc_dep1 + cc_dep2
        flag = state.se.LShR(res, 31)
    elif concrete_op == ARMG_CC_OP_SUB:
        res = cc_dep1 - cc_dep2
        flag = state.se.LShR(res, 31)
    elif concrete_op == ARMG_CC_OP_ADC:
        res = cc_dep1 + cc_dep2 + cc_dep3
        flag = state.se.LShR(res, 31)
    elif concrete_op == ARMG_CC_OP_SBB:
        res = cc_dep1 - cc_dep2 - (cc_dep3^1)
        flag = state.se.LShR(res, 31)
    elif concrete_op == ARMG_CC_OP_LOGIC:
        flag = state.se.LShR(cc_dep1, 31)
    elif concrete_op == ARMG_CC_OP_MUL:
        flag = state.se.LShR(cc_dep1, 31)
    elif concrete_op == ARMG_CC_OP_MULL:
        flag = state.se.LShR(cc_dep2, 31)

    if flag is not None: return flag, [ cc_op == concrete_op ]
    l.error("Unknown cc_op %s (armg_calculate_flag_n)", cc_op)
    raise SimCCallError("Unknown cc_op %s" % cc_op)

def arm_zerobit(state, x):
    return calc_zerobit(state, x).zero_extend(31)

def armg_calculate_flag_z(state, cc_op, cc_dep1, cc_dep2, cc_dep3):
    concrete_op = flag_concretize(state, cc_op)
    flag = None

    if concrete_op == ARMG_CC_OP_COPY:
        flag = state.se.LShR(cc_dep1, ARMG_CC_SHIFT_Z) & 1
    elif concrete_op == ARMG_CC_OP_ADD:
        res = cc_dep1 + cc_dep2
        flag = arm_zerobit(state, res)
    elif concrete_op == ARMG_CC_OP_SUB:
        res = cc_dep1 - cc_dep2
        flag = arm_zerobit(state, res)
    elif concrete_op == ARMG_CC_OP_ADC:
        res = cc_dep1 + cc_dep2 + cc_dep3
        flag = arm_zerobit(state, res)
    elif concrete_op == ARMG_CC_OP_SBB:
        res = cc_dep1 - cc_dep2 - (cc_dep3^1)
        flag = arm_zerobit(state, res)
    elif concrete_op == ARMG_CC_OP_LOGIC:
        flag = arm_zerobit(state, cc_dep1)
    elif concrete_op == ARMG_CC_OP_MUL:
        flag = arm_zerobit(state, cc_dep1)
    elif concrete_op == ARMG_CC_OP_MULL:
        flag = arm_zerobit(state, cc_dep1 | cc_dep2)

    if flag is not None: return flag, [ cc_op == concrete_op ]

    l.error("Unknown cc_op %s (armg_calculate_flag_z)", concrete_op)
    raise SimCCallError("Unknown cc_op %s" % concrete_op)

def armg_calculate_flag_c(state, cc_op, cc_dep1, cc_dep2, cc_dep3):
    concrete_op = flag_concretize(state, cc_op)
    flag = None

    if concrete_op == ARMG_CC_OP_COPY:
        flag = state.se.LShR(cc_dep1, ARMG_CC_SHIFT_C) & 1
    elif concrete_op == ARMG_CC_OP_ADD:
        res = cc_dep1 + cc_dep2
        flag = boolean_extend(state, state.se.ULT, res, cc_dep1, 32)
    elif concrete_op == ARMG_CC_OP_SUB:
        flag = boolean_extend(state, state.se.UGE, cc_dep1, cc_dep2, 32)
    elif concrete_op == ARMG_CC_OP_ADC:
        res = cc_dep1 + cc_dep2 + cc_dep3
        flag = state.se.If(cc_dep2 != 0, boolean_extend(state, state.se.ULE, res, cc_dep1, 32), boolean_extend(state, state.se.ULT, res, cc_dep1, 32))
    elif concrete_op == ARMG_CC_OP_SBB:
        flag = state.se.If(cc_dep2 != 0, boolean_extend(state, state.se.UGE, cc_dep1, cc_dep2, 32), boolean_extend(state, state.se.UGT, cc_dep1, cc_dep2, 32))
    elif concrete_op == ARMG_CC_OP_LOGIC:
        flag = cc_dep2
    elif concrete_op == ARMG_CC_OP_MUL:
        flag = (state.se.LShR(cc_dep3, 1)) & 1
    elif concrete_op == ARMG_CC_OP_MULL:
        flag = (state.se.LShR(cc_dep3, 1)) & 1

    if flag is not None: return flag, [ cc_op == concrete_op ]

    l.error("Unknown cc_op %s (armg_calculate_flag_c)", cc_op)
    raise SimCCallError("Unknown cc_op %s" % cc_op)

def armg_calculate_flag_v(state, cc_op, cc_dep1, cc_dep2, cc_dep3):
    concrete_op = flag_concretize(state, cc_op)
    flag = None

    if concrete_op == ARMG_CC_OP_COPY:
        flag = state.se.LShR(cc_dep1, ARMG_CC_SHIFT_V) & 1
    elif concrete_op == ARMG_CC_OP_ADD:
        res = cc_dep1 + cc_dep2
        v = ((res ^ cc_dep1) & (res ^ cc_dep2))
        flag = state.se.LShR(v, 31)
    elif concrete_op == ARMG_CC_OP_SUB:
        res = cc_dep1 - cc_dep2
        v = ((cc_dep1 ^ cc_dep2) & (cc_dep1 ^ res))
        flag = state.se.LShR(v, 31)
    elif concrete_op == ARMG_CC_OP_ADC:
        res = cc_dep1 + cc_dep2 + cc_dep3
        v = ((res ^ cc_dep1) & (res ^ cc_dep2))
        flag = state.se.LShR(v, 31)
    elif concrete_op == ARMG_CC_OP_SBB:
        res = cc_dep1 - cc_dep2 - (cc_dep3^1)
        v = ((cc_dep1 ^ cc_dep2) & (cc_dep1 ^ res))
        flag = state.se.LShR(v, 31)
    elif concrete_op == ARMG_CC_OP_LOGIC:
        flag = cc_dep3
    elif concrete_op == ARMG_CC_OP_MUL:
        flag = cc_dep3 & 1
    elif concrete_op == ARMG_CC_OP_MULL:
        flag = cc_dep3 & 1

    if flag is not None: return flag, [ cc_op == concrete_op ]

    l.error("Unknown cc_op %s (armg_calculate_flag_v)", cc_op)
    raise SimCCallError("Unknown cc_op %s" % cc_op)

def armg_calculate_data_nzcv(state, cc_op, cc_dep1, cc_dep2, cc_dep3):
    # NOTE: adding constraints afterwards works here *only* because the constraints are actually useless, because we require
    # cc_op to be unique. If we didn't, we'd need to pass the constraints into any functions called after the constraints were
    # created.
    n, c1 = armg_calculate_flag_n(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
    z, c2 = armg_calculate_flag_z(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
    c, c3 = armg_calculate_flag_c(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
    v, c4 = armg_calculate_flag_v(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
    return (n << ARMG_CC_SHIFT_N) | (z << ARMG_CC_SHIFT_Z) | (c << ARMG_CC_SHIFT_C) | (v << ARMG_CC_SHIFT_V), c1 + c2 + c3 + c4

def armg_calculate_condition(state, cond_n_op, cc_dep1, cc_dep2, cc_dep3):
    cond = state.se.LShR(cond_n_op, 4)
    cc_op = cond_n_op & 0xF
    inv = cond & 1

    concrete_cond = flag_concretize(state, cond)
    flag = None
    c1,c2,c3 = [ ], [ ], [ ]

    # NOTE: adding constraints afterwards works here *only* because the constraints are actually useless, because we require
    # cc_op to be unique. If we didn't, we'd need to pass the constraints into any functions called after the constraints were
    # created.

    if concrete_cond == ARMCondAL:
        flag = state.se.BitVecVal(1, 32)
    elif concrete_cond in [ ARMCondEQ, ARMCondNE ]:
        zf, c1 = armg_calculate_flag_z(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        flag = inv ^ zf
    elif concrete_cond in [ ARMCondHS, ARMCondLO ]:
        cf, c1 = armg_calculate_flag_c(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        flag = inv ^ cf
    elif concrete_cond in [ ARMCondMI, ARMCondPL ]:
        nf, c1 = armg_calculate_flag_n(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        flag = inv ^ nf
    elif concrete_cond in [ ARMCondVS, ARMCondVC ]:
        vf, c1 = armg_calculate_flag_v(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        flag = inv ^ vf
    elif concrete_cond in [ ARMCondHI, ARMCondLS ]:
        cf, c1 = armg_calculate_flag_c(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        zf, c2 = armg_calculate_flag_z(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        flag = inv ^ (cf & ~zf)
    elif concrete_cond in [ ARMCondGE, ARMCondLT ]:
        nf, c1 = armg_calculate_flag_n(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        vf, c2 = armg_calculate_flag_v(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        flag = inv ^ (1 & ~(nf ^ vf))
    elif concrete_cond in [ ARMCondGT, ARMCondLE ]:
        nf, c1 = armg_calculate_flag_n(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        vf, c2 = armg_calculate_flag_v(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        zf, c3 = armg_calculate_flag_z(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        flag = inv ^ (1 & ~(zf | (nf ^ vf)))

    if flag is not None: return flag, [ cond == concrete_cond ] + c1 + c2 + c3

    l.error("Unrecognized condition %d in armg_calculate_condition", concrete_cond)
    raise SimCCallError("Unrecognized condition %d in armg_calculate_condition" % concrete_cond)

ARM64G_CC_SHIFT_N = 31
ARM64G_CC_SHIFT_Z = 30
ARM64G_CC_SHIFT_C = 29
ARM64G_CC_SHIFT_V = 28

ARM64G_CC_OP_COPY=0      #/* DEP1 = NZCV in 31:28, DEP2 = 0, DEP3 = 0 just copy DEP1 to output */
ARM64G_CC_OP_ADD32=1     #/* DEP1 = argL (Rn), DEP2 = argR (shifter_op), DEP3 = 0 */
ARM64G_CC_OP_ADD64=2     #/* DEP1 = argL (Rn), DEP2 = argR (shifter_op), DEP3 = 0 */
ARM64G_CC_OP_SUB32=3     #/* DEP1 = argL (Rn), DEP2 = argR (shifter_op), DEP3 = 0 */
ARM64G_CC_OP_SUB64=4     #/* DEP1 = argL (Rn), DEP2 = argR (shifter_op), DEP3 = 0 */
ARM64G_CC_OP_ADC32=5     #/* DEP1 = argL (Rn), DEP2 = arg2 (shifter_op), DEP3 = oldC (in LSB) */
ARM64G_CC_OP_ADC64=6     #/* DEP1 = argL (Rn), DEP2 = arg2 (shifter_op), DEP3 = oldC (in LSB) */
ARM64G_CC_OP_SBC32=7     #/* DEP1 = argL (Rn), DEP2 = arg2 (shifter_op), DEP3 = oldC (in LSB) */
ARM64G_CC_OP_SBC64=8     #/* DEP1 = argL (Rn), DEP2 = arg2 (shifter_op), DEP3 = oldC (in LSB) */
ARM64G_CC_OP_LOGIC32=9   #/* DEP1 = result, DEP2 = 0, DEP3 = 0 */
ARM64G_CC_OP_LOGIC64=10  #/* DEP1 = result, DEP2 = 0, DEP3 = 0 */
ARM64G_CC_OP_NUMBER=11   #

ARM64CondEQ = 0  #/* equal                         : Z=1 */
ARM64CondNE = 1  #/* not equal                     : Z=0 */
ARM64CondCS = 2  #/* >=u (higher or same) (aka HS) : C=1 */
ARM64CondCC = 3  #/* <u  (lower)          (aka LO) : C=0 */
ARM64CondMI = 4  #/* minus (negative)              : N=1 */
ARM64CondPL = 5  #/* plus (zero or +ve)            : N=0 */
ARM64CondVS = 6  #/* overflow                      : V=1 */
ARM64CondVC = 7  #/* no overflow                   : V=0 */
ARM64CondHI = 8  #/* >u   (higher)                 : C=1 && Z=0 */
ARM64CondLS = 9  #/* <=u  (lower or same)          : C=0 || Z=1 */
ARM64CondGE = 10 #/* >=s (signed greater or equal) : N=V */
ARM64CondLT = 11 #/* <s  (signed less than)        : N!=V */
ARM64CondGT = 12 #/* >s  (signed greater)          : Z=0 && N=V */
ARM64CondLE = 13 #/* <=s (signed less or equal)    : Z=1 || N!=V */
ARM64CondAL = 14 #/* always (unconditional)        : 1 */
ARM64CondNV = 15 #/* always (unconditional)        : 1 */

def arm64g_calculate_flag_n(state, cc_op, cc_dep1, cc_dep2, cc_dep3):
    concrete_op = flag_concretize(state, cc_op)
    flag = None

    if concrete_op == ARM64G_CC_OP_COPY:
        flag = state.se.LShR(cc_dep1, ARM64G_CC_SHIFT_N) & 1
    elif concrete_op == ARM64G_CC_OP_ADD32:
        res = cc_dep1 + cc_dep2
        flag = state.se.LShR(res, 31)
    elif concrete_op == ARM64G_CC_OP_ADD64:
        res = cc_dep1 + cc_dep2
        flag = state.se.LShR(res, 63)
    elif concrete_op == ARM64G_CC_OP_SUB32:
        res = cc_dep1 - cc_dep2
        flag = state.se.LShR(res, 31)
    elif concrete_op == ARM64G_CC_OP_SUB64:
        res = cc_dep1 - cc_dep2
        flag = state.se.LShR(res, 63)
    elif concrete_op == ARM64G_CC_OP_ADC32:
        res = cc_dep1 + cc_dep2 + cc_dep3
        flag = state.se.LShR(res, 31)
    elif concrete_op == ARM64G_CC_OP_ADC64:
        res = cc_dep1 + cc_dep2 + cc_dep3
        flag = state.se.LShR(res, 63)
    elif concrete_op == ARM64G_CC_OP_SBC32:
        res = cc_dep1 - cc_dep2 - (cc_dep3^1)
        flag = state.se.LShR(res, 31)
    elif concrete_op == ARM64G_CC_OP_SBC64:
        res = cc_dep1 - cc_dep2 - (cc_dep3^1)
        flag = state.se.LShR(res, 63)
    elif concrete_op == ARM64G_CC_OP_LOGIC32:
        flag = state.se.LShR(cc_dep1, 31)
    elif concrete_op == ARM64G_CC_OP_LOGIC64:
        flag = state.se.LShR(cc_dep1, 63)

    if flag is not None: return flag, [ cc_op == concrete_op ]
    l.error("Unknown cc_op %s (arm64g_calculate_flag_n)", cc_op)
    raise SimCCallError("Unknown cc_op %s" % cc_op)

def arm64_zerobit(state, x):
    return calc_zerobit(state, x).zero_extend(63)

def arm64g_calculate_flag_z(state, cc_op, cc_dep1, cc_dep2, cc_dep3):
    concrete_op = flag_concretize(state, cc_op)
    flag = None

    if concrete_op == ARM64G_CC_OP_COPY:
        flag = state.se.LShR(cc_dep1, ARM64G_CC_SHIFT_Z) & 1
    elif concrete_op in (ARM64G_CC_OP_ADD32, ARM64G_CC_OP_ADD64):
        res = cc_dep1 + cc_dep2
        flag = arm64_zerobit(state, res)
    elif concrete_op in (ARM64G_CC_OP_SUB32, ARM64G_CC_OP_SUB64):
        res = cc_dep1 - cc_dep2
        flag = arm64_zerobit(state, res)
    elif concrete_op in (ARM64G_CC_OP_ADC32, ARM64G_CC_OP_ADC64):
        res = cc_dep1 + cc_dep2 + cc_dep3
        flag = arm64_zerobit(state, res)
    elif concrete_op in (ARM64G_CC_OP_SBC32, ARM64G_CC_OP_SBC64):
        res = cc_dep1 - cc_dep2 - (cc_dep3^1)
        flag = arm64_zerobit(state, res)
    elif concrete_op in (ARM64G_CC_OP_LOGIC32, ARM64G_CC_OP_LOGIC64):
        flag = arm64_zerobit(state, cc_dep1)

    if flag is not None: return flag, [ cc_op == concrete_op ]

    l.error("Unknown cc_op %s (arm64g_calculate_flag_z)", concrete_op)
    raise SimCCallError("Unknown cc_op %s" % concrete_op)

def arm64g_calculate_flag_c(state, cc_op, cc_dep1, cc_dep2, cc_dep3):
    concrete_op = flag_concretize(state, cc_op)
    flag = None

    if concrete_op == ARM64G_CC_OP_COPY:
        flag = state.se.LShR(cc_dep1, ARM64G_CC_SHIFT_C) & 1
    elif concrete_op in (ARM64G_CC_OP_ADD32, ARM64G_CC_OP_ADD64):
        res = cc_dep1 + cc_dep2
        flag = boolean_extend(state, state.se.ULT, res, cc_dep1, 64)
    elif concrete_op in (ARM64G_CC_OP_SUB32, ARM64G_CC_OP_SUB64):
        flag = boolean_extend(state, state.se.UGE, cc_dep1, cc_dep2, 64)
    elif concrete_op in (ARM64G_CC_OP_ADC32, ARM64G_CC_OP_ADC64):
        res = cc_dep1 + cc_dep2 + cc_dep3
        flag = state.se.If(cc_dep2 != 0, boolean_extend(state, state.se.ULE, res, cc_dep1, 64), boolean_extend(state, state.se.ULT, res, cc_dep1, 64))
    elif concrete_op in (ARM64G_CC_OP_SBC32, ARM64G_CC_OP_SBC64):
        flag = state.se.If(cc_dep2 != 0, boolean_extend(state, state.se.UGE, cc_dep1, cc_dep2, 64), boolean_extend(state, state.se.UGT, cc_dep1, cc_dep2, 64))
    elif concrete_op in (ARM64G_CC_OP_LOGIC32, ARM64G_CC_OP_LOGIC64):
        flag = state.BVV(0, 64) # C after logic is zero on arm64

    if flag is not None: return flag, [ cc_op == concrete_op ]

    l.error("Unknown cc_op %s (arm64g_calculate_flag_c)", cc_op)
    raise SimCCallError("Unknown cc_op %s" % cc_op)

def arm64g_calculate_flag_v(state, cc_op, cc_dep1, cc_dep2, cc_dep3):
    concrete_op = flag_concretize(state, cc_op)
    flag = None

    if concrete_op == ARM64G_CC_OP_COPY:
        flag = state.se.LShR(cc_dep1, ARM64G_CC_SHIFT_V) & 1
    elif concrete_op == ARM64G_CC_OP_ADD32:
        res = cc_dep1 + cc_dep2
        v = ((res ^ cc_dep1) & (res ^ cc_dep2))
        flag = state.se.LShR(v, 31).zero_extend(32)
    elif concrete_op == ARM64G_CC_OP_ADD64:
        res = cc_dep1 + cc_dep2
        v = ((res ^ cc_dep1) & (res ^ cc_dep2))
        flag = state.se.LShR(v, 63)
    elif concrete_op == ARM64G_CC_OP_SUB32:
        res = cc_dep1 - cc_dep2
        v = ((cc_dep1 ^ cc_dep2) & (cc_dep1 ^ res))
        flag = state.se.LShR(v, 31).zero_extend(32)
    elif concrete_op == ARM64G_CC_OP_SUB64:
        res = cc_dep1 - cc_dep2
        v = ((cc_dep1 ^ cc_dep2) & (cc_dep1 ^ res))
        flag = state.se.LShR(v, 63)
    elif concrete_op == ARM64G_CC_OP_ADC32:
        res = cc_dep1 + cc_dep2 + cc_dep3
        v = ((res ^ cc_dep1) & (res ^ cc_dep2))
        flag = state.se.LShR(v, 31).zero_extend(32)
    elif concrete_op == ARM64G_CC_OP_ADC64:
        res = cc_dep1 + cc_dep2 + cc_dep3
        v = ((res ^ cc_dep1) & (res ^ cc_dep2))
        flag = state.se.LShR(v, 63)
    elif concrete_op == ARM64G_CC_OP_SBC32:
        res = cc_dep1 - cc_dep2 - (cc_dep3^1)
        v = ((cc_dep1 ^ cc_dep2) & (cc_dep1 ^ res))
        flag = state.se.LShR(v, 31).zero_extend(32)
    elif concrete_op == ARM64G_CC_OP_SBC64:
        res = cc_dep1 - cc_dep2 - (cc_dep3^1)
        v = ((cc_dep1 ^ cc_dep2) & (cc_dep1 ^ res))
        flag = state.se.LShR(v, 63).zero_extend(32)
    elif concrete_op in (ARM64G_CC_OP_LOGIC32, ARM64G_CC_OP_LOGIC64):
        flag = state.BVV(0, 64)

    if flag is not None: return flag, [ cc_op == concrete_op ]

    l.error("Unknown cc_op %s (arm64g_calculate_flag_v)", cc_op)
    raise SimCCallError("Unknown cc_op %s" % cc_op)

def arm64g_calculate_data_nzcv(state, cc_op, cc_dep1, cc_dep2, cc_dep3):
    # NOTE: adding constraints afterwards works here *only* because the constraints are actually useless, because we require
    # cc_op to be unique. If we didn't, we'd need to pass the constraints into any functions called after the constraints were
    # created.
    n, c1 = arm64g_calculate_flag_n(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
    z, c2 = arm64g_calculate_flag_z(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
    c, c3 = arm64g_calculate_flag_c(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
    v, c4 = arm64g_calculate_flag_v(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
    return (n << ARM64G_CC_SHIFT_N) | (z << ARM64G_CC_SHIFT_Z) | (c << ARM64G_CC_SHIFT_C) | (v << ARM64G_CC_SHIFT_V), c1 + c2 + c3 + c4

def arm64g_calculate_condition(state, cond_n_op, cc_dep1, cc_dep2, cc_dep3):
    cond = state.se.LShR(cond_n_op, 4)
    cc_op = cond_n_op & 0xF
    inv = cond & 1

    concrete_cond = flag_concretize(state, cond)
    flag = None
    c1,c2,c3 = [ ], [ ], [ ]

    if concrete_cond in (ARM64CondAL, ARM64CondNV):
        flag = state.se.BitVecVal(1, 64)
    elif concrete_cond in (ARM64CondEQ, ARM64CondNE):
        zf, c1 = arm64g_calculate_flag_z(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        flag = inv ^ zf
    elif concrete_cond in (ARM64CondCS, ARM64CondCC):
        cf, c1 = arm64g_calculate_flag_c(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        flag = inv ^ cf
    elif concrete_cond in (ARM64CondMI, ARM64CondPL):
        nf, c1 = arm64g_calculate_flag_n(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        flag = inv ^ nf
    elif concrete_cond in (ARM64CondVS, ARM64CondVC):
        vf, c1 = arm64g_calculate_flag_v(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        flag = inv ^ vf
    elif concrete_cond in (ARM64CondHI, ARM64CondLS):
        cf, c1 = arm64g_calculate_flag_c(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        zf, c2 = arm64g_calculate_flag_z(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        flag = inv ^ (1 & (cf & ~zf))
    elif concrete_cond in (ARM64CondGE, ARM64CondLT):
        nf, c1 = arm64g_calculate_flag_n(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        vf, c2 = arm64g_calculate_flag_v(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        flag = inv ^ (1 & ~(nf ^ vf))
    elif concrete_cond in (ARM64CondGT, ARM64CondLE):
        nf, c1 = arm64g_calculate_flag_n(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        vf, c2 = arm64g_calculate_flag_v(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        zf, c3 = arm64g_calculate_flag_z(state, cc_op, cc_dep1, cc_dep2, cc_dep3)
        flag = inv ^ (1 & ~(zf | (nf ^ vf)))

    if flag is not None: return flag, [ cond == concrete_cond ] + c1 + c2 + c3

    l.error("Unrecognized condition %d in arm64g_calculate_condition", concrete_cond)
    raise SimCCallError("Unrecognized condition %d in arm64g_calculate_condition" % concrete_cond)


from ..s_errors import SimError, SimCCallError
from ..s_options import USE_SIMPLIFIED_CCALLS
