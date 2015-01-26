#!/usr/bin/env python

import logging
l = logging.getLogger("simuvex.s_ccall")
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
def pc_actions_SMUL(*args, **kwargs):
    l.error("Unsupported flag action SMUL")
    raise SimCCallError("Unsupported flag action. Please implement or bug Yan.")
def pc_actions_SMULQ(*args, **kwargs):
    l.error("Unsupported flag action SMULQ")
    raise SimCCallError("Unsupported flag action. Please implement or bug Yan.")



def pc_calculate_rdata_all_WRK(state, cc_op, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=None):
    # sanity check
    if type(cc_op) not in (int, long):
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
    if type(rdata_all) is tuple:
        return pc_make_rdata_if_necessary(data[platform]['size'], *rdata_all, platform=platform), [ ]
    else:
        return rdata_all, [ ]

# This function takes a condition that is being checked (ie, zero bit), and basically
# returns that bit
def pc_calculate_condition(state, cond, cc_op, cc_dep1, cc_dep2, cc_ndep, platform=None):
    rdata_all = pc_calculate_rdata_all_WRK(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform=platform)
    if type(rdata_all) is tuple:
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

        if v in [data[platform]['CondTypes']['CondB'], data[platform]['CondBitOffsets']['CondNB']]:
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

def pc_calculate_rdata_c(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform=None):
    cc_op = flag_concretize(state, cc_op)

    if cc_op == data[platform]['OpTypes']['G_CC_OP_COPY']:
        return state.se.LShR(cc_dep1, data[platform]['CondBitOffsets']['G_CC_SHIFT_C']) & 1, [ ] # TODO: actual constraints
    elif cc_op in ( data[platform]['OpTypes']['G_CC_OP_LOGICQ'], data[platform]['OpTypes']['G_CC_OP_LOGICL'], data[platform]['OpTypes']['G_CC_OP_LOGICW'], data[platform]['OpTypes']['G_CC_OP_LOGICB'] ):
        return state.se.BitVecVal(0, state.arch.bits), [ ] # TODO: actual constraints

    rdata_all = pc_calculate_rdata_all_WRK(state, cc_op,cc_dep1,cc_dep2,cc_ndep, platform=platform)

    if type(rdata_all) is tuple:
        cf, pf, af, zf, sf, of = rdata_all
        return state.se.Concat(state.BVV(0, state.arch.bits-1), cf & 1), [ ]
    else:
        return state.se.LShR(rdata_all, data[platform]['CondBitOffsets']['G_CC_SHIFT_C']) & 1, []

###########################
### AMD64-specific ones ###
###########################
def amd64g_calculate_condition(state, cond, cc_op, cc_dep1, cc_dep2, cc_ndep):
    return pc_calculate_condition(state, cond, cc_op, cc_dep1, cc_dep2, cc_ndep, platform='AMD64')

def amd64g_calculate_rflags_all(state, cc_op, cc_dep1, cc_dep2, cc_ndep):
    return pc_calculate_rdata_all(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform='AMD64')

def amd64g_calculate_rflags_c(state, cc_op, cc_dep1, cc_dep2, cc_ndep):
    return pc_calculate_rdata_c(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform='AMD64')

###########################
### X86-specific ones ###
###########################
def x86g_calculate_condition(state, cond, cc_op, cc_dep1, cc_dep2, cc_ndep):
    return pc_calculate_condition(state, cond, cc_op, cc_dep1, cc_dep2, cc_ndep, platform='X86')

def x86g_calculate_eflags_all(state, cc_op, cc_dep1, cc_dep2, cc_ndep):
    return pc_calculate_rdata_all(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform='X86')

def x86g_calculate_eflags_c(state, cc_op, cc_dep1, cc_dep2, cc_ndep):
    return pc_calculate_rdata_c(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform='X86')

#
# x86 segment selection
#

def get_segdescr_base(state, descriptor):
    lo = descriptor[47:32]
    mid = descriptor[31:24]
    hi = descriptor[7:0]
    return state.se.Concat(hi, mid, lo)

def get_segdescr_limit(state, descriptor):
    lo = descriptor[63:48]
    hi = descriptor[15:12]
    return state.se.Concat(hi, lo).zero_extend(8)

def x86g_use_seg_selector(state, ldt, gdt, seg_selector, virtual_addr):
    a = 0xf00d + virtual_addr
    return a.zero_extend(64 - len(a)), [ ]
# TODO: /* Check for wildly invalid selector. */
# TODO: if (seg_selector & ~0xFFFF)
# TODO:     goto bad;

# TODO:    seg_selector = seg_selector & 0x0000FFFF
# TODO:
# TODO:   #/* Sanity check the segment selector.  Ensure that RPL=11b (least
# TODO:   #    privilege).  This forms the bottom 2 bits of the selector. */
# TODO:   if ((seg_selector & 3) != 3)
# TODO:       goto bad;

# TODO:   /* Extract the TI bit (0 means GDT, 1 means LDT) */
# TODO:   tiBit = (seg_selector >> 2) & 1;

# TODO:   /* Convert the segment selector onto a table index */
# TODO:   seg_selector >>= 3;
# TODO:   vassert(seg_selector >= 0 && seg_selector < 8192);

# TODO:   if (tiBit == 0) {

# TODO:       /* GDT access. */
# TODO:       /* Do we actually have a GDT to look at? */
# TODO:       if (gdt == 0)
# TODO:           goto bad;

# TODO:       /* Check for access to non-existent entry. */
# TODO:       if (seg_selector >= VEX_GUEST_X86_GDT_NENT)
# TODO:           goto bad;

# TODO:       the_descrs = (VexGuestX86SegDescr*)gdt;
# TODO:       base  = get_segdescr_base (&the_descrs[seg_selector]);
# TODO:       limit = get_segdescr_limit(&the_descrs[seg_selector]);

# TODO:   } else {

# TODO:       /* All the same stuff, except for the LDT. */
# TODO:       if (ldt == 0)
# TODO:           goto bad;

# TODO:       if (seg_selector >= VEX_GUEST_X86_LDT_NENT)
# TODO:           goto bad;

# TODO:       the_descrs = (VexGuestX86SegDescr*)ldt;
# TODO:       base  = get_segdescr_base (&the_descrs[seg_selector]);
# TODO:       limit = get_segdescr_limit(&the_descrs[seg_selector]);

# TODO:   }

# TODO:   /* Do the limit check.  Note, this check is just slightly too
# TODO:       slack.  Really it should be "if (virtual_addr + size - 1 >=
# TODO:       limit)," but we don't have the size info to hand.  Getting it
# TODO:       could be significantly complex.  */
# TODO:   if (virtual_addr >= limit)
# TODO:       goto bad;

# TODO:   if (verboze)
# TODO:       vex_printf("x86h_use_seg_selector: "
# TODO:                     "base = 0x%x, addr = 0x%x\n",
# TODO:                     base, base + virtual_addr);

# TODO:   /* High 32 bits are zero, indicating success. */
# TODO:   return (ULong)( ((UInt)virtual_addr) + base );

# TODO:bad:
# TODO:   return 1ULL << 32;
# TODO:

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
    l.error("Unknown cc_op %s", cc_op)
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

    l.error("Unknown cc_op %s", concrete_op)
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

    l.error("Unknown cc_op %s", cc_op)
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

    l.error("Unknown cc_op %s", cc_op)
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

from ..s_errors import SimError, SimCCallError
