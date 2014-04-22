#!/usr/bin/env python

import symexec

import logging
l = logging.getLogger("s_ccall")
#l.setLevel(logging.DEBUG)

# pylint: disable=R0911
# pylint: disable=W0613
# pylint: disable=W0612

###############
### Helpers ###
###############

# There might be a better way of doing this
def calc_paritybit(p):
	b = symexec.BitVecVal(1, 1)
	for i in xrange(p.size()):
		b = b ^ symexec.Extract(i, i, p)
	return b

def calc_zerobit(state, p):
	return sim_ite_autoadd(state, p == 0, symexec.BitVecVal(1, 1), symexec.BitVecVal(0, 1))
	#b = symexec.BitVecVal(0, 1)
	#for i in xrange(p.size()):
	#	b = b | symexec.Extract(i, i, p)
	#return b ^ symexec.BitVecVal(1, 1)

def boolean_extend(state, O, a, b, size):
	return sim_ite_autoadd(state, O(a, b), symexec.BitVecVal(1, size), symexec.BitVecVal(0, size))

def flag_concretize(state, flag):
	flag_value = state.expr_value(flag)
	return flag_value.exactly_n(1)[0]

##################
### x86* data ###
##################

data = { 'AMD64': { }, 'X86': { } }

data['AMD64']['size'] = 64

# condition types
data['AMD64']['CondO']      = 0  # /* overflow           */
data['AMD64']['CondNO']     = 1  # /* no overflow        */
data['AMD64']['CondB']      = 2  # /* below              */
data['AMD64']['CondNB']     = 3  # /* not below          */
data['AMD64']['CondZ']      = 4  # /* zero               */
data['AMD64']['CondNZ']     = 5  # /* not zero           */
data['AMD64']['CondBE']     = 6  # /* below or equal     */
data['AMD64']['CondNBE']    = 7  # /* not below or equal */
data['AMD64']['CondS']      = 8  # /* negative           */
data['AMD64']['CondNS']     = 9  # /* not negative       */
data['AMD64']['CondP']      = 10 # /* parity even        */
data['AMD64']['CondNP']     = 11 # /* not parity even    */
data['AMD64']['CondL']      = 12 # /* jump less          */
data['AMD64']['CondNL']     = 13 # /* not less           */
data['AMD64']['CondLE']     = 14 # /* less or equal      */
data['AMD64']['CondNLE']    = 15 # /* not less or equal  */

# condition bit offsets
data['AMD64']['G_CC_SHIFT_O'] = 11
data['AMD64']['G_CC_SHIFT_S'] = 7
data['AMD64']['G_CC_SHIFT_Z'] = 6
data['AMD64']['G_CC_SHIFT_A'] = 4
data['AMD64']['G_CC_SHIFT_C'] = 0
data['AMD64']['G_CC_SHIFT_P'] = 2

# masks
data['AMD64']['G_CC_MASK_O'] = (1 << data['AMD64']['G_CC_SHIFT_O'])
data['AMD64']['G_CC_MASK_S'] = (1 << data['AMD64']['G_CC_SHIFT_S'])
data['AMD64']['G_CC_MASK_Z'] = (1 << data['AMD64']['G_CC_SHIFT_Z'])
data['AMD64']['G_CC_MASK_A'] = (1 << data['AMD64']['G_CC_SHIFT_A'])
data['AMD64']['G_CC_MASK_C'] = (1 << data['AMD64']['G_CC_SHIFT_C'])
data['AMD64']['G_CC_MASK_P'] = (1 << data['AMD64']['G_CC_SHIFT_P'])

# operation types
data['AMD64']['G_CC_OP_COPY'] = 0
data['AMD64']['G_CC_OP_ADDB'] = 1
data['AMD64']['G_CC_OP_ADDW'] = 2
data['AMD64']['G_CC_OP_ADDL'] = 3
data['AMD64']['G_CC_OP_ADDQ'] = 4
data['AMD64']['G_CC_OP_SUBB'] = 5
data['AMD64']['G_CC_OP_SUBW'] = 6
data['AMD64']['G_CC_OP_SUBL'] = 7
data['AMD64']['G_CC_OP_SUBQ'] = 8
data['AMD64']['G_CC_OP_ADCB'] = 9
data['AMD64']['G_CC_OP_ADCW'] = 10
data['AMD64']['G_CC_OP_ADCL'] = 11
data['AMD64']['G_CC_OP_ADCQ'] = 12
data['AMD64']['G_CC_OP_SBBB'] = 13
data['AMD64']['G_CC_OP_SBBW'] = 14
data['AMD64']['G_CC_OP_SBBL'] = 15
data['AMD64']['G_CC_OP_SBBQ'] = 16
data['AMD64']['G_CC_OP_LOGICB'] = 17
data['AMD64']['G_CC_OP_LOGICW'] = 18
data['AMD64']['G_CC_OP_LOGICL'] = 19
data['AMD64']['G_CC_OP_LOGICQ'] = 20
data['AMD64']['G_CC_OP_INCB'] = 21
data['AMD64']['G_CC_OP_INCW'] = 22
data['AMD64']['G_CC_OP_INCL'] = 23
data['AMD64']['G_CC_OP_INCQ'] = 24
data['AMD64']['G_CC_OP_DECB'] = 25
data['AMD64']['G_CC_OP_DECW'] = 26
data['AMD64']['G_CC_OP_DECL'] = 27
data['AMD64']['G_CC_OP_DECQ'] = 28
data['AMD64']['G_CC_OP_SHLB'] = 29
data['AMD64']['G_CC_OP_SHLW'] = 30
data['AMD64']['G_CC_OP_SHLL'] = 31
data['AMD64']['G_CC_OP_SHLQ'] = 32
data['AMD64']['G_CC_OP_SHRB'] = 33
data['AMD64']['G_CC_OP_SHRW'] = 34
data['AMD64']['G_CC_OP_SHRL'] = 35
data['AMD64']['G_CC_OP_SHRQ'] = 36
data['AMD64']['G_CC_OP_ROLB'] = 37
data['AMD64']['G_CC_OP_ROLW'] = 38
data['AMD64']['G_CC_OP_ROLL'] = 39
data['AMD64']['G_CC_OP_ROLQ'] = 40
data['AMD64']['G_CC_OP_RORB'] = 41
data['AMD64']['G_CC_OP_RORW'] = 42
data['AMD64']['G_CC_OP_RORL'] = 43
data['AMD64']['G_CC_OP_RORQ'] = 44
data['AMD64']['G_CC_OP_UMULB'] = 45
data['AMD64']['G_CC_OP_UMULW'] = 46
data['AMD64']['G_CC_OP_UMULL'] = 47
data['AMD64']['G_CC_OP_UMULQ'] = 48
data['AMD64']['G_CC_OP_SMULB'] = 49
data['AMD64']['G_CC_OP_SMULW'] = 50
data['AMD64']['G_CC_OP_SMULL'] = 51
data['AMD64']['G_CC_OP_SMULQ'] = 52
data['AMD64']['G_CC_OP_NUMBER'] = 53

data['X86']['size']      = 32

data['X86']['CondO']      = 0
data['X86']['CondNO']     = 1
data['X86']['CondB']      = 2
data['X86']['CondNB']     = 3
data['X86']['CondZ']      = 4
data['X86']['CondNZ']     = 5
data['X86']['CondBE']     = 6
data['X86']['CondNBE']    = 7
data['X86']['CondS']      = 8
data['X86']['CondNS']     = 9
data['X86']['CondP']      = 10
data['X86']['CondNP']     = 11
data['X86']['CondL']      = 12
data['X86']['CondNL']     = 13
data['X86']['CondLE']     = 14
data['X86']['CondNLE']    = 15
data['X86']['CondAlways'] = 16

data['X86']['G_CC_SHIFT_O'] = 11
data['X86']['G_CC_SHIFT_S'] = 7
data['X86']['G_CC_SHIFT_Z'] = 6
data['X86']['G_CC_SHIFT_A'] = 4
data['X86']['G_CC_SHIFT_C'] = 0
data['X86']['G_CC_SHIFT_P'] = 2

# masks
data['X86']['G_CC_MASK_O'] = (1 << data['X86']['G_CC_SHIFT_O'])
data['X86']['G_CC_MASK_S'] = (1 << data['X86']['G_CC_SHIFT_S'])
data['X86']['G_CC_MASK_Z'] = (1 << data['X86']['G_CC_SHIFT_Z'])
data['X86']['G_CC_MASK_A'] = (1 << data['X86']['G_CC_SHIFT_A'])
data['X86']['G_CC_MASK_C'] = (1 << data['X86']['G_CC_SHIFT_C'])
data['X86']['G_CC_MASK_P'] = (1 << data['X86']['G_CC_SHIFT_P'])

data['X86']['G_CC_OP_COPY'] = 0
data['X86']['G_CC_OP_ADDB'] = 1
data['X86']['G_CC_OP_ADDW'] = 2
data['X86']['G_CC_OP_ADDL'] = 3
data['X86']['G_CC_OP_SUBB'] = 4
data['X86']['G_CC_OP_SUBW'] = 5
data['X86']['G_CC_OP_SUBL'] = 6
data['X86']['G_CC_OP_ADCB'] = 7
data['X86']['G_CC_OP_ADCW'] = 8
data['X86']['G_CC_OP_ADCL'] = 9
data['X86']['G_CC_OP_SBBB'] = 10
data['X86']['G_CC_OP_SBBW'] = 11
data['X86']['G_CC_OP_SBBL'] = 12
data['X86']['G_CC_OP_LOGICB'] = 13
data['X86']['G_CC_OP_LOGICW'] = 14
data['X86']['G_CC_OP_LOGICL'] = 15
data['X86']['G_CC_OP_INCB'] = 16
data['X86']['G_CC_OP_INCW'] = 17
data['X86']['G_CC_OP_INCL'] = 18
data['X86']['G_CC_OP_DECB'] = 19
data['X86']['G_CC_OP_DECW'] = 20
data['X86']['G_CC_OP_DECL'] = 21
data['X86']['G_CC_OP_SHLB'] = 22
data['X86']['G_CC_OP_SHLW'] = 23
data['X86']['G_CC_OP_SHLL'] = 24
data['X86']['G_CC_OP_SHRB'] = 25
data['X86']['G_CC_OP_SHRW'] = 26
data['X86']['G_CC_OP_SHRL'] = 27
data['X86']['G_CC_OP_ROLB'] = 28
data['X86']['G_CC_OP_ROLW'] = 29
data['X86']['G_CC_OP_ROLL'] = 30
data['X86']['G_CC_OP_RORB'] = 31
data['X86']['G_CC_OP_RORW'] = 32
data['X86']['G_CC_OP_RORL'] = 33
data['X86']['G_CC_OP_UMULB'] = 34
data['X86']['G_CC_OP_UMULW'] = 35
data['X86']['G_CC_OP_UMULL'] = 36
data['X86']['G_CC_OP_SMULB'] = 37
data['X86']['G_CC_OP_SMULW'] = 38
data['X86']['G_CC_OP_SMULL'] = 39
data['X86']['G_CC_OP_NUMBER'] = 40

data['X86']['G_CC_OP_SMULQ'] = None
data['X86']['G_CC_OP_UMULQ'] = None
data['X86']['G_CC_OP_RORQ'] = None
data['X86']['G_CC_OP_ROLQ'] = None
data['X86']['G_CC_OP_SHRQ'] = None
data['X86']['G_CC_OP_SHLQ'] = None
data['X86']['G_CC_OP_DECQ'] = None
data['X86']['G_CC_OP_INCQ'] = None
data['X86']['G_CC_OP_LOGICQ'] = None
data['X86']['G_CC_OP_SBBQ'] = None
data['X86']['G_CC_OP_ADCQ'] = None
data['X86']['G_CC_OP_SUBQ'] = None
data['X86']['G_CC_OP_ADDQ'] = None

#
# AMD64 internal helpers
#
def pc_preamble(nbits, platform=None):
	data_mask = symexec.BitVecVal(2 ** nbits - 1, nbits)
	sign_mask = 1 << (nbits - 1)
	return data_mask, sign_mask

def pc_make_rdata(nbits, cf, pf, af, zf, sf, of, platform=None):
	return 	symexec.ZeroExt(nbits - 1, cf) << data[platform]['G_CC_SHIFT_C'] | \
		    symexec.ZeroExt(nbits - 1, pf) << data[platform]['G_CC_SHIFT_P'] | \
		    symexec.ZeroExt(nbits - 1, af) << data[platform]['G_CC_SHIFT_A'] | \
		    symexec.ZeroExt(nbits - 1, zf) << data[platform]['G_CC_SHIFT_Z'] | \
		    symexec.ZeroExt(nbits - 1, sf) << data[platform]['G_CC_SHIFT_S'] | \
		    symexec.ZeroExt(nbits - 1, of) << data[platform]['G_CC_SHIFT_O']

def pc_actions_ADD(state, nbits, arg_l, arg_r, cc_ndep, platform=None):
	data_mask, sign_mask = pc_preamble(nbits, platform=platform)
	res = arg_l + arg_r

	cf = sim_ite_autoadd(state, symexec.ULT(res, arg_l), symexec.BitVecVal(1, 1), symexec.BitVecVal(0, 1))
	pf = calc_paritybit(symexec.Extract(7, 0, res))
	af = symexec.Extract(data[platform]['G_CC_SHIFT_A'], data[platform]['G_CC_SHIFT_A'], (res ^ arg_l ^ arg_r))
	zf = calc_zerobit(state, res)
	sf = symexec.Extract(nbits - 1, nbits - 1, res)
	of = symexec.Extract(nbits - 1, nbits - 1, (arg_l ^ arg_r ^ data_mask) & (arg_l ^ res))

	return pc_make_rdata(data[platform]['size'], cf, pf, af, zf, sf, of, platform=platform)

def pc_actions_SUB(state, nbits, arg_l, arg_r, cc_ndep, platform=None):
	data_mask, sign_mask = pc_preamble(nbits, platform=platform)
	res = arg_l - arg_r

	cf = sim_ite_autoadd(state, symexec.ULT(arg_l, arg_r), symexec.BitVecVal(1, 1), symexec.BitVecVal(0, 1))
	pf = calc_paritybit(symexec.Extract(7, 0, res))
	af = symexec.Extract(data[platform]['G_CC_SHIFT_A'], data[platform]['G_CC_SHIFT_A'], (res ^ arg_l ^ arg_r))
	zf = calc_zerobit(state, res)
	sf = symexec.Extract(nbits - 1, nbits - 1, res)
	of = symexec.Extract(nbits - 1, nbits - 1, (arg_l ^ arg_r) & (arg_l ^ res))

	return pc_make_rdata(data[platform]['size'], cf, pf, af, zf, sf, of, platform=platform)

def pc_actions_LOGIC(state, nbits, arg_l, arg_r, cc_ndep, platform=None):
	data_mask, sign_mask = pc_preamble(nbits, platform=platform)

	cf = symexec.BitVecVal(0, 1)
	pf = calc_paritybit(symexec.Extract(7, 0, arg_l))
	af = symexec.BitVecVal(0, 1)
	zf = calc_zerobit(state, arg_l)
	sf = symexec.Extract(nbits - 1, nbits - 1, arg_l)
	of = symexec.BitVecVal(0, 1)

	return pc_make_rdata(data[platform]['size'], cf, pf, af, zf, sf, of, platform=platform)

def pc_actions_DEC(state, nbits, res, _, cc_ndep, platform=None):
	data_mask, sign_mask = pc_preamble(nbits, platform=platform)
	arg_l = res + 1
	arg_r = 1

	cf = symexec.Extract(data[platform]['G_CC_SHIFT_C'], data[platform]['G_CC_SHIFT_C'], cc_ndep & data[platform]['G_CC_MASK_C'])
	pf = calc_paritybit(symexec.Extract(7, 0, res))
	af = symexec.Extract(data[platform]['G_CC_SHIFT_A'], data[platform]['G_CC_SHIFT_A'], (res ^ arg_l ^ 1))
	zf = calc_zerobit(state, res)
	sf = symexec.Extract(nbits - 1, nbits - 1, res)
	of = sim_ite_autoadd(state, sf == symexec.Extract(nbits - 1, nbits - 1, arg_l), symexec.BitVecVal(0, 1), symexec.BitVecVal(1, 1))
	return pc_make_rdata(data[platform]['size'], cf, pf, af, zf, sf, of, platform=platform)

def pc_actions_ADC(*args, **kwargs):
	raise Exception("Unsupported flag action. Please implement or bug Yan.")
def pc_actions_SBB(*args, **kwargs):
	raise Exception("Unsupported flag action. Please implement or bug Yan.")

def pc_actions_INC(state, nbits, res, _, cc_ndep, platform=None):
	data_mask, sign_mask = pc_preamble(nbits, platform=platform)
	arg_l = res - 1
	arg_r = 1

	cf = symexec.Extract(data[platform]['G_CC_SHIFT_C'], data[platform]['G_CC_SHIFT_C'], cc_ndep & data[platform]['G_CC_MASK_C'])
	pf = calc_paritybit(symexec.Extract(7, 0, res))
	af = symexec.Extract(data[platform]['G_CC_SHIFT_A'], data[platform]['G_CC_SHIFT_A'], (res ^ arg_l ^ 1))
	zf = calc_zerobit(state, res)
	sf = symexec.Extract(nbits - 1, nbits - 1, res)
	of = sim_ite_autoadd(state, sf == symexec.Extract(nbits - 1, nbits - 1, arg_l), symexec.BitVecVal(0, 1), symexec.BitVecVal(1, 1))
	return pc_make_rdata(data[platform]['size'], cf, pf, af, zf, sf, of, platform=platform)

def pc_actions_SHL(*args, **kwargs):
	raise Exception("Unsupported flag action. Please implement or bug Yan.")
def pc_actions_SHR(*args, **kwargs):
	raise Exception("Unsupported flag action. Please implement or bug Yan.")
def pc_actions_ROL(*args, **kwargs):
	raise Exception("Unsupported flag action. Please implement or bug Yan.")
def pc_actions_ROR(*args, **kwargs):
	raise Exception("Unsupported flag action. Please implement or bug Yan.")
def pc_actions_UMUL(*args, **kwargs):
	raise Exception("Unsupported flag action. Please implement or bug Yan.")
def pc_actions_UMULQ(*args, **kwargs):
	raise Exception("Unsupported flag action. Please implement or bug Yan.")
def pc_actions_SMUL(*args, **kwargs):
	raise Exception("Unsupported flag action. Please implement or bug Yan.")
def pc_actions_SMULQ(*args, **kwargs):
	raise Exception("Unsupported flag action. Please implement or bug Yan.")



def pc_calculate_rdata_all_WRK(state, cc_op, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=None):
	# sanity check
	if type(cc_op) not in [int, long]:
		raise Exception("Non-concrete cc_op received.")

	cc_op = int(cc_op)
	if cc_op == data[platform]['G_CC_OP_COPY']:
		l.debug("cc_op == data[platform]['G_CC_OP_COPY']")
		return cc_dep1_formal & (data[platform]['G_CC_MASK_O'] | data[platform]['G_CC_MASK_S'] | data[platform]['G_CC_MASK_Z']
			   | data[platform]['G_CC_MASK_A'] | data[platform]['G_CC_MASK_C'] | data[platform]['G_CC_MASK_P'])

	if platform == "AMD64":
		nbits = 2 ** (((cc_op - 1) % 4) + 3)
	elif platform == "X86":
		nbits = 2 ** ((cc_op - 1) % 4 + 2)

	l.debug("nbits == %d", nbits)

	cc_dep1_formal = symexec.Extract(nbits-1, 0, cc_dep1_formal)
	cc_dep2_formal = symexec.Extract(nbits-1, 0, cc_dep2_formal)
	# TODO: does ndep need to be extracted as well?

	if cc_op in [ data[platform]['G_CC_OP_ADDB'], data[platform]['G_CC_OP_ADDW'], data[platform]['G_CC_OP_ADDL'], data[platform]['G_CC_OP_ADDQ'] ]:
		l.debug("cc_op: ADD")
		return pc_actions_ADD(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

	if cc_op in [ data[platform]['G_CC_OP_ADCB'], data[platform]['G_CC_OP_ADCW'], data[platform]['G_CC_OP_ADCL'], data[platform]['G_CC_OP_ADCQ'] ]:
		l.debug("cc_op: ADC")
		return pc_actions_ADC(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

	if cc_op in [ data[platform]['G_CC_OP_SUBB'], data[platform]['G_CC_OP_SUBW'], data[platform]['G_CC_OP_SUBL'], data[platform]['G_CC_OP_SUBQ'] ]:
		l.debug("cc_op: SUB")
		return pc_actions_SUB(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

	if cc_op in [ data[platform]['G_CC_OP_SBBB'], data[platform]['G_CC_OP_SBBW'], data[platform]['G_CC_OP_SBBL'], data[platform]['G_CC_OP_SBBQ'] ]:
		l.debug("cc_op: SBB")
		return pc_actions_SBB(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

	if cc_op in [ data[platform]['G_CC_OP_LOGICB'], data[platform]['G_CC_OP_LOGICW'], data[platform]['G_CC_OP_LOGICL'], data[platform]['G_CC_OP_LOGICQ'] ]:
		l.debug("cc_op: LOGIC")
		return pc_actions_LOGIC(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

	if cc_op in [ data[platform]['G_CC_OP_INCB'], data[platform]['G_CC_OP_INCW'], data[platform]['G_CC_OP_INCL'], data[platform]['G_CC_OP_INCQ'] ]:
		l.debug("cc_op: INC")
		return pc_actions_INC(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

	if cc_op in [ data[platform]['G_CC_OP_DECB'], data[platform]['G_CC_OP_DECW'], data[platform]['G_CC_OP_DECL'], data[platform]['G_CC_OP_DECQ'] ]:
		l.debug("cc_op: DEC")
		return pc_actions_DEC(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

	if cc_op in [ data[platform]['G_CC_OP_SHLB'], data[platform]['G_CC_OP_SHLW'], data[platform]['G_CC_OP_SHLL'], data[platform]['G_CC_OP_SHLQ'] ]:
		l.debug("cc_op: SHL")
		return pc_actions_SHL(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

	if cc_op in [ data[platform]['G_CC_OP_SHRB'], data[platform]['G_CC_OP_SHRW'], data[platform]['G_CC_OP_SHRL'], data[platform]['G_CC_OP_SHRQ'] ]:
		l.debug("cc_op: SHR")
		return pc_actions_SHR(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

	if cc_op in [ data[platform]['G_CC_OP_ROLB'], data[platform]['G_CC_OP_ROLW'], data[platform]['G_CC_OP_ROLL'], data[platform]['G_CC_OP_ROLQ'] ]:
		l.debug("cc_op: ROL")
		return pc_actions_ROL(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

	if cc_op in [ data[platform]['G_CC_OP_RORB'], data[platform]['G_CC_OP_RORW'], data[platform]['G_CC_OP_RORL'], data[platform]['G_CC_OP_RORQ'] ]:
		l.debug("cc_op: ROR")
		return pc_actions_ROR(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

	if cc_op in [ data[platform]['G_CC_OP_UMULB'], data[platform]['G_CC_OP_UMULW'], data[platform]['G_CC_OP_UMULL'], data[platform]['G_CC_OP_UMULQ'] ]:
		l.debug("cc_op: UMUL")
		return pc_actions_UMUL(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)
	if cc_op == data[platform]['G_CC_OP_UMULQ']:
		l.debug("cc_op: UMULQ")
		return pc_actions_UMULQ(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)
	if cc_op in [ data[platform]['G_CC_OP_SMULB'], data[platform]['G_CC_OP_SMULW'], data[platform]['G_CC_OP_SMULL'], data[platform]['G_CC_OP_SMULQ'] ]:
		l.debug("cc_op: SMUL")
		return pc_actions_SMUL(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)
	if cc_op == data[platform]['G_CC_OP_SMULQ']:
		l.debug("cc_op: SMULQ")
		return pc_actions_SMULQ(state, nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal, platform=platform)

	raise Exception("Unsupported cc_op in pc_calculate_rdata_all_WRK")

# This function returns all the data
def pc_calculate_rdata_all(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform=None):
	cc_op = flag_concretize(state, cc_op)
	return pc_calculate_rdata_all_WRK(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform=platform), [ ]

# This function takes a condition that is being checked (ie, zero bit), and basically
# returns that bit
def pc_calculate_condition(state, cond, cc_op, cc_dep1, cc_dep2, cc_ndep, platform=None):
	cc_op = flag_concretize(state, cc_op)
	rdata = pc_calculate_rdata_all_WRK(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform=platform)
	v = cond.as_long()
	inv = v & 1
	l.debug("inv: %d", inv)
	l.debug("cond value: 0x%x", v)

	if v in [ data[platform]['CondO'], data[platform]['CondNO'] ]:
		l.debug("CondO")
		of = symexec.LShR(rdata, data[platform]['G_CC_SHIFT_O'])
		return 1 & (inv ^ of), [ ]

	if v in [ data[platform]['CondZ'], data[platform]['CondNZ'] ]:
		l.debug("CondZ")
		zf = symexec.LShR(rdata, data[platform]['G_CC_SHIFT_Z'])
		return 1 & (inv ^ zf), [ ]

	if v in [ data[platform]['CondB'], data[platform]['CondNB'] ]:
		l.debug("CondB")
		cf = symexec.LShR(rdata, data[platform]['G_CC_SHIFT_C'])
		return 1 & (inv ^ cf), [ ]

	if v in [ data[platform]['CondBE'], data[platform]['CondNBE'] ]:
		l.debug("CondBE")
		cf = symexec.LShR(rdata, data[platform]['G_CC_SHIFT_C'])
		zf = symexec.LShR(rdata, data[platform]['G_CC_SHIFT_Z'])
		return 1 & (inv ^ (cf | zf)), [ ]

	if v in [ data[platform]['CondS'], data[platform]['CondNS'] ]:
		l.debug("CondS")
		sf = symexec.LShR(rdata, data[platform]['G_CC_SHIFT_S'])
		return 1 & (inv ^ sf), [ ]

	if v in [ data[platform]['CondP'], data[platform]['CondNP'] ]:
		l.debug("CondP")
		pf = symexec.LShR(rdata, data[platform]['G_CC_SHIFT_P'])
		return 1 & (inv ^ pf), [ ]

	if v in [ data[platform]['CondL'], data[platform]['CondNL'] ]:
		l.debug("CondL")
		sf = symexec.LShR(rdata, data[platform]['G_CC_SHIFT_S'])
		of = symexec.LShR(rdata, data[platform]['G_CC_SHIFT_O'])
		return 1 & (inv ^ (sf ^ of)), [ ]

	if v in [ data[platform]['CondLE'], data[platform]['CondNLE'] ]:
		l.debug("CondLE")
		sf = symexec.LShR(rdata, data[platform]['G_CC_SHIFT_S'])
		of = symexec.LShR(rdata, data[platform]['G_CC_SHIFT_O'])
		zf = symexec.LShR(rdata, data[platform]['G_CC_SHIFT_Z'])
		return 1 & (inv ^ ((sf ^ of) | zf)), [ ]

	raise Exception("Unrecognized condition in pc_calculate_condition")

def pc_calculate_rdata_c(state, cc_op, cc_dep1, cc_dep2, cc_ndep, platform=None):
	cc_op = flag_concretize(state, cc_op)

	if cc_op == data[platform]['G_CC_OP_COPY']:
		return symexec.LShR(cc_dep1, data[platform]['G_CC_SHIFT_C']) & 1, [ ] # TODO: actual constraints
	elif cc_op in ( data[platform]['G_CC_OP_LOGICQ'], data[platform]['G_CC_OP_LOGICL'], data[platform]['G_CC_OP_LOGICW'], data[platform]['G_CC_OP_LOGICB'] ):
		return symexec.BitVecVal(0, 64), [ ] # TODO: actual constraints

	return symexec.LShR(pc_calculate_rdata_all_WRK(state, cc_op,cc_dep1,cc_dep2,cc_ndep, platform=platform), data[platform]['G_CC_SHIFT_C']) & 1, [ ]

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
		flag = symexec.LShR(cc_dep1, ARMG_CC_SHIFT_N) & 1
	elif concrete_op == ARMG_CC_OP_ADD:
		res = cc_dep1 + cc_dep2
		flag = symexec.LShR(res, 31)
	elif concrete_op == ARMG_CC_OP_SUB:
		res = cc_dep1 - cc_dep2
		flag = symexec.LShR(res, 31)
	elif concrete_op == ARMG_CC_OP_ADC:
		res = cc_dep1 + cc_dep2 + cc_dep3
		flag = symexec.LShR(res, 31)
	elif concrete_op == ARMG_CC_OP_SBB:
		res = cc_dep1 - cc_dep2 - (cc_dep3^1)
		flag = symexec.LShR(res, 31)
	elif concrete_op == ARMG_CC_OP_LOGIC:
		flag = symexec.LShR(cc_dep1, 31)
	elif concrete_op == ARMG_CC_OP_MUL:
		flag = symexec.LShR(cc_dep1, 31)
	elif concrete_op == ARMG_CC_OP_MULL:
		flag = symexec.LShR(cc_dep2, 31)

	if flag is not None: return flag, [ cc_op == concrete_op ]
	raise Exception("Unknown cc_op %s" % cc_op)

def arm_zerobit(state, x):
	return symexec.ZeroExt(31, calc_zerobit(state, x))

def armg_calculate_flag_z(state, cc_op, cc_dep1, cc_dep2, cc_dep3):
	concrete_op = flag_concretize(state, cc_op)
	flag = None

	if concrete_op == ARMG_CC_OP_COPY:
		flag = symexec.LShR(cc_dep1, ARMG_CC_SHIFT_Z) & 1
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
	raise Exception("Unknown cc_op %s" % concrete_op)

def armg_calculate_flag_c(state, cc_op, cc_dep1, cc_dep2, cc_dep3):
	concrete_op = flag_concretize(state, cc_op)
	flag = None

	if concrete_op == ARMG_CC_OP_COPY:
		flag = symexec.LShR(cc_dep1, ARMG_CC_SHIFT_C) & 1
	elif concrete_op == ARMG_CC_OP_ADD:
		res = cc_dep1 + cc_dep2
		flag = boolean_extend(state, symexec.ULT, res, cc_dep1, 32)
	elif concrete_op == ARMG_CC_OP_SUB:
		flag = boolean_extend(state, symexec.UGE, cc_dep1, cc_dep2, 32)
	elif concrete_op == ARMG_CC_OP_ADC:
		res = cc_dep1 + cc_dep2 + cc_dep3
		flag = sim_ite_autoadd(state, cc_dep2 != 0, boolean_extend(state, symexec.ULE, res, cc_dep1, 32), boolean_extend(state, symexec.ULT, res, cc_dep1, 32))
	elif concrete_op == ARMG_CC_OP_SBB:
		flag = sim_ite_autoadd(state, cc_dep2 != 0, boolean_extend(state, symexec.UGE, cc_dep1, cc_dep2, 32), boolean_extend(state, symexec.UGT, cc_dep1, cc_dep2, 32))
	elif concrete_op == ARMG_CC_OP_LOGIC:
		flag = cc_dep2
	elif concrete_op == ARMG_CC_OP_MUL:
		flag = (symexec.LShR(cc_dep3, 1)) & 1
	elif concrete_op == ARMG_CC_OP_MULL:
		flag = (symexec.LShR(cc_dep3, 1)) & 1

	if flag is not None: return flag, [ cc_op == concrete_op ]
	raise Exception("Unknown cc_op %s" % cc_op)

def armg_calculate_flag_v(state, cc_op, cc_dep1, cc_dep2, cc_dep3):
	concrete_op = flag_concretize(state, cc_op)
	flag = None

	if concrete_op == ARMG_CC_OP_COPY:
		flag = symexec.LShR(cc_dep1, ARMG_CC_SHIFT_V) & 1
	elif concrete_op == ARMG_CC_OP_ADD:
		res = cc_dep1 + cc_dep2
		v = ((res ^ cc_dep1) & (res ^ cc_dep2))
		flag = symexec.LShR(v, 31)
	elif concrete_op == ARMG_CC_OP_SUB:
		res = cc_dep1 - cc_dep2
		v = ((cc_dep1 ^ cc_dep2) & (cc_dep1 ^ res))
		flag = symexec.LShR(v, 31)
	elif concrete_op == ARMG_CC_OP_ADC:
		res = cc_dep1 + cc_dep2 + cc_dep3
		v = ((res ^ cc_dep1) & (res ^ cc_dep2))
		flag = symexec.LShR(v, 31)
	elif concrete_op == ARMG_CC_OP_SBB:
		res = cc_dep1 - cc_dep2 - (cc_dep3^1)
		v = ((cc_dep1 ^ cc_dep2) & (cc_dep1 ^ res))
		flag = symexec.LShR(v, 31)
	elif concrete_op == ARMG_CC_OP_LOGIC:
		flag = cc_dep3
	elif concrete_op == ARMG_CC_OP_MUL:
		flag = cc_dep3 & 1
	elif concrete_op == ARMG_CC_OP_MULL:
		flag = cc_dep3 & 1

	if flag is not None: return flag, [ cc_op == concrete_op ]
	raise Exception("Unknown cc_op %s" % cc_op)

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
	cond = symexec.LShR(cond_n_op, 4)
	cc_op = cond_n_op & 0xF
	inv = cond & 1

	concrete_cond = flag_concretize(state, cond)
	flag = None
	c1,c2,c3 = [ ], [ ], [ ]

	# NOTE: adding constraints afterwards works here *only* because the constraints are actually useless, because we require
	# cc_op to be unique. If we didn't, we'd need to pass the constraints into any functions called after the constraints were
	# created.

	if concrete_cond == ARMCondAL:
		flag = symexec.BitVecVal(1, 32)
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
	raise Exception("Unrecognized condition %d in armg_calculate_condition" % concrete_cond)

from .s_helpers import sim_ite_autoadd
