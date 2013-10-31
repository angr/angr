#!/usr/bin/env python

import z3

import logging
l = logging.getLogger("s_ccall")
#l.setLevel(logging.DEBUG)

###############
### Helpers ###
###############

# There might be a better way of doing this
def calc_paritybit(p):
	b = z3.BitVecVal(1, 1)
	for i in xrange(p.size()):
		b = b ^ z3.Extract(i, i, p)
	return b

# There might be a better way of doing this
def calc_zerobit(p):
	b = z3.BitVecVal(0, 1)
	for i in xrange(p.size()):
		b = b | z3.Extract(i, i, p)
	return b ^ z3.BitVecVal(1, 1)

def boolean_extend(O, a, b, size):
	return z3.If(O(a, b), z3.BitVecVal(1, size), z3.BitVecVal(0, size))

# There might be a faster way of doing this
#def calc_overflow(a, b):
#	ax = z3.ZeroExt(1, a)
#	cx = z3.ZeroExt(1, b)
#	return z3.Extend(

###################
### AMD64 flags ###
###################

# condition types
AMD64CondO      = 0  # /* overflow           */
AMD64CondNO     = 1  # /* no overflow        */
AMD64CondB      = 2  # /* below              */
AMD64CondNB     = 3  # /* not below          */
AMD64CondZ      = 4  # /* zero               */
AMD64CondNZ     = 5  # /* not zero           */
AMD64CondBE     = 6  # /* below or equal     */
AMD64CondNBE    = 7  # /* not below or equal */
AMD64CondS      = 8  # /* negative           */
AMD64CondNS     = 9  # /* not negative       */
AMD64CondP      = 10 # /* parity even        */
AMD64CondNP     = 11 # /* not parity even    */
AMD64CondL      = 12 # /* jump less          */
AMD64CondNL     = 13 # /* not less           */
AMD64CondLE     = 14 # /* less or equal      */
AMD64CondNLE    = 15 # /* not less or equal  */

# condition bit offsets
AMD64G_CC_SHIFT_O = 11
AMD64G_CC_SHIFT_S = 7
AMD64G_CC_SHIFT_Z = 6
AMD64G_CC_SHIFT_A = 4
AMD64G_CC_SHIFT_C = 0
AMD64G_CC_SHIFT_P = 2

# masks
AMD64G_CC_MASK_O = (1 << AMD64G_CC_SHIFT_O)
AMD64G_CC_MASK_S = (1 << AMD64G_CC_SHIFT_S)
AMD64G_CC_MASK_Z = (1 << AMD64G_CC_SHIFT_Z)
AMD64G_CC_MASK_A = (1 << AMD64G_CC_SHIFT_A)
AMD64G_CC_MASK_C = (1 << AMD64G_CC_SHIFT_C)
AMD64G_CC_MASK_P = (1 << AMD64G_CC_SHIFT_P)

# operation types
AMD64G_CC_OP_COPY = 0
AMD64G_CC_OP_ADDB = 1
AMD64G_CC_OP_ADDW = 2
AMD64G_CC_OP_ADDL = 3
AMD64G_CC_OP_ADDQ = 4
AMD64G_CC_OP_SUBB = 5
AMD64G_CC_OP_SUBW = 6
AMD64G_CC_OP_SUBL = 7
AMD64G_CC_OP_SUBQ = 8
AMD64G_CC_OP_ADCB = 9
AMD64G_CC_OP_ADCW = 10
AMD64G_CC_OP_ADCL = 11
AMD64G_CC_OP_ADCQ = 12
AMD64G_CC_OP_SBBB = 13
AMD64G_CC_OP_SBBW = 14
AMD64G_CC_OP_SBBL = 15
AMD64G_CC_OP_SBBQ = 16
AMD64G_CC_OP_LOGICB = 17
AMD64G_CC_OP_LOGICW = 18
AMD64G_CC_OP_LOGICL = 19
AMD64G_CC_OP_LOGICQ = 20
AMD64G_CC_OP_INCB = 21
AMD64G_CC_OP_INCW = 22
AMD64G_CC_OP_INCL = 23
AMD64G_CC_OP_INCQ = 24
AMD64G_CC_OP_DECB = 25
AMD64G_CC_OP_DECW = 26
AMD64G_CC_OP_DECL = 27
AMD64G_CC_OP_DECQ = 28
AMD64G_CC_OP_SHLB = 29
AMD64G_CC_OP_SHLW = 30
AMD64G_CC_OP_SHLL = 31
AMD64G_CC_OP_SHLQ = 32
AMD64G_CC_OP_SHRB = 33
AMD64G_CC_OP_SHRW = 34
AMD64G_CC_OP_SHRL = 35
AMD64G_CC_OP_SHRQ = 36
AMD64G_CC_OP_ROLB = 37
AMD64G_CC_OP_ROLW = 38
AMD64G_CC_OP_ROLL = 39
AMD64G_CC_OP_ROLQ = 40
AMD64G_CC_OP_RORB = 41
AMD64G_CC_OP_RORW = 42
AMD64G_CC_OP_RORL = 43
AMD64G_CC_OP_RORQ = 44
AMD64G_CC_OP_UMULB = 45
AMD64G_CC_OP_UMULW = 46
AMD64G_CC_OP_UMULL = 47
AMD64G_CC_OP_UMULQ = 48
AMD64G_CC_OP_SMULB = 49
AMD64G_CC_OP_SMULW = 50
AMD64G_CC_OP_SMULL = 51
AMD64G_CC_OP_SMULQ = 52
AMD64G_CC_OP_NUMBER = 53

def amd64g_preamble(nbits):
	data_mask = z3.BitVecVal(2 ** nbits - 1, nbits)
	sign_mask = 1 << (nbits - 1)
	return data_mask, sign_mask

def amd64_make_rflags(nbits, cf, pf, af, zf, sf, of):
	return 	z3.ZeroExt(nbits - 1, cf) << AMD64G_CC_SHIFT_C | \
		z3.ZeroExt(nbits - 1, pf) << AMD64G_CC_SHIFT_P | \
		z3.ZeroExt(nbits - 1, af) << AMD64G_CC_SHIFT_A | \
		z3.ZeroExt(nbits - 1, zf) << AMD64G_CC_SHIFT_Z | \
		z3.ZeroExt(nbits - 1, sf) << AMD64G_CC_SHIFT_S | \
		z3.ZeroExt(nbits - 1, of) << AMD64G_CC_SHIFT_O

def amd64_actions_ADD(nbits, arg_l, arg_r, cc_ndep):
	data_mask, sign_mask = amd64g_preamble(nbits)
	res = z3.ZeroExt(1, arg_l) + z3.ZeroExt(1, arg_r)
	cf = z3.Extract(nbits-1, nbits-1, res)

	res = z3.Extract(nbits - 1, 0, res)
	pf = calc_paritybit(z3.Extract(7, 0, res))
	af = z3.Extract(4, 4, (res ^ arg_l ^ arg_r))
	zf = calc_zerobit(res)
	sf = z3.Extract(nbits-1, nbits-1, res)
	of = z3.Extract(nbits-1, nbits-1, (arg_l ^ arg_r ^ data_mask) & (arg_l ^ res))
	return amd64_make_rflags(64, cf, pf, af, zf, sf, of)

def amd64_actions_SUB(nbits, arg_l, arg_r, cc_ndep):
	data_mask, sign_mask = amd64g_preamble(nbits)
	res = z3.ZeroExt(1, arg_l) - z3.ZeroExt(1, arg_r)
	cf = z3.Extract(nbits - 1, nbits - 1, res)

	res = z3.Extract(nbits - 1, 0, res)
	pf = calc_paritybit(z3.Extract(7, 0, res))
	af = z3.Extract(4, 4, (res ^ arg_l ^ arg_r))
	zf = calc_zerobit(res)
	sf = z3.Extract(nbits - 1, nbits - 1, res)
	of = z3.Extract(nbits - 1, nbits - 1, (arg_l ^ arg_r ^ data_mask) & (arg_l ^ res))
	return amd64_make_rflags(64, cf, pf, af, zf, sf, of)

def amd64g_calculate_rflags_all_WRK(cc_op, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal):
	if cc_op == AMD64G_CC_OP_COPY:
		l.debug("cc_op == AMD64G_CC_OP_COPY")
		return cc_dep1_formal & (AMD64G_CC_MASK_O | AMD64G_CC_MASK_S | AMD64G_CC_MASK_Z
			   | AMD64G_CC_MASK_A | AMD64G_CC_MASK_C | AMD64G_CC_MASK_P)

	nbits = 2 ** ((cc_op % 4) + 3)
	l.debug("nbits == %d" % nbits)

	if cc_op in [ AMD64G_CC_OP_ADDB, AMD64G_CC_OP_ADDW, AMD64G_CC_OP_ADDL, AMD64G_CC_OP_ADDQ ]:
		l.debug("cc_op: ADD")
		return amd64_actions_ADD(nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal)

	if cc_op in [ AMD64G_CC_OP_ADCB, AMD64G_CC_OP_ADCW, AMD64G_CC_OP_ADCL, AMD64G_CC_OP_ADCQ ]:
		l.debug("cc_op: ADC")
		return amd64_actions_ADC(nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal)

	if cc_op in [ AMD64G_CC_OP_SUBB, AMD64G_CC_OP_SUBW, AMD64G_CC_OP_SUBL, AMD64G_CC_OP_SUBQ ]:
		l.debug("cc_op: SUB")
		return amd64_actions_SUB(nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal)

	if cc_op in [ AMD64G_CC_OP_SBBB, AMD64G_CC_OP_SBBW, AMD64G_CC_OP_SBBL, AMD64G_CC_OP_SBBQ ]:
		l.debug("cc_op: SBB")
		return amd64_actions_SBB(nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal)

	if cc_op in [ AMD64G_CC_OP_LOGICB, AMD64G_CC_OP_LOGICW, AMD64G_CC_OP_LOGICL, AMD64G_CC_OP_LOGICQ ]:
		l.debug("cc_op: LOGIC")
		return amd64_actions_LOGIC(nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal)

	if cc_op in [ AMD64G_CC_OP_INCB, AMD64G_CC_OP_INCW, AMD64G_CC_OP_INCL, AMD64G_CC_OP_INCQ ]:
		l.debug("cc_op: INC")
		return amd64_actions_INC(nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal)

	if cc_op in [ AMD64G_CC_OP_DECB, AMD64G_CC_OP_DECW, AMD64G_CC_OP_DECL, AMD64G_CC_OP_DECQ ]:
		l.debug("cc_op: DEC")
		return amd64_actions_DEC(nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal)

	if cc_op in [ AMD64G_CC_OP_SHLB, AMD64G_CC_OP_SHLW, AMD64G_CC_OP_SHLL, AMD64G_CC_OP_SHLQ ]:
		l.debug("cc_op: SHL")
		return amd64_actions_SHL(nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal)

	if cc_op in [ AMD64G_CC_OP_SHRB, AMD64G_CC_OP_SHRW, AMD64G_CC_OP_SHRL, AMD64G_CC_OP_SHRQ ]:
		l.debug("cc_op: SHR")
		return amd64_actions_SHR(nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal)

	if cc_op in [ AMD64G_CC_OP_ROLB, AMD64G_CC_OP_ROLW, AMD64G_CC_OP_ROLL, AMD64G_CC_OP_ROLQ ]:
		l.debug("cc_op: ROL")
		return amd64_actions_ROL(nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal)

	if cc_op in [ AMD64G_CC_OP_RORB, AMD64G_CC_OP_RORW, AMD64G_CC_OP_RORL, AMD64G_CC_OP_RORQ ]:
		l.debug("cc_op: ROR")
		return amd64_actions_ROR(nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal)

	if cc_op in [ AMD64G_CC_OP_UMULB, AMD64G_CC_OP_UMULW, AMD64G_CC_OP_UMULL, AMD64G_CC_OP_UMULQ ]:
		l.debug("cc_op: UMUL")
		return amd64_actions_UMUL(nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal)
	if cc_op == AMD64G_CC_OP_UMULQ:
		l.debug("cc_op: UMULQ")
		return amd64_actions_UMULQ()

	if cc_op in [ AMD64G_CC_OP_SMULB, AMD64G_CC_OP_SMULW, AMD64G_CC_OP_SMULL, AMD64G_CC_OP_SMULQ ]:
		l.debug("cc_op: SMUL")
		return amd64_actions_SMUL(nbits, cc_dep1_formal, cc_dep2_formal, cc_ndep_formal)
	if cc_op == AMD64G_CC_OP_SMULQ:
		l.debug("cc_op: SMULQ")
		return amd64_actions_SMULQ()

	raise Exception("Unsupported cc_op in amd64g_calculate_rflags_all_WRK")

# This function returns all the flags
def amd64g_calculate_rflags_all(cc_op, cc_dep1, cc_dep2, cc_ndep):
	return amd64g_calculate_rflags_all_WRK(cc_op, cc_dep1, cc_dep2, cc_ndep)

# This function takes a condition that is being checked (ie, zero bit), and basically
# returns that bit
def amd64g_calculate_condition(cond, cc_op, cc_dep1, cc_dep2, cc_ndep):
	rflags = amd64g_calculate_rflags_all_WRK(cc_op, cc_dep1, cc_dep2, cc_ndep)
	v = cond.as_long()
	inv = v & 1

	if v == AMD64CondO or v == AMD64CondNO:
		l.debug("AMD64CondO")
		of = z3.LShR(rflags, AMD64G_CC_SHIFT_O)
		return 1 & (inv ^ of)

	if v == AMD64CondZ or v == AMD64CondNZ:
		l.debug("AMD64CondZ")
		zf = z3.LShR(rflags, AMD64G_CC_SHIFT_Z)
		return 1 & (inv ^ zf)

	if v == AMD64CondB or v == AMD64CondNB:
		l.debug("AMD64CondB")
		cf = z3.LShR(rflags, AMD64G_CC_SHIFT_C)
		return 1 & (inv ^ cf)

	if v == AMD64CondBE or v == AMD64CondNBE:
		l.debug("AMD64CondBE")
		cf = z3.LShR(rflags, AMD64G_CC_SHIFT_C)
		zf = z3.LShR(rflags, AMD64G_CC_SHIFT_Z)
		return 1 & (inv ^ (cf | zf))

	if v == AMD64CondS or v == AMD64CondNS:
		l.debug("AMD64CondS")
		sf = z3.LShR(rflags, AMD64G_CC_SHIFT_S)
		return 1 & (inv ^ sf)

	if v == AMD64CondP or v == AMD64CondNP:
		l.debug("AMD64CondP")
		pf = z3.LShR(rflags, AMD64G_CC_SHIFT_P)
		return 1 & (inv ^ pf)

	if v == AMD64CondL or AMD64CondNL:
		l.debug("AMD64CondL")
		sf = z3.LShR(rflags, AMD64G_CC_SHIFT_S)
		of = z3.LShR(rflags, AMD64G_CC_SHIFT_O)
		return 1 & (inv ^ (sf ^ of))

	if v == AMD64CondLE or v == AMD64CondNLE:
		l.debug("AMD64CondLE")
		sf = z3.LShR(rflags, AMD64G_CC_SHIFT_S)
		of = z3.LShR(rflags, AMD64G_CC_SHIFT_O)
		zf = z3.LShR(rflags, AMD64G_CC_SHIFT_Z)
		return 1 & (inv ^ ((sf ^ of) | zf))

	raise Exception("Unrecognized condition in amd64g_calculate_condition")

def amd64g_calculate_rflags_c(cc_op, cc_dep1, cc_dep2, cc_ndep):
	if cc_op == AMD64G_CC_OP_COPY:
		z3.LShR(cc_dep1, AMD64G_CC_SHIFT_C) & 1
	elif cc_op == AMD64G_CC_OP_LOGICQ or AMD64G_CC_OP_LOGICL or AMD64G_CC_OP_LOGICW or AMD64G_CC_OP_LOGICB:
		return z3.BitVecVal(0, 1)

	return z3.LShR(amd64g_calculate_rflags_all_WRK(cc_op,cc_dep1,cc_dep2,cc_ndep), AMD64G_CC_SHIFT_C) & 1

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

def armg_calculate_flag_n(cc_op, cc_dep1, cc_dep2, cc_dep3):
	if cc_op == ARMG_CC_OP_COPY:
		return z3.LShR(cc_dep1, ARMG_CC_SHIFT_N) & 1
	elif cc_op == ARMG_CC_OP_ADD:
		res = cc_dep1 + cc_dep2
		return z3.LShR(res, 31)
	elif cc_op == ARMG_CC_OP_SUB:
		res = cc_dep1 - cc_dep2
		return z3.LShR(res, 31)
	elif cc_op == ARMG_CC_OP_ADC:
		res = cc_dep1 + cc_dep2 + cc_dep3
		return z3.LShR(res, 31)
	elif cc_op == ARMG_CC_OP_SBB:
		res = cc_dep1 - cc_dep2 - (cc_dep3^1)
		return z3.LShR(res, 31)
	elif cc_op == ARMG_CC_OP_LOGIC:
		return z3.LShR(cc_dep1, 31)
	elif cc_op == ARMG_CC_OP_MUL:
		return z3.LShR(cc_dep1, 31)
	elif cc_op == ARMG_CC_OP_MULL:
		return z3.LShR(cc_dep2, 31)

	raise Exception("Unknown cc_op %s" % cc_op)

def amd_zerobit(x):
	z3.ZeroExt(31, calc_zerobit(x))

def armg_calculate_flag_z(cc_op, cc_dep1, cc_dep2, cc_dep3):
	if cc_op == ARMG_CC_OP_COPY:
		return z3.LShR(cc_dep1, ARMG_CC_SHIFT_Z) & 1
	elif cc_op == ARMG_CC_OP_ADD:
		res = cc_dep1 + cc_dep2
		return amd_zerobit(z3.LShR(res, 31))
	elif cc_op == ARMG_CC_OP_SUB:
		res = cc_dep1 - cc_dep2
		return amd_zerobit(z3.LShR(res, 31))
	elif cc_op == ARMG_CC_OP_ADC:
		res = cc_dep1 + cc_dep2 + cc_dep3
		return amd_zerobit(z3.LShR(res, 31))
	elif cc_op == ARMG_CC_OP_SBB:
		res = cc_dep1 - cc_dep2 - (cc_dep3^1)
		return amd_zerobit(z3.LShR(res, 31))
	elif cc_op == ARMG_CC_OP_LOGIC:
		return amd_zerobit(z3.LShR(cc_dep1, 31))
	elif cc_op == ARMG_CC_OP_MUL:
		return amd_zerobit(z3.LShR(cc_dep1, 31))
	elif cc_op == ARMG_CC_OP_MULL:
		return amd_zerobit(z3.LShR(cc_dep1 | cc_dep2, 31))

	raise Exception("Unknown cc_op %s" % cc_op)

def armg_calculate_flag_c(cc_op, cc_dep1, cc_dep2, cc_dep3):
	if cc_op == ARMG_CC_OP_COPY:
		return z3.LShR(cc_dep1, ARMG_CC_SHIFT_C) & 1
	elif cc_op == ARMG_CC_OP_ADD:
		res = cc_dep1 + cc_dep2
		return boolean_extend(z3.LT, res, cc_dep1, 32)
	elif cc_op == ARMG_CC_OP_SUB:
		return boolean_extend(z3.GTE, cc_dep1, cc_dep2, 32)
	elif cc_op == ARMG_CC_OP_ADC:
		res = cc_dep1 + cc_dep2 + cc_dep3
		return z3.If(cc_dep2 != 0, boolean_extend(z3.LTE, res, cc_dep1, 32), boolean_extend(z3.LT, res, cc_dep1, 32))
	elif cc_op == ARMG_CC_OP_SBB:
		return z3.If(cc_dep2 != 0, boolean_extend(z3.GTE, cc_dep1, cc_dep2, 32), boolean_extend(z3.GT, cc_dep1, cc_dep2, 32))
	elif cc_op == ARMG_CC_OP_LOGIC:
		return cc_dep2
	elif cc_op == ARMG_CC_OP_MUL:
		return (cc_dep3 >> 1) & 1
	elif cc_op == ARMG_CC_OP_MULL:
		return (cc_dep3 >> 1) & 1

	raise Exception("Unknown cc_op %s" % cc_op)

def armg_calculate_flag_v(cc_op, cc_dep1, cc_dep2, cc_dep3):
	if cc_op == ARMG_CC_OP_COPY:
		return z3.LShR(cc_dep1, ARMG_CC_SHIFT_V) & 1
	elif cc_op == ARMG_CC_OP_ADD:
		res = cc_dep1 + cc_dep2
		v = ((res ^ cc_dep1) & (res ^ cc_dep2))
		return z3.LShR(v, 31)
	elif cc_op == ARMG_CC_OP_SUB:
		res = cc_dep1 - cc_dep2
		v = ((cc_dep1 ^ cc_dep2) & (cc_dep1 ^ res))
		return z3.LShR(v, 31)
	elif cc_op == ARMG_CC_OP_ADC:
		res = cc_dep1 + cc_dep2 + cc_dep3
		v = ((res ^ cc_dep1) & (res ^ cc_dep2))
		return z3.LShR(v, 31)
	elif cc_op == ARMG_CC_OP_SBB:
		res = cc_dep1 - cc_dep2 - (cc_dep3^1)
		v = ((cc_dep1 ^ cc_dep2) & (cc_dep1 ^ res))
		return z3.LShR(v, 31)
	elif cc_op == ARMG_CC_OP_LOGIC:
		return cc_dep3
	elif cc_op == ARMG_CC_OP_MUL:
		return cc_dep3 & 1
	elif cc_op == ARMG_CC_OP_MULL:
		return cc_dep3 & 1

	raise Exception("Unknown cc_op %s" % cc_op)

def armg_calculate_flags_nzcv(cc_op, cc_dep1, cc_dep2, cc_dep3):
	n = armg_calculate_flag_n(cc_op, cc_dep1, cc_dep2, cc_dep3)
	z = armg_calculate_flag_z(cc_op, cc_dep1, cc_dep2, cc_dep3)
	c = armg_calculate_flag_c(cc_op, cc_dep1, cc_dep2, cc_dep3)
	v = armg_calculate_flag_v(cc_op, cc_dep1, cc_dep2, cc_dep3)
	return (n << ARMG_CC_SHIFT_N) | (z << ARMG_CC_SHIFT_Z) | (c << ARMG_CC_SHIFT_C) | (v << ARMG_CC_SHIFT_V)

def armg_calculate_condition(cond_n_op, cc_dep1, cc_dep2, cc_dep3):
	cond = cond_n_op.as_long() >> 4
	cc_op = cond_n_op & 0xF
	inv = cond & 1

	if cond == ARMCondAL:
		return z3.BitVecVal(1, 32)
	elif cond in [ ARMCondEQ, ARMCondNE ]:
		zf = armg_calculate_flag_z(cc_op, cc_dep1, cc_dep2, cc_dep3)
		return inv ^ zf;
	elif cond in [ ARMCondHS, ARMCondLO ]:
		cf = armg_calculate_flag_c(cc_op, cc_dep1, cc_dep2, cc_dep3)
		return inv ^ cf;
	elif cond in [ ARMCondMI, ARMCondPL ]:
		nf = armg_calculate_flag_n(cc_op, cc_dep1, cc_dep2, cc_dep3)
		return inv ^ nf;
	elif cond in [ ARMCondVS, ARMCondVC ]:
		vf = armg_calculate_flag_v(cc_op, cc_dep1, cc_dep2, cc_dep3)
		return inv ^ vf
	elif cond in [ ARMCondHI, ARMCondLS ]:
		cf = armg_calculate_flag_c(cc_op, cc_dep1, cc_dep2, cc_dep3)
		zf = armg_calculate_flag_z(cc_op, cc_dep1, cc_dep2, cc_dep3)
		return inv ^ (cf & ~zf)
	elif cond in [ ARMCondGE, ARMCondLT ]:
		nf = armg_calculate_flag_n(cc_op, cc_dep1, cc_dep2, cc_dep3)
		vf = armg_calculate_flag_v(cc_op, cc_dep1, cc_dep2, cc_dep3)
		return inv ^ (1 & ~(nf ^ vf))
	elif cond in [ ARMCondGT, ARMCondLE ]:
		nf = armg_calculate_flag_n(cc_op, cc_dep1, cc_dep2, cc_dep3)
		vf = armg_calculate_flag_v(cc_op, cc_dep1, cc_dep2, cc_dep3)
		zf = armg_calculate_flag_z(cc_op, cc_dep1, cc_dep2, cc_dep3)
		return inv ^ (1 & ~(zf | (nf ^ vf)))

	raise Exception("Unrecognized condition in armg_calculate_condition")
