#!/usr/bin/env python
import platform
import fractions
from z3 import *
import logging

logging.basicConfig()
l = logging.getLogger("symbolic_operations")
l.setLevel(logging.INFO)

def get_highest_arch_value():
    steps = range(int(platform.architecture()[0].split('bit')[0]) >> 2)
    value = 0
    for i in steps:
        value |= 0xF
        if i != steps[-1]:
            value <<= 4
    return value

_n_bits = int(platform.architecture()[0].split('bit')[0])
_h_value = z3.BitVecVal(get_highest_arch_value(), _n_bits)

def get_min(expr, constr, lo = 0, hi = 0):
    lo = z3.BitVecVal(0 if (lo < 0) else lo, _n_bits)
    hi = z3.BitVecVal(_h_value.as_long() if (hi < 0) else hi, _n_bits)
    s = Solver()
    ret = -1
    # workaround for the constant simplifying bug
    try:
        expr_smpl = simplify(expr)
        constr_smpl = simplify(constr)
    except:
        expr_smpl = expr
        constr_smpl = constr

    old_bnd = z3.BitVecVal(0, _n_bits)
    while 1:
        bnd = z3.BitVecVal(lo.as_long() + z3.simplify(z3.LShR(z3.BitVecVal(hi.as_long() - lo.as_long(), _n_bits), 1)).as_long(), _n_bits)
        if bnd.as_long() == old_bnd.as_long(): #consider to remove .as_long()
            break
        s.add(ULE(expr_smpl, bnd))
        s.add(UGE(expr_smpl, lo))
        if constr_smpl != None:
            s.add(constr_smpl)
        if  s.check() == sat:
            hi = bnd
            ret = bnd.as_long()
            l.debug("Lower bound Model: %s" % s.model());
        else:
            lo = z3.BitVecVal(bnd.as_long() + 1, _n_bits)
        s.reset()
        old_bnd = bnd

    return ret

def get_max(expr, constr, lo = 0, hi = 0):
    lo = z3.BitVecVal(0 if (lo < 0) else lo, _n_bits)
    hi = z3.BitVecVal(_h_value.as_long() if (hi < 0) else hi, _n_bits)
    s = Solver()
    ret = -1
    end = hi
    # workaround for the constant simplifying bug
    try:
        expr_smpl = simplify(expr)
        constr_smpl = simplify(constr)
    except:
        expr_smpl = expr
        constr_smpl = constr

    old_bnd = z3.BitVecVal(0, _n_bits)
    while 1:
        bnd = z3.BitVecVal(lo.as_long() + z3.simplify(z3.LShR(z3.BitVecVal(hi.as_long() - lo.as_long(), _n_bits), 1)).as_long(), _n_bits)
        if bnd.as_long() == old_bnd.as_long():
            break
        s.add(UGE(expr_smpl, bnd))
        s.add(ULE(expr_smpl, hi))
        if constr_smpl != None:
            s.add(constr_smpl)
        if  s.check() == sat:
            l.debug("Upper bound Model: %s" % s.model());
            lo = bnd
            ret = bnd.as_long()
        else:
            hi = z3.BitVecVal(bnd.as_long() - 1, _n_bits)
        s.reset()
        old_bnd = bnd

    # The algorithm above retrieves the floor of the upper
    # bound range (i.e. [Floor_upper, Ceil_upper]. So we
    # have to try also the ceiling.
    if ret != -1:
        s.add(expr_smpl == (z3.BitVecVal(ret + 1, _n_bits)))
        s.add(ULE(expr_smpl, hi))
        if s.check() == sat:
            ret += 1

    return ret

# def _get_step(self, expr, start, stop, incr):
#     lo = 0 if (start < 0) else start
#     hi = ((1 << self.arch_bits) - 1) if (stop < 0) else stop
#     incr = 1 if (incr <= 0) else incr
#     s = Solver()

#     gcd = -1
#     unsat_steps = 0

#     while lo <= hi:
#         s.add(expr == lo)
#         if  s.check() == sat:
#             gcd = unsat_steps if (gcd == -1) else fractions.gcd(gcd, unsat_steps)
#             if gcd == 1:
#                 break
#             unsat_steps = 1
#         else:
#             unsat_steps += 1
#             s.reset()
#         lo = lo + incr

#     return gcd

def get_max_min(expr, irsp_cnstr=None, start = None, end = None):
    single_constraint = z3.And(*irsp_cnstr) if irsp_cnstr != None else None
    start = z3.BitVecVal(0 if (start == None or start < 0) else start, _n_bits)
    end = z3.BitVecVal(_h_value.as_long() if (end == None or end < 0) else end, _n_bits)
    lo = get_min(expr, single_constraint, start, end)
    hi = get_max(expr, single_constraint, start, end)
    assert z3.is_bv(lo) == False and z3.is_bv(hi) == False, "BitVecVal would not be returned"
    return [lo, hi]
