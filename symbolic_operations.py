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

_h_value = get_highest_arch_value()

def get_min(expr, constr, lo = 0, hi = 0):
    lo = 0 if (lo < 0) else lo
    hi = _h_value if (hi < 0) else hi
    s = Solver()
    ret = -1
    # workaround for the constant simplifying bug
    try:
        expr_smpl = simplify(expr)
    except:
        expr_smpl = expr

    old_bnd = -1
    while 1:
        bnd = lo + ((hi - lo) >> 1)
        if bnd == old_bnd:
            break
        s.add(ULE(expr_smpl, bnd))
        s.add(UGE(expr_smpl, lo))
        if constr != None:
            s.add(constr)
        if  s.check() == sat:
            hi = bnd
            ret = bnd
            l.debug("Lower bound Model: %s" % s.model());
        else:
            lo = bnd + 1
        s.reset()
        old_bnd = bnd

    return ret

def get_max(expr, constr, lo = 0, hi = 0):
    lo = 0 if (lo < 0) else lo
    hi = _h_value if (hi < 0) else hi
    s = Solver()
    ret = -1
    end = hi
    # workaround for the constant simplifying bug
    try:
        expr_smpl = simplify(expr)
    except:
        expr_smpl = expr

    old_bnd = -1
    while 1:
        bnd = lo + ((hi - lo) >> 1)
        if bnd == old_bnd:
            break
        s.add(UGE(expr_smpl, bnd))
        s.add(ULE(expr_smpl, hi))
        if constr != None:
            s.add(constr)
        if  s.check() == sat:
            l.debug("Upper bound Model: %s" % s.model());
            lo = bnd
            ret = bnd
        else:
            hi = bnd - 1
        s.reset()
        old_bnd = bnd

    # The algorithm above retrieves the floor of the upper
    # bound range (i.e. [Floor_upper, Ceil_upper]. So we
    # have to try also the ceiling.
    if ret != -1:
        s.add(expr_smpl == (ret + 1))
        s.add(expr_smpl <= hi)
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

# Gets the memory scope of the index
def get_codominium(expr, irsp_cnstr=None, start = None, end = None):
    single_constraint = z3.And(*irsp_cnstr) if irsp_cnstr != None else None
    start = 0 if (start == None or start < 0) else start
    end = _h_value if (end == None or end < 0) else end
    lo = get_min(expr, single_constraint, start, end)
    hi = get_max(expr, single_constraint, start, end)
    return [lo, hi]
