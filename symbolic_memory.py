import platform
import fractions
from z3 import *
import logging

# This class manages memory blocks in the Bintrimmer projects
class MemoryMap(object):

    # Gets the highest representable value on the machine
    def _get_highest_arch_value(self):
        steps = range(self.arch_bits >> 2)
        value = 0
        for i in steps:
            value |= 0xF
            if i != steps[-1]:
                value <<= 4
        return value

    # Initializes the class object
    def __init__(self, arch_type = None):
        logging.basicConfig(level = logging.DEBUG)
        self.mmap = {}
        self.sym_var = []
        self.arch_bits = int(platform.architecture()[0].split('bit')[0]) if (arch_type == None) else arch_type
        self.h_value = self._get_highest_arch_value()


    def _lower_bound(self, expr, lo, hi):
        # Necessary check since Pyhton doesn't allow private functions
        lo = 0 if (lo < 0) else lo
        hi = (self.h_value) if (hi < 0) else hi
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
            s.add(expr_smpl <= bnd)
            s.add(expr_smpl >= lo)
            if  s.check() == sat:
                hi = bnd
                ret = bnd
                logging.debug("Lower bound: Model %s" % s.model());
            else:
                lo = bnd + 1
            s.reset()
            old_bnd = bnd

        return ret

    def _upper_bound(self, expr, lo, hi):
        # Necessary check since Pyhton doesn't allow private functions
        lo = 0 if (lo < 0) else lo
        hi = (self.h_value) if (hi < 0) else hi
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
            s.add(expr_smpl >= bnd)
            s.add(expr_smpl <= hi) #are you serious?
            if  s.check() == sat:
                logging.debug("Upper bound: Model %s" % s.model());
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
    def get_index_scope(self, index_expr, start = None, end = None):
        expr = index_expr
        start = 0 if (start == None or start < 0) else start
        end = self.h_value if (end == None or end < 0) else end
        lo = self._lower_bound(expr, start, end)
        hi = self._upper_bound(expr, start, end)
        # st = self._get_step(expr, lo, hi, 1) #too slow
        st = 1
        return [lo, hi, st]
