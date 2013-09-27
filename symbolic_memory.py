#!/usr/bin/env python
import platform
import fractions
from z3 import *
import logging

logging.basicConfig()
l = logging.getLogger("symbolic_memory")
l.setLevel(logging.DEBUG)

# This class manages memory blocks in the Bintrimmer projects
class MemoryMap(object):

    # Gets the highest representable value on the machine
    def _get_highest_arch_value(self):
        steps = range(self._arch_bits >> 2)
        value = 0
        for i in steps:
            value |= 0xF
            if i != steps[-1]:
                value <<= 4
        return value

    # Initializes the class object
    def __init__(self, arch_type = None):
        self._mmap = {}
        self._sym_var = []
        self._arch_bits = int(platform.architecture()[0].split('bit')[0]) if (arch_type == None) else arch_type
        self._h_value = self._get_highest_arch_value()

    # Gets the Codominium's lower bound of an expression
    def _lower_bound(self, expr, lo, hi):
        # Necessary check since Pyhton doesn't allow private functions
        lo = 0 if (lo < 0) else lo
        hi = (self._h_value) if (hi < 0) else hi
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
            if  s.check() == sat:
                hi = bnd
                ret = bnd
                l.debug("Lower bound Model: %s" % s.model());
            else:
                lo = bnd + 1
            s.reset()
            old_bnd = bnd

        return ret

    # Gets the Codominium's upper bound of an expression
    def _upper_bound(self, expr, lo, hi):
        # Necessary check since Pyhton doesn't allow private functions
        lo = 0 if (lo < 0) else lo
        hi = (self._h_value) if (hi < 0) else hi
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

    #Store value in memory (size has to be expressed in bytes)
    def store(self, dst, src, bytes_size):
        assert z3.is_bv(src), "Stored value unrecognized"
        start = 0
        for mem in range(0, bytes_size):
            ex = z3.Extract(start + 7, start, src)
            self._mmap[dst + (mem * 8)] = ex
            l.debug("Stored at 0x%s value: %s" % (str(dst + (mem * 8)), ex))
            start += 7

    #Load x bit from memory
    def load(self, dst, bytes_size):
        value = {}
        for mem in range(0, bytes_size):
            try:
                value[mem] = self._mmap[dst + (mem * 8)]
                l.debug("Loaded from 0x%s value: %s" % (str(dst + (mem * 8)), value[mem]))
            except:
                l.debug("No value previously loaded. Symbolic Variable found!")
                self._sym_var.append(dst + (mem * 8))
        return value

    # Gets the memory scope of the index
    def get_index_scope(self, index_expr, start = None, end = None):
        expr = index_expr
        start = 0 if (start == None or start < 0) else start
        end = self._h_value if (end == None or end < 0) else end
        lo = self._lower_bound(expr, start, end)
        hi = self._upper_bound(expr, start, end)
        # st = self._get_step(expr, lo, hi, 1) #too slow
        st = 1
        return [lo, hi, st]
