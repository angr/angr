import platform
import fractions
from z3 import *
import logging

# This class manages memory blocks in the Bintrimmer projects
class MemoryMap(object):

    # Initializes the class object
    def __init__(self, arch_type = None):
        logging.basicConfig(level = logging.DEBUG)
        self.mmap = {}
        self.sym_var = []
        self.arch_bits = int(platform.architecture()[0].split('bit')[0]) if (arch_type == None) else arch_type

    def _lower_bound(self, expr, var, lo, hi):
        s = Solver()
        __y = BitVec('__y', 64)
        ret = -1
        # workaround for the constant simplifying bug
        try:
            expr_smpl = simplify(expr)
        except:
            expr_smpl = expr
        s.add(lo <= expr_smpl)
        s.add(__y == expr_smpl)

        if  s.check() == sat:
            logging.debug('_lower_bound: got model %s' % s.model())
            ret = s.model()[__y].as_long()
            ret = ret if(ret <= hi) else -1
        return ret

    def _upper_bound(self, expr, var, lo, hi):
        s = Solver()
        __y = BitVec('__y', 64)
        ret = -1
        # workaround for the constant simplifying bug
        try:
            expr_smpl = simplify(expr)
        except:
            expr_smpl = expr
        s.add(expr_smpl <= hi)
        s.add(__y == expr_smpl)

        if  s.check() == sat:
            logging.debug('_upper_bound: got model %s' % s.model())
            ret = s.model()[__y].as_long()
            ret = ret if(ret >= lo) else -1
        return ret

    def _get_step(self, expr, start, stop, incr):
        lo = 0 if (start < 0) else start
        hi = ((1 << self.arch_bits) - 1) if (stop < 0) else stop
        incr = 1 if (incr <= 0) else incr
        s = Solver()

        gcd = -1
        unsat_steps = 0

        while lo <= hi:
            s.add(expr == lo)
            if  s.check() == sat:
                gcd = unsat_steps if (gcd == -1) else fractions.gcd(gcd, unsat_steps)
                if gcd == 1:
                    break
                unsat_steps = 1
            else:
                unsat_steps += 1
                s.reset()
            lo = lo + incr

        return gcd

    # Gets the memory scope of the index
    def get_index_scope(self, index_expr, var, start = None, end = None):
        expr = index_expr
        start = 0 if (start == None) else start
        end = (1 << self.arch_bits) - 1 if (end == None) else end
        lo = self._lower_bound(expr, var, start, end)
        hi = self._upper_bound(expr, var, start, end)
        # st = self._get_step(expr, lo, hi, 1) #too slow

        st = 1
        return [lo, hi, st]
