#!/usr/bin/env python
import z3

import logging
l = logging.getLogger("s_value")

class ConcretizingException(Exception):
        pass

class Value:
        def __init__(self, expr, constraints = None, lo = 0, hi = 2**64):
                # workaround for the constant simplifying bug
                try:
                        self.expr = z3.simplify(expr)
                        self.constraints = z3.simplify(constraints) if constraints != None else None
                except:
                        self.expr = expr
                        self.constraints = constraints

                self.solver = z3.Solver()
                if constraints != None:
                        self.solver.add(*self.constraints)
                        self.solver.push()

                self.min_for_size = 0
                self.max_for_size = 2 ** self.expr.size() - 1

                self.min = self.get_min(lo, hi)
                self.max = self.get_max(self.min, hi)

        def get_min(self, lo = 0, hi = 2**64):
                lo = max(lo, self.min_for_size)
                hi = min(hi, self.max_for_size)

                ret = -1
                old_bnd = -1
                while 1:
                        bnd = lo + ((hi - lo) >> 1)
                        if bnd == old_bnd:
                                break

                        bnd_asbv = z3.BitVecVal(bnd, 64)
                        lo_asbv = z3.BitVecVal(lo, 64)
                        self.solver.push()
                        self.solver.add(z3.ULE(self.expr, bnd_asbv))
                        self.solver.add(z3.UGE(self.expr, lo_asbv))

                        if self.solver.check() == z3.sat:
                                hi = bnd
                                ret = bnd
                        else:
                                lo = bnd + 1

                        self.solver.pop()
                        old_bnd = bnd

                if ret == -1:
                        raise ConcretizingException("Unable to concretize expression %s", str(self.expr))
                return ret

        def get_max(self, lo = 0, hi = 2**64):
                lo = max(lo, self.min_for_size)
                hi = min(hi, self.max_for_size)

                ret = -1
                end = hi

                old_bnd = -1
                while 1:
                        bnd = lo + ((hi - lo) >> 1)
                        if bnd == old_bnd:
                                break

                        bnd_asbv = z3.BitVecVal(bnd, 64)
                        hi_asbv = z3.BitVecVal(hi, 64)
                        self.solver.push()
                        self.solver.add(z3.UGE(self.expr, bnd_asbv))
                        self.solver.add(z3.ULE(self.expr, hi_asbv))

                        if self.solver.check() == z3.sat:
                                lo = bnd
                                ret = bnd
                        else:
                                hi = bnd - 1

                        self.solver.pop()
                        old_bnd = bnd

                # The algorithm above retrieves the floor of the upper
                # bound range (i.e. [Floor_upper, Ceil_upper]. So we
                # have to try also the ceiling.
                if ret != -1:
                        self.solver.push()
                        self.solver.add(self.expr == (ret + 1))
                        self.solver.add(z3.ULE(self.expr, hi))
                        if self.solver.check() == z3.sat:
                                ret += 1
                        self.solver.pop()

                if ret == -1:
                        raise ConcretizingException("Unable to concretize expression %s", str(self.expr))
                return ret

        # iterates over all possible values
        def iter(self, lo=0, hi=2**64):
                lo = max(lo, self.min_for_size, self.min)
                hi = min(hi, self.max_for_size, self.max)

                self.current = lo
                while self.current <= hi:
                        self.current = self.get_min(self.current, hi)
                        yield self.current
                        self.current += 1

        # def _get_step(self, expr, start, stop, incr):
        #        lo = 0 if (start < 0) else start
        #        hi = ((1 << self.arch_bits) - 1) if (stop < 0) else stop
        #        incr = 1 if (incr <= 0) else incr
        #        s = Solver()

        #        gcd = -1
        #        unsat_steps = 0

        #        while lo <= hi:
        #                s.add(expr == lo)
        #                if  s.check() == sat:
        #                        gcd = unsat_steps if (gcd == -1) else fractions.gcd(gcd, unsat_steps)
        #                        if gcd == 1:
        #                                break
        #                        unsat_steps = 1
        #                else:
        #                        unsat_steps += 1
        #                        s.reset()
        #                lo = lo + incr

        #        return gcd
