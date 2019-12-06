import angr

import itertools
rand_count = itertools.count()

class random(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, buf, count, rnd_bytes):
        if self.state.mode == 'fastpath':
            # Special case for CFG
            if (not self.state.solver.symbolic(count) and
                    not self.state.solver.symbolic(buf) and
                    not self.state.solver.symbolic(rnd_bytes)):
                if (self.state.solver.is_true(rnd_bytes != 0) and self.state.cgc.addr_invalid(rnd_bytes))\
                        or self.state.cgc.addr_invalid(buf):
                    return self.state.cgc.EFAULT

                max_count = self.state.solver.eval_one(count)
                random_num = self.state.solver.Unconstrained('random_%d' % next(rand_count), max_count * 8)
                self.state.memory.store(buf, random_num, size=count)
                if self.state.solver.is_true(rnd_bytes != 0):
                    self.state.memory.store(rnd_bytes, count, endness='Iend_LE')

            # We always return something in fastpath mode
            return self.state.solver.BVV(0, self.state.arch.bits)

        # return code
        r = self.state.solver.ite_cases((
                (self.state.cgc.addr_invalid(buf), self.state.cgc.EFAULT),
                (self.state.solver.And(rnd_bytes != 0, self.state.cgc.addr_invalid(rnd_bytes)), self.state.cgc.EFAULT),
            ), self.state.solver.BVV(0, self.state.arch.bits))

        if self.state.satisfiable(extra_constraints=[count!=0]):
            self.state.memory.store(buf, self.state.solver.Unconstrained('random_%d' % next(rand_count), self.state.solver.max_int(count*8), key=('syscall', 'random')), size=count)
        self.state.memory.store(rnd_bytes, count, endness='Iend_LE', condition=rnd_bytes != 0)

        return r
