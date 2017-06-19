import simuvex

import itertools
rand_count = itertools.count()

class random(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, buf, count, rnd_bytes):
        if self.state.mode == 'fastpath':
            # Special case for CFG
            if (not self.state.se.symbolic(count) and
                    not self.state.se.symbolic(buf) and
                    not self.state.se.symbolic(rnd_bytes)):
                if (self.state.se.is_true(rnd_bytes != 0) and self.state.cgc.addr_invalid(rnd_bytes))\
                        or self.state.cgc.addr_invalid(buf):
                    return self.state.cgc.EFAULT

                max_count = self.state.se.exactly_int(count)
                random_num = self.state.se.Unconstrained('random_%d' % rand_count.next(), max_count * 8)
                self.state.memory.store(buf, random_num, size=count)
                if self.state.se.is_true(rnd_bytes != 0):
                    self.state.memory.store(rnd_bytes, count, endness='Iend_LE')

            # We always return something in fastpath mode
            return self.state.se.BVV(0, self.state.arch.bits)

        # return code
        r = self.state.se.ite_cases((
                (self.state.cgc.addr_invalid(buf), self.state.cgc.EFAULT),
                (self.state.se.And(rnd_bytes != 0, self.state.cgc.addr_invalid(rnd_bytes)), self.state.cgc.EFAULT),
            ), self.state.se.BVV(0, self.state.arch.bits))

        if self.state.satisfiable(extra_constraints=[count!=0]):
            self.state.memory.store(buf, self.state.se.Unconstrained('random_%d' % rand_count.next(), self.state.se.max_int(count*8)), size=count)
        self.state.memory.store(rnd_bytes, count, endness='Iend_LE', condition=rnd_bytes != 0)

        return r
