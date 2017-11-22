import angr
import claripy


class random(angr.SimProcedure):
    #pylint:disable=arguments-differ
    IS_SYSCALL = True

    def run(self, buf, count, rnd_bytes):
        # return code
        r = self.state.se.ite_cases(((self.state.cgc.addr_invalid(buf), self.state.cgc.EFAULT),
                                     (self.state.se.And(rnd_bytes != 0,
                                                        self.state.cgc.addr_invalid(rnd_bytes)), self.state.cgc.EFAULT)),
                                     claripy.BVV(0, self.state.arch.bits))

        if self.state.satisfiable(extra_constraints=[count!=0]):
            self.state.memory.store(buf,
                                    claripy.BVV('A' * self.state.se.max_int(count)),
                                    size=count)

        self.state.memory.store(rnd_bytes,
                                count,
                                endness='Iend_LE',
                                condition=rnd_bytes != 0)
        return r
