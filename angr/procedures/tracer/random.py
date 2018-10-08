import angr
import claripy


class random(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, buf, count, rnd_bytes):
        # return code
        r = self.state.solver.ite_cases(((self.state.cgc.addr_invalid(buf), self.state.cgc.EFAULT),
                                     (self.state.solver.And(rnd_bytes != 0,
                                                        self.state.cgc.addr_invalid(rnd_bytes)), self.state.cgc.EFAULT)),
                                     claripy.BVV(0, self.state.arch.bits))

        if self.state.satisfiable(extra_constraints=[count!=0]):
            max_size = min(1024768 * 10, self.state.solver.max_int(count))
            self.state.memory.store(buf,
                                    claripy.BVV(b'A' * max_size),
                                    size=count
                                    )

        self.state.memory.store(rnd_bytes,
                                count,
                                endness='Iend_LE',
                                condition=rnd_bytes != 0)
        return r
