import simuvex

class deallocate(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, addr, length): #pylint:disable=unused-argument
        # return code (see deallocate() docs)
        r = self.state.se.ite_cases((
                (addr % 0x1000 != 0, self.state.cgc.EINVAL),
                (length == 0, self.state.cgc.EINVAL),
                (self.state.cgc.addr_invalid(addr), self.state.cgc.EINVAL),
                (self.state.cgc.addr_invalid(addr + length), self.state.cgc.EINVAL),
            ), self.state.se.BVV(0, self.state.arch.bits))

        return r
