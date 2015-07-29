import simuvex

class allocate(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, length, is_x, addr): #pylint:disable=unused-argument
        # return code (see allocate() docs)
        r = self.state.se.ite_cases((
                (length == 0, self.state.cgc.EINVAL),
                (length > self.state.cgc.max_allocation, self.state.cgc.EINVAL),
                (self.state.cgc.addr_invalid(addr), self.state.cgc.EFAULT),
            ), self.state.se.BVV(0, self.state.arch.bits))

        aligned_length = ((length + 0xfff) / 0x1000) * 0x1000
        if isinstance(self.state.cgc.allocation_base, (int, long)):
            self.state.cgc.allocation_base = self.state.BVV(self.state.cgc.allocation_base)
        self.state.memory.store(addr, self.state.cgc.allocation_base - aligned_length, condition=self.state.se.And(r == 0, addr != 0), endness='Iend_LE')

        self.state.cgc.allocation_base -= self.state.se.If(r == 0, aligned_length, self.state.se.BVV(0, self.state.arch.bits))
        return r
