import simuvex

import logging
l = logging.getLogger("simuvex.procedures.cgc.deallocate")

class deallocate(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, addr, length): #pylint:disable=unused-argument
        # return code (see deallocate() docs)
        r = self.state.se.ite_cases((
                (addr % 0x1000 != 0, self.state.cgc.EINVAL),
                (length == 0, self.state.cgc.EINVAL),
                (self.state.cgc.addr_invalid(addr), self.state.cgc.EINVAL),
                (self.state.cgc.addr_invalid(addr + length), self.state.cgc.EINVAL),
            ), self.state.se.BVV(0, self.state.arch.bits))

        aligned_length = ((length + 0xfff) / 0x1000) * 0x1000

        # TODO: not sure if this is valuable until we actually model CGC
        # allocations accurately
        # self.state.memory.unmap_region(addr, aligned_length)

        return r
