import claripy
import simuvex
import logging

l = logging.getLogger("simuvex.procedures.cgc.allocate")

class allocate(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, length, is_x, addr): #pylint:disable=unused-argument
        if self.state.se.symbolic(length):
            l.warning("Concretizing symbolic length passed to allocate to max_int")

        length = self.state.se.max_int(length)

        # return code (see allocate() docs)
        r = self.state.se.ite_cases((
                (length == 0, self.state.cgc.EINVAL),
                (length > self.state.cgc.max_allocation, self.state.cgc.EINVAL),
                (self.state.cgc.addr_invalid(addr), self.state.cgc.EFAULT),
            ), self.state.se.BVV(0, self.state.arch.bits))

        aligned_length = ((length + 0xfff) / 0x1000) * 0x1000

        if isinstance(self.state.cgc.allocation_base, (int, long)):
            self.state.cgc.allocation_base = self.state.se.BVV(self.state.cgc.allocation_base, self.state.arch.bits)

        chosen = sinkhole_chosen = self.state.cgc.get_max_sinkhole(aligned_length)
        if chosen is None:
            chosen = self.state.cgc.allocation_base - aligned_length

        self.state.memory.store(addr, chosen, condition=self.state.se.And(r == 0, addr != 0), endness='Iend_LE')

        if sinkhole_chosen is None:
            self.state.cgc.allocation_base -= self.state.se.If(r == 0,
                    aligned_length,
                    self.state.se.BVV(0, self.state.arch.bits))

        # PROT_READ | PROT_WRITE default
        permissions = self.state.se.BVV(1 | 2, 3)
        permissions |= self.state.se.If(is_x != 0, claripy.BVV(4, 3), claripy.BVV(0, 3))

        if self.state.se.max_int(r) == 0:  # map only on success

            l.debug("Allocate address %#x", self.state.se.any_int(chosen))
            self.state.memory.map_region(
                    chosen,
                    aligned_length,
                    permissions
                    )
        return r
