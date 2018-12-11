import claripy
import angr
import logging

l = logging.getLogger(name=__name__)

class allocate(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, length, is_x, addr): #pylint:disable=unused-argument
        if self.state.solver.symbolic(length):
            l.warning("Concretizing symbolic length passed to allocate to max_int")

        length = self.state.solver.max_int(length)

        # return code (see allocate() docs)
        r = self.state.solver.ite_cases((
                (length == 0, self.state.cgc.EINVAL),
                (length > self.state.cgc.max_allocation, self.state.cgc.EINVAL),
                (self.state.cgc.addr_invalid(addr), self.state.cgc.EFAULT),
            ), self.state.solver.BVV(0, self.state.arch.bits))

        aligned_length = ((length + 0xfff) // 0x1000) * 0x1000

        if isinstance(self.state.cgc.allocation_base, int):
            self.state.cgc.allocation_base = self.state.solver.BVV(self.state.cgc.allocation_base, self.state.arch.bits)

        chosen = sinkhole_chosen = self.state.cgc.get_max_sinkhole(aligned_length)
        if chosen is None:
            chosen = self.state.cgc.allocation_base - aligned_length

        self.state.memory.store(addr, chosen, condition=self.state.solver.And(r == 0, addr != 0), endness='Iend_LE')

        if sinkhole_chosen is None:
            self.state.cgc.allocation_base -= self.state.solver.If(r == 0,
                    aligned_length,
                    self.state.solver.BVV(0, self.state.arch.bits))

        # PROT_READ | PROT_WRITE default
        permissions = self.state.solver.BVV(1 | 2, 3)
        permissions |= self.state.solver.If(is_x != 0, claripy.BVV(4, 3), claripy.BVV(0, 3))

        if self.state.solver.max_int(r) == 0:  # map only on success

            chosen_conc = self.state.solver.eval(chosen)
            l.debug("Allocate address %#x", chosen_conc)
            self.state.memory.map_region(
                    chosen_conc,
                    aligned_length,
                    permissions
                    )
        return r
