from __future__ import annotations
import logging

import claripy
import angr

l = logging.getLogger(name=__name__)

cgc_flag_page_start_addr = 0x4347C000


class allocate(angr.SimProcedure):
    # pylint:disable=arguments-differ,missing-class-docstring

    def run(self, length, is_x, addr):  # pylint:disable=unused-argument
        if self.state.solver.symbolic(length):
            l.warning("Concretizing symbolic length passed to allocate to max_int")

        length = self.state.solver.max_int(length)

        # return code (see allocate() docs)
        r = claripy.ite_cases(
            (
                (length == 0, self.state.cgc.EINVAL),
                (length > self.state.cgc.max_allocation, self.state.cgc.EINVAL),
                (self.state.cgc.addr_invalid(addr), self.state.cgc.EFAULT),
            ),
            claripy.BVV(0, self.state.arch.bits),
        )

        if self.state.solver.max_int(r) != 0:
            # allocate did not succeed. Abort.
            return r

        aligned_length = ((length + 0xFFF) // 0x1000) * 0x1000

        if isinstance(self.state.cgc.allocation_base, int):
            self.state.cgc.allocation_base = claripy.BVV(self.state.cgc.allocation_base, self.state.arch.bits)

        chosen = self.state.cgc.get_max_sinkhole(aligned_length)
        if chosen is None:
            # No sinkhole that can accommodate the requested size exists
            chosen = self.state.cgc.allocation_base - aligned_length
            allocation_base_conc = self.state.solver.eval(self.state.cgc.allocation_base)
            chosen_conc = self.state.solver.eval(chosen)
            if chosen_conc <= cgc_flag_page_start_addr < allocation_base_conc:
                # Chosen memory overlaps with flag page. Add non-overlapping part as a sinkhole and allocate space after
                # the flag page
                sinkhole_size = allocation_base_conc - cgc_flag_page_start_addr - 0x1000
                if sinkhole_size != 0:
                    self.state.cgc.add_sinkhole(cgc_flag_page_start_addr + 0x1000, sinkhole_size)

                chosen = claripy.BVV(cgc_flag_page_start_addr - aligned_length, self.state.arch.bits)
            elif chosen_conc <= self.state.project.loader.max_addr < allocation_base_conc:
                # Chosen memory overlaps with some loaded object
                sinkhole_size = allocation_base_conc - self.state.project.loader.max_addr
                if sinkhole_size != 0:
                    self.state.cgc.add_sinkhole(self.state.project.loader.max_addr, sinkhole_size)

                chosen = claripy.BVV(self.state.project.loader.min_addr - aligned_length, self.state.arch.bits)

            self.state.cgc.allocation_base = chosen

        self.state.memory.store(
            addr, chosen, size=self.state.arch.bytes, condition=claripy.And(addr != 0), endness="Iend_LE"
        )

        # PROT_READ | PROT_WRITE default
        permissions = claripy.BVV(1 | 2, 3)
        permissions |= claripy.If(is_x != 0, claripy.BVV(4, 3), claripy.BVV(0, 3))

        chosen_conc = self.state.solver.eval(chosen)
        l.debug("Allocating [%#x, %#x]", chosen_conc, chosen_conc + aligned_length - 1)
        self.state.memory.map_region(chosen_conc, aligned_length, permissions)
        return r
