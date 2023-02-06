import angr
import logging

l = logging.getLogger(name=__name__)


class mprotect(angr.SimProcedure):
    def run(self, addr, length, prot):  # pylint:disable=arguments-differ,unused-argument
        try:
            addr = self.state.solver.eval_one(addr)
        except angr.errors.SimValueError:
            raise angr.errors.SimValueError("mprotect can't handle symbolic addr")

        try:
            length = self.state.solver.eval_one(length)
        except angr.errors.SimValueError:
            raise angr.errors.SimValueError("mprotect can't handle symbolic length")

        try:
            prot = self.state.solver.eval_one(prot)
        except angr.errors.SimValueError:
            raise angr.errors.SimValueError("mprotect can't handle symbolic prot")

        l.debug("mprotect(%#x, %#x, %#x) = ...", addr, length, prot)

        if addr & 0xFFF != 0:
            l.debug("... = -1 (not aligned)")
            return -1

        page_end = ((addr + length - 1) & ~0xFFF) + 0x1000
        try:
            for page in range(addr, page_end, 0x1000):
                self.state.memory.permissions(page)
        except angr.errors.SimMemoryError:
            l.debug("... = -1 (missing mappings)")
            return -1

        for page in range(addr, page_end, 0x1000):
            self.state.memory.permissions(page, prot & 7)
        l.debug("... = 0 (good)")
        return 0
