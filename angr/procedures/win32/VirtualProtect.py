import angr
import logging

from .VirtualAlloc import convert_prot, deconvert_prot

l = logging.getLogger(name=__name__)


class VirtualProtect(angr.SimProcedure):
    def run(self, lpAddress, dwSize, flNewProtect, lpfOldProtect):
        l.debug("VirtualProtect(%s, %s, %s, %s)", lpAddress, dwSize, flNewProtect, lpfOldProtect)
        addrs = self.state.solver.eval_upto(lpAddress, 2)
        if len(addrs) != 1:
            raise angr.errors.SimValueError("VirtualProtect can't handle symbolic lpAddress")
        addr = addrs[0]

        size = self.state.solver.max_int(dwSize)
        if dwSize.symbolic and size > self.state.libc.max_variable_size:
            l.warning(
                "symbolic VirtuaProtect dwSize %s has maximum %#x, greater than state.libc.max_variable_size %#x",
                dwSize,
                size,
                self.state.libc.max_variable_size,
            )
            size = self.state.libc.max_variable_size

        prots = self.state.solver.eval_upto(flNewProtect, 2)
        if len(prots) != 1:
            raise angr.errors.SimValueError("VirtualProtect can't handle symbolic flNewProtect")
        prot = prots[0]

        try:
            if not self.state.solver.is_false(self.state.memory.permissions(lpfOldProtect) & 2 == 0):
                l.debug("...failed, bad lpfOldProtect (write-perm)")
                return 0
        except angr.errors.SimMemoryError:
            l.debug("...failed, bad lpfOldProtect (write-miss)")
            return 0

        page_start = addr & ~0xFFF
        page_end = (addr + size - 1) & ~0xFFF
        first_prot = None
        try:
            for page in range(page_start, page_end + 0x1000, 0x1000):
                old_prot = self.state.memory.permissions(page)
                if first_prot is None:
                    first_prot = self.state.solver.eval(old_prot)
        except angr.errors.SimMemoryError:
            l.debug("...failed, bad address")
            return 0

        angr_prot = convert_prot(prot)

        # we're good! make the changes.
        for page in range(page_start, page_end + 0x1000, 0x1000):
            self.state.memory.permissions(page, angr_prot)

        self.state.mem[lpfOldProtect].dword = deconvert_prot(first_prot)
        return 1
