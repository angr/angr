import angr
import logging

l = logging.getLogger('angr.procedures.win32.VirtualAlloc')

# https://msdn.microsoft.com/en-us/library/windows/desktop/aa366890(v=vs.85).aspx
class VirtualAlloc(angr.SimProcedure):
    def run(self, lpAddress, dwSize, flAllocationType, flProtect):
        addrs = self.state.se.any_n_int(lpAddress, 2)
        if len(addrs) != 1:
            raise angr.errors.SimValueError("VirtualAlloc can't handle symbolic lpAddress")
        addr = addrs[0]
        addr &= ~0xfff

        size = self.state.se.max_int(dwSize)
        if dwSize.symbolic and size > self.state.libc.max_variable_size:
            l.warning('symbolic VirtualAlloc dwSize %s has maximum %#x, greater than state.libc.max_variable_size %#x',
                      dwSize, size, self.state.libc.max_variable_size)
            size = self.state.libc.max_variable_size

        flagss = self.state.se.any_n_int(flAllocationType, 2)
        if len(flagss) != 1:
            raise angr.errors.SimValueError("VirtualAlloc can't handle symbolic flAllocationType")
        flags = flagss[0]

        prots = self.state.se.any_n_int(flProtect, 2)
        if len(prots) != 1:
            raise angr.errors.SimValueError("VirtualAlloc can't handle symbolic flProtect")
        prot = prots[0]
        angr_prot = self.convert_prot(prot)

        if flags & 0x00080000 or flags & 0x1000000:
            l.warning("VirtualAlloc with MEM_RESET and MEM_RESET_UNDO are not supported")
            return addr

        if flags & 0x00002000 or addr == 0: # MEM_RESERVE
            if addr == 0:
                while True:
                    addr = self.allocate_memory(size)
                    try:
                        self.state.memory.map_region(addr, size, angr_prot, init_zero=True)
                    except angr.errors.SimMemoryError:
                        continue
                    else:
                        break
            else:
                try:
                    self.state.memory.map_region(addr, size, angr_prot, init_zero=True)
                except angr.errors.SimMemoryError:
                    return 0

        if flags & 0x00001000: # MEM_COMMIT
            # we don't really emulate commit. we just check to see if the region was allocated.
            try:
                self.state.memory.permissions(addr)
            except angr.errors.SimMemoryError:
                return 0

        # if we got all the way to the end, nothing failed! success!
        return addr

    def allocate_memory(self,size):
        addr = self.state.libc.mmap_base
        new_base = addr + size

        if new_base & 0xfff:
            new_base = (new_base & ~0xfff) + 0x1000

        self.state.libc.mmap_base = new_base
        return addr

    @staticmethod
    def convert_prot(prot):
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa366786(v=vs.85).aspx
        if prot & 0x10:
            return 4
        if prot & 0x20:
            return 5
        if prot & 0x40:
            return 7
        if prot & 0x80:
            return 7
        if prot & 0x01:
            return 0
        if prot & 0x02:
            return 1
        if prot & 0x04:
            return 3
        if prot & 0x08:
            return 3
        raise angr.errors.SimValueError("Unknown value of VirtualAlloc flProtect: %#x" % prot)
