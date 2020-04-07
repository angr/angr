from ..posix.mmap import mmap

class old_mmap(mmap):
    def run(self, ptr):
        addr, length, prot, flags, fd, offset = self.state.mem[ptr].dword.array(6).resolved
        return super(old_mmap, self).run(addr, length, prot, flags, fd, offset)

class mmap2(mmap):
    def run(self, addr, length, prot, flags, fd, offset):
        if len(offset) == 32:
            offset = offset.zero_extend(32)
            offset *= 0x1000
        return super(mmap2, self).run(addr, length, prot, flags, fd, offset)
