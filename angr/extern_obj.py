from cle import Backend, Clemory, Segment

class AngrExternObject(Backend):
    def __init__(self, arch, alloc_size=0x4000, granularity=16):
        super(AngrExternObject, self).__init__('##angr_externs##')
        self._next_addr = 0
        self._lookup_table = {}
        self._arch = arch
        self._alloc_size = alloc_size
        self._granularity = granularity
        self.memory = Clemory(arch)
        self.memory.add_backer(0, '\0'*alloc_size)
        self.segments = [Segment(0, 0, 0, alloc_size)]
        self.segments[0].is_readable = True
        self.segments[0].is_writable = False
        self.segments[0].is_executable = True

    def get_max_addr(self):
        return self._alloc_size + self.rebase_addr

    def get_min_addr(self):
        return self.rebase_addr

    def contains_addr(self, addr):
        return addr >= self.get_min_addr() and addr < self.get_max_addr()

    def get_pseudo_addr(self, ident, size=16):
        if ident not in self._lookup_table:
            self._lookup_table[ident] = self._next_addr
            self._next_addr += size + ((self._granularity - size) % self._granularity)
        return self._lookup_table[ident] + self.rebase_addr

    def contains_identifier(self, ident):
        return ident in self._lookup_table

    def get_pseudo_addr_for_symbol(self, ident):
        if ident not in self._lookup_table:
            return None

        return self._lookup_table[ident] + self.rebase_addr
