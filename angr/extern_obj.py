from cle.absobj import AbsObj

class AngrExternObject(AbsObj):
    def __init__(self, alloc_size=0x4000):
        super(AngrExternObject, self).__init__('##angr_externs##')
        self._next_addr = 0
        self._lookup_table = {}
        self._alloc_size = alloc_size
        self.memory = 'please never look at this'

    def get_max_addr(self):
        return self._alloc_size + self.rebase_addr

    def get_min_addr(self):
        return self.rebase_addr

    def get_pseudo_addr(self, ident):
        if ident not in self._lookup_table:
            self._lookup_table[ident] = self._next_addr
            self._next_addr += 16
        return self._lookup_table[ident] + self.rebase_addr
