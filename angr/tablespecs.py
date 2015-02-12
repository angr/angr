class StringSpec(object):
    __immutable = False
    def __init__(self, string=None, sym_length=None, concat=None, name=None, nonnull=False):
        argc = (string is not None) + (sym_length is not None) + (concat is not None)
        if argc == 0 or argc > 1:
            raise ValueError("You must provide one arg!")
        if string is not None:
            self.type = 1
            self._len = len(string)
            self._str = string
        elif sym_length is not None:
            self.type = 2
            self._len = sym_length
            self._name = name if name is not None else ("sym_string_%d" % sym_length)
            self._nonnull = nonnull
        else: # concat is not None
            self._len = 0
            for substring in concat:
                if not isinstance(substring, StringSpec):
                    raise ValueError('All items in concat argument must be StringSpecs!')
                self._len += len(substring)
            self.type = 3
            self._children = concat
        self.__immutable = True

    def dump(self, state, address):
        if self.type == 1:
            for i, c in enumerate(self._str):
                state.store_mem(address + i, state.BVV(ord(c), 8))
        elif self.type == 2:
            state.store_mem(address, state.se.Unconstrained(self._name, 8*self._len))
            if self._nonnull:
                for i in xrange(self._len):
                    state.se.add(state.mem_expr(i + address, length=1) != state.BVV(0, 8))
        else:
            i = 0
            for child in self._children:
                child.dump(state, address + i)
                i += len(child)

    def __add__(self, other):
        if type(other) is str:
            return StringSpec(concat=(self, StringSpec(other)))
        elif isinstance(other, StringSpec):
            return StringSpec(concat=(self, other))
        else:
            return None

    def __radd__(self, other):
        if type(other) is str:
            return StringSpec(concat=(StringSpec(other), self))
        elif isinstance(other, StringSpec):
            return StringSpec(concat=(other, self))
        else:
            return None

    def __mul__(self, other):
        return StringSpec(concat=(self)*other)

    def __len__(self):
        return self._len

    def __hash__(self):
        if self.type == 1:
            return hash(self._str) ^ 0xbadfaced
        elif self.type == 2:
            return hash(self._len) ^ hash(self._name) ^ 0xd00dcac3
        elif self.type == 3:
            return hash(tuple(self._children))

    def __setattr__(self, key, value):
        if self.__immutable:
            raise TypeError('Class is immutable')
        else:
            super(StringSpec, self).__setattr__(key, value)


class StringTableSpec:
    def __init__(self):
        self._contents = []
        self._str_len = 0

    def add_string(self, string):
        if type(string) is str:
            self._contents.append(StringSpec(string+'\0'))
        elif isinstance(string, StringSpec):
            self._contents.append(string + StringSpec('\0'))
        else:
            raise ValueError('String must be either string literal or StringSpec')
        self._str_len += len(string) + 1

    def add_pointer(self, pointer):
        self._contents.append(pointer)

    def add_null(self):
        self._contents.append(0)

    def dump(self, state, end_addr, align=0x10):
        if type(end_addr) in (int, long):
            end_addr = state.BVV(end_addr, state.arch.bits)
        ptr_size = len(self._contents) * state.arch.bytes
        size = self._str_len + ptr_size
        start_addr = end_addr - size
        start_addr -= start_addr % align
        start_str = start_addr + ptr_size

        ptr_i = start_addr
        str_i = start_str
        for item in self._contents:
            if isinstance(item, StringSpec):
                state.store_mem(ptr_i, str_i, size=state.arch.bytes, endness=state.arch.memory_endness)
                item.dump(state, str_i)
                ptr_i += state.arch.bytes
                str_i += len(item)
            else:
                if type(item) in (int, long):
                    item = state.BVV(item, state.arch.bits)
                state.store_mem(ptr_i, item, size=state.arch.bytes, endness=state.arch.memory_endness)
                ptr_i += state.arch.bytes
        return start_addr
