class RegisterOffset(object):
    def __init__(self, bits, reg, offset):
        self._bits = bits
        self.reg = reg
        self.offset = offset

    @property
    def bits(self):
        return self._bits

    def __repr__(self):
        return "%s%s" % (self.reg, '' if self.offset == 0 else '%+x' % self.offset)

    def __add__(self, other):
        if type(other) is int:
            return RegisterOffset(self._bits, self.reg, self._to_signed(self.offset + other))
        raise TypeError()

    def __sub__(self, other):
        if type(other) is int:
            return RegisterOffset(self._bits, self.reg, self._to_signed(self.offset - other))
        raise TypeError()

    def _to_signed(self, n):
        if n >= 2 ** (self._bits - 1):
            return n - 2 ** self._bits
        return n


class SpOffset(RegisterOffset):
    def __init__(self, bits, offset, is_base=False):
        super(SpOffset, self).__init__(bits, 'sp', offset)
        self.is_base = is_base

    def __repr__(self):
        return "%s%s" % ('BP' if self.is_base else 'SP', '' if self.offset == 0 else '%+x' % self.offset)

    def __add__(self, other):
        if type(other) is int:
            return SpOffset(self._bits, self._to_signed(self.offset + other))
        raise TypeError()

    def __sub__(self, other):
        if type(other) is int:
            return SpOffset(self._bits, self._to_signed(self.offset - other))
        raise TypeError()

    def __eq__(self, other):
        return type(other) is SpOffset and self._bits == other.bits and self.reg == other.reg and \
               self.offset == other.offset and self.is_base is other.is_base

    def __hash__(self):
        return hash((self._bits, self.reg, self.offset, self.is_base))

    def __lt__(self, other):
        if type(other) is not SpOffset or self.reg != other.reg:
            return NotImplemented
        return self.offset < other.offset

    def __gt__(self, other):
        if type(other) is not SpOffset or self.reg != other.reg:
            return NotImplemented
        return self.offset > other.offset
