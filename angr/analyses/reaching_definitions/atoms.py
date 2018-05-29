class Atom(object):
    def __init__(self):
        pass

    def __repr__(self):
        raise NotImplementedError()


class Tmp(Atom):
    __slots__ = ['tmp_idx']

    def __init__(self, tmp_idx):
        super(Tmp, self).__init__()
        self.tmp_idx = tmp_idx

    def __repr__(self):
        return "<Tmp %d>" % self.tmp_idx

    def __eq__(self, other):
        return type(other) is Tmp and \
               self.tmp_idx == other.tmp_idx

    def __hash__(self):
        return hash(('tmp', self.tmp_idx))


class Register(Atom):
    __slots__ = ['reg_offset', 'size']

    def __init__(self, reg_offset, size):
        super(Register, self).__init__()

        self.reg_offset = reg_offset
        self.size = size

    def __repr__(self):
        return "<Reg %d<%d>>" % (self.reg_offset, self.size)

    def __eq__(self, other):
        return type(other) is Register and \
               self.reg_offset == other.reg_offset and \
               self.size == other.size

    def __hash__(self):
        return hash(('reg', self.reg_offset, self.size))


class MemoryLocation(Atom):
    __slots__ = ['addr', 'size']

    def __init__(self, addr, size):
        super(MemoryLocation, self).__init__()

        self.addr = addr
        self.size = size

    def __repr__(self):
        return "<Mem %#x<%d>>" % (self.addr, self.size)

    @property
    def bits(self):
        return self.size * 8

    def __eq__(self, other):
        return type(other) is MemoryLocation and \
               self.addr == other.addr and \
               self.size == other.size

    def __hash__(self):
        return hash(('mem', self.addr, self.size))


class Parameter(Atom):
    __slots__ = ['value', 'type_', 'meta']

    def __init__(self, value, type_=None, meta=None):
        super(Parameter, self).__init__()

        self.value = value
        self.type_ = type_
        self.meta = meta

    def __repr__(self):
        type_ = ', type=%s' % self.type_ if self.type_ is not None else ''
        meta = ', meta=%s' % self.meta if self.meta is not None else ''
        return '<Param %s%s%s>' % (self.value, type_, meta)

    def __eq__(self, other):
        return type(other) is Parameter and \
               self.value == other.value and \
               self.type_ == other.type_ and \
               self.meta == other.meta
