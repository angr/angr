
class Atom:
    """
    This class represents a data storage location manipulated by IR instructions.

    It could either be a Tmp (temporary variable), a Register, a MemoryLocation, or a Parameter.
    """
    def __repr__(self):
        raise NotImplementedError()


class GuardUse(Atom):
    def __init__(self, target):
        self.target = target

    def __repr__(self):
        return '<Guard %#x>' % self.target


class Tmp(Atom):
    """
    Represents a variable used by the IR to store intermediate values.
    """
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
    """
    Represents a given CPU register.

    As an IR abstracts the CPU design to target different architectures, registers are represented as a separated memory
    space.
    Thus a register is defined by its offset from the base of this memory and its size.

    :ivar int reg_offset:    The offset from the base to define its place in the memory bloc.
    :ivar int size:          The size, in number of bytes.
    """
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

    @property
    def bits(self):
        return self.size * 8


class MemoryLocation(Atom):
    """
    Represents a memory slice.

    It is characterized by its address and its size.
    """
    __slots__ = ['addr', 'size']

    def __init__(self, addr, size):
        super(MemoryLocation, self).__init__()

        self.addr = addr
        self.size = size

    def __repr__(self):
        return "<Mem %s<%d>>" % (hex(self.addr) if type(self.addr) is int else self.addr, self.size)

    @property
    def bits(self):
        return self.size * 8

    @property
    def symbolic(self):
        return not type(self.addr) is int

    def __eq__(self, other):
        return type(other) is MemoryLocation and \
               self.addr == other.addr and \
               self.size == other.size

    def __hash__(self):
        return hash(('mem', self.addr, self.size))


class Parameter(Atom):
    """
    Represents a function parameter.

    Can either be a <angr.engines.light.data.SpOffset> if the parameter was passed on the stack, or a <Register>, depending on the calling
    convention.
    """
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

    def __hash__(self):
        return hash(('par', self.value, self.type_, self.meta))
