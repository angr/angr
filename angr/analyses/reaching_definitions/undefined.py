class Undefined:

    __slots__ = ('bits', '_type', '_meta')

    def __init__(self, bits, type_=None, meta=None):
        self.bits = bits
        self._type = type_
        self._meta = meta

    @property
    def type_(self):
        return self._type

    @property
    def meta(self):
        return self._meta

    def __add__(self, other):
        return self

    def __radd__(self, other):
        return self

    def __sub__(self, other):
        return self

    def __rsub__(self, other):
        return self

    def __lshift__(self, other):
        return self

    def __rlshift__(self, other):
        return self

    def __rshift__(self, other):
        return self

    def __rrshift__(self, other):
        return self

    def __and__(self, other):
        return self

    def __rand__(self, other):
        return self

    def __xor__(self, other):
        return self

    def __rxor__(self, other):
        return self

    def __or__(self, other):
        return self

    def __ror__(self, other):
        return self

    def __neg__(self):
        return self

    def __eq__(self, other):
        return type(other) is Undefined and \
               self.bits == other.bits and \
               self._type == other.type_ and \
               self._meta == other.meta

    def __hash__(self):
        return hash(('undefined', self.bits, self._type, self._meta))

    def __str__(self):
        type_ = (', type=%s' % self._type) if self._type is not None else ''
        meta = ', meta=%s' % self._meta if self._meta is not None else ''
        return '<Undef%s%s>' % (type_, meta)

    def __repr__(self):
        return "<Undefined>"
