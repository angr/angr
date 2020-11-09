
import ailment

from ...utils.constants import is_alignment_mask


class ArithmeticExpression:

    Add = 0
    Sub = 1
    Or = 2
    And = 4
    RShift = 8
    LShift = 16
    Mul = 32
    Xor = 64

    CONST_TYPES = (int, ailment.expression.Const)

    __slots__ = ('op', 'operands', )

    def __init__(self, op, operands):
        self.op = op
        self.operands = operands

    def __repr__(self):
        if self.op == ArithmeticExpression.Add:
            return "%s + %s" % self.operands
        elif self.op == ArithmeticExpression.Sub:
            return "%s - %s" % self.operands
        elif self.op == ArithmeticExpression.And:
            return "%s & %s" % self.operands
        elif self.op == ArithmeticExpression.Or:
            return "%s | %s" % self.operands
        elif self.op == ArithmeticExpression.RShift:
            return "%s >> %s" % self.operands
        elif self.op == ArithmeticExpression.LShift:
            return "%s << %s" % self.operands
        elif self.op == ArithmeticExpression.Mul:
            return "%s * %s" % self.operands
        else:
            return "Unsupported op %s" % self.op

    def __add__(self, other):
        if type(other) in ArithmeticExpression.CONST_TYPES:
            other = self._unpack_const(other)
            if type(self.operands[0]) in ArithmeticExpression.CONST_TYPES:
                return ArithmeticExpression(self.op, (self.operands[0] + other, self.operands[1], ))
            elif type(self.operands[1]) is int:
                return ArithmeticExpression(self.op, (self.operands[0], self.operands[1] + other,))
        return ArithmeticExpression(self.op, (self, other, ))

    def __sub__(self, other):
        if type(other) in ArithmeticExpression.CONST_TYPES:
            other = self._unpack_const(other)
            if type(self.operands[0]) is int:
                return ArithmeticExpression(self.op, (self.operands[0] - other, self.operands[1], ))
            elif type(self.operands[1]) is int:
                return ArithmeticExpression(self.op, (self.operands[0], self.operands[1] - other,))
        return ArithmeticExpression(self.op, (self, other, ))

    def __rsub__(self, other):
        if type(other) in ArithmeticExpression.CONST_TYPES:
            other = self._unpack_const(other)
            if type(self.operands[0]) is int:
                return ArithmeticExpression(self.op, other - (self.operands[0], self.operands[1], ))
            elif type(self.operands[1]) is int:
                return ArithmeticExpression(self.op, (self.operands[0], other - self.operands[1],))
        return ArithmeticExpression(self.op, (self, other, ))


    def __and__(self, other):
        if type(other) in ArithmeticExpression.CONST_TYPES:
            other = self._unpack_const(other)
            if type(self.operands[0]) is int:
                return ArithmeticExpression(self.op, (self.operands[0] & other, self.operands[1], ))
            elif type(self.operands[1]) is int:
                return ArithmeticExpression(self.op, (self.operands[0], self.operands[1] & other,))
        return ArithmeticExpression(self.op, (self, other, ))

    def __or__(self, other):
        if type(other) in ArithmeticExpression.CONST_TYPES:
            other = self._unpack_const(other)
            if type(self.operands[0]) is int:
                return ArithmeticExpression(self.op, (self.operands[0] | other, self.operands[1], ))
            elif type(self.operands[1]) is int:
                return ArithmeticExpression(self.op, (self.operands[0], self.operands[1] | other,))
        return ArithmeticExpression(self.op, (self, other, ))

    def __xor__(self, other):
        if type(other) in ArithmeticExpression.CONST_TYPES:
            other = self._unpack_const(other)
            if type(self.operands[0]) is int:
                return ArithmeticExpression(self.op, (self.operands[0] ^ other, self.operands[1], ))
            elif type(self.operands[1]) is int:
                return ArithmeticExpression(self.op, (self.operands[0], self.operands[1] ^ other,))
        return ArithmeticExpression(self.op, (self, other, ))


    def __lshift__(self, other):
        if type(other) in ArithmeticExpression.CONST_TYPES:
            other = self._unpack_const(other)
            if type(self.operands[0]) in ArithmeticExpression.CONST_TYPES:
                return ArithmeticExpression(self.op, (self.operands[0] << other, self.operands[1], ))
            elif type(self.operands[1]) is int:
                return ArithmeticExpression(self.op, (self.operands[0], self.operands[1] << other,))
        return ArithmeticExpression(self.op, (self, other, ))

    def __rlshift__(self, other):
        if type(other) in ArithmeticExpression.CONST_TYPES:
            other = self._unpack_const(other)
            if type(self.operands[0]) in ArithmeticExpression.CONST_TYPES:
                return ArithmeticExpression(self.op, (other << self.operands[0], self.operands[1], ))
            elif type(self.operands[1]) is int:
                return ArithmeticExpression(self.op, (self.operands[0], other << self.operands[1],))
        return ArithmeticExpression(self.op, ( other, self, ))

    def __rrshift__(self, other):
        if type(other) in ArithmeticExpression.CONST_TYPES:
            other = self._unpack_const(other)
            if type(self.operands[0]) in ArithmeticExpression.CONST_TYPES:
                return ArithmeticExpression(self.op, (other >> self.operands[0], self.operands[1], ))
            elif type(self.operands[1]) is int:
                return ArithmeticExpression(self.op, (self.operands[0], other >> self.operands[1],))
        return ArithmeticExpression(self.op, ( other, self, ))

    def __rshift__(self, other):
        if type(other) in ArithmeticExpression.CONST_TYPES:
            other = self._unpack_const(other)
            if type(self.operands[0]) in ArithmeticExpression.CONST_TYPES:
                return ArithmeticExpression(self.op, (self.operands[0] >> other, self.operands[1], ))
            elif type(self.operands[1]) is int:
                return ArithmeticExpression(self.op, (self.operands[0], self.operands[1] >> other,))
        return ArithmeticExpression(self.op, (self, other, ))


    @staticmethod
    def _unpack_const(expr):
        if type(expr) is int:
            return expr
        elif type(expr) is ailment.expression.Const:
            return expr.value
        raise NotImplementedError("Unsupported const expression type %s." % type(expr))

    @staticmethod
    def try_unpack_const(expr):
        try:
            return ArithmeticExpression._unpack_const(expr)
        except NotImplementedError:
            return expr


class RegisterOffset:

    __slots__ = ('_bits', 'reg', 'offset', )

    def __init__(self, bits, reg, offset):
        self._bits = bits
        self.reg = reg
        self.offset = offset

    @property
    def bits(self):
        return self._bits

    @property
    def symbolic(self):
        return type(self.offset) is not int

    def __repr__(self):
        if type(self.offset) is int:
            offset_str = '' if self.offset == 0 else "%+x" % self.offset
        else:
            offset_str = str(self.offset)
        return "%s%s" % (self.reg, offset_str)

    def __add__(self, other):
        if not self.symbolic and type(other) is int:
            # Keep things in concrete
            return RegisterOffset(self._bits, self.reg, self._to_signed(self.offset + other))
        else:
            if self.symbolic:
                return RegisterOffset(self._bits, self.reg, self.offset + other)
            else:
                # Convert to symbolic
                return RegisterOffset(self._bits, self.reg,
                                      ArithmeticExpression(ArithmeticExpression.Add, (self.offset, other, )))

    def __radd__(self, other):
        return self.__add__(other)

    def __sub__(self, other):
        if not self.symbolic and type(other) is int:
            return RegisterOffset(self._bits, self.reg, self._to_signed(self.offset - other))
        else:
            if self.symbolic:
                return RegisterOffset(self._bits, self.reg, self.offset - other)
            else:
                return RegisterOffset(self._bits, self.reg,
                                      ArithmeticExpression(ArithmeticExpression.Sub, (self.offset, other,)))

    def __rsub__(self, other):
        if not self.symbolic and type(other) is int:
            return RegisterOffset(self._bits, self.reg, self._to_signed(other - self.offset))
        else:
            if self.symbolic:
                return RegisterOffset(self._bits, self.reg, other - self.offset)
            else:
                return RegisterOffset(self._bits, self.reg,
                                      ArithmeticExpression(ArithmeticExpression.Sub, (other, self.offset, )))

    def __mul__(self, other):
        if not self.symbolic and type(other) is int:
            return RegisterOffset(self._bits, self.reg, self._to_signed(self.offset * other))
        else:
            if self.symbolic:
                return RegisterOffset(self._bits, self.reg, self.offset * other)
            else:
                return RegisterOffset(self._bits, self.reg,
                                      ArithmeticExpression(ArithmeticExpression.Mul, (self.offset, other, )))

    def __rmul__(self, other):
        if not self.symbolic and type(other) is int:
            return RegisterOffset(self._bits, self.reg, self._to_signed(other * self.offset))
        else:
            if self.symbolic:
                return RegisterOffset(self._bits, self.reg, self.offset * other)
            else:
                return RegisterOffset(self._bits, self.reg,
                                      ArithmeticExpression(ArithmeticExpression.Mul, (other, self.offset, )))

    def __and__(self, other):
        if not self.symbolic and type(other) is int:
            return RegisterOffset(self._bits, self.reg, self._to_signed(self.offset & other))
        else:
            if self.symbolic:
                return RegisterOffset(self._bits, self.reg, self.offset & other)
            else:
                return RegisterOffset(self._bits, self.reg,
                                      ArithmeticExpression(ArithmeticExpression.And, (self.offset, other,)))

    def __rand__(self, other):
        return self.__and__(other)

    def __or__(self, other):
        if not self.symbolic and type(other) is int:
            return RegisterOffset(self._bits, self.reg, self._to_signed(self.offset | other))
        else:
            if self.symbolic:
                return RegisterOffset(self._bits, self.reg, self.offset | other)
            else:
                return RegisterOffset(self._bits, self.reg,
                                      ArithmeticExpression(ArithmeticExpression.Or, (self.offset, other,)))

    def __ror__(self, other):
        return self.__or__(other)

    def __xor__(self, other):
        if not self.symbolic and type(other) is int:
            return RegisterOffset(self._bits, self.reg, self._to_signed(self.offset | other))
        else:
            if self.symbolic:
                return RegisterOffset(self._bits, self.reg, self.offset ^ other)
            else:
                return RegisterOffset(self._bits, self.reg,
                                      ArithmeticExpression(ArithmeticExpression.Xor, (self.offset, other,)))

    def __rxor__(self, other):
        return self.__xor__(other)

    def __floordiv__(self, other):
        # this should never happen. returning self is obviously incorrect.
        return self

    def __rshift__(self, other):
        if not self.symbolic and type(other) is int:
            return RegisterOffset(self._bits, self.reg, self._to_signed(self.offset >> other))
        else:
            if self.symbolic:
                return RegisterOffset(self._bits, self.reg, self.offset >> other)
            else:
                return RegisterOffset(self._bits, self.reg,
                                      ArithmeticExpression(ArithmeticExpression.RShift, (self.offset, other,)))

    def __rrshift__(self, other):
        if not self.symbolic and type(other) is int:
            return RegisterOffset(self._bits, self.reg, self._to_signed(other >> self.offset))
        else:
            if self.symbolic:
                return RegisterOffset(self._bits, self.reg, other >> self.offset)
            else:
                return RegisterOffset(self._bits, self.reg,
                                      ArithmeticExpression(ArithmeticExpression.RShift, (other, self.offset,)))

    def __lshift__(self, other):
        if not self.symbolic and type(other) is int:
            return RegisterOffset(self._bits, self.reg, self._to_signed(self.offset << other))
        else:
            if self.symbolic:
                return RegisterOffset(self._bits, self.reg, self.offset << other)
            else:
                return RegisterOffset(self._bits, self.reg,
                                      ArithmeticExpression(ArithmeticExpression.LShift, (self.offset, other,)))
    def __rlshift__(self, other):
        if not self.symbolic and type(other) is int:
            return RegisterOffset(self._bits, self.reg, self._to_signed(other << self.offset))
        else:
            if self.symbolic:
                return RegisterOffset(self._bits, self.reg, other << self.offset)
            else:
                return RegisterOffset(self._bits, self.reg,
                                      ArithmeticExpression(ArithmeticExpression.LShift, (other, self.offset,)))

    def __neg__(self):
        if not self.symbolic:
            return RegisterOffset(self._bits, self.reg, self._to_signed(-self.offset))
        else:
            return RegisterOffset(self._bits, self.reg, -self.offset)

    def __invert__(self):
        if not self.symbolic:
            return RegisterOffset(self._bits, self.reg, self._to_signed(~self.offset))
        else:
            return RegisterOffset(self._bits, self.reg, ~self.offset)

    def _to_signed(self, n):
        if n >= 2 ** (self._bits - 1):
            return n - 2 ** self._bits
        return n


class SpOffset(RegisterOffset):

    __slots__ = ('is_base', )

    def __init__(self, bits, offset, is_base=False):
        super(SpOffset, self).__init__(bits, 'sp', offset)
        self.is_base = is_base

    def __repr__(self):
        if type(self.offset) is int:
            offset_str = '' if self.offset == 0 else "%+x" % self.offset
        else:
            offset_str = str(self.offset)
        return "%s%s" % ('BP' if self.is_base else 'SP', offset_str)

    def __add__(self, other):
        other = ArithmeticExpression.try_unpack_const(other)
        if not self.symbolic and type(other) is int:
            return SpOffset(self._bits, self._to_signed(self.offset + other))
        else:
            if self.symbolic:
                return SpOffset(self._bits, self.offset + other)
            else:
                return SpOffset(self._bits, ArithmeticExpression(ArithmeticExpression.Add, (self.offset, other, )))

    def __sub__(self, other):
        other = ArithmeticExpression.try_unpack_const(other)
        if not self.symbolic and type(other) is int:
            return SpOffset(self._bits, self._to_signed(self.offset - other))
        else:
            if self.symbolic:
                return SpOffset(self._bits, self.offset - other)
            else:
                return SpOffset(self._bits, ArithmeticExpression(ArithmeticExpression.Sub, (self.offset, other, )))

    def __and__(self, other):
        other = ArithmeticExpression.try_unpack_const(other)
        if is_alignment_mask(other):
            # stack pointer alignment. ignore it.
            return SpOffset(self._bits, self.offset)
        else:
            return SpOffset(self._bits, ArithmeticExpression(ArithmeticExpression.And, (self, other, )))

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
