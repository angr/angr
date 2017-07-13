
from .tagged_object import TaggedObject


class Expression(TaggedObject):
    """
    The base class of all AIL expressions.
    """
    def __init__(self, idx, **kwargs):
        super(Expression, self).__init__(**kwargs)
        self.idx = idx

    def __repr__(self):
        raise NotImplementedError()

    def has_atom(self, atom):
        return False


class Atom(Expression):
    def __init__(self, idx, variable, **kwargs):
        super(Atom, self).__init__(idx, **kwargs)
        self.variable = variable

    def __repr__(self):
        return "Atom (%d)" % self.idx


class Const(Atom):
    def __init__(self, idx, variable, value, bits, **kwargs):
        super(Const, self).__init__(idx, variable, **kwargs)

        self.value = value
        self.bits = bits

    def __str__(self):
        return "%#x<%d>" % (self.value, self.bits)

    def __eq__(self, other):
        return type(self) is type(other) and \
            self.value == other.value and \
            self.bits == other.bits


class Tmp(Atom):
    def __init__(self, idx, variable, tmp_idx, bits, **kwargs):
        super(Tmp, self).__init__(idx, variable, **kwargs)

        self.tmp_idx = tmp_idx
        self.bits = bits

    def __str__(self):
        return "t%d" % self.tmp_idx

    def __eq__(self, other):
        return type(self) is type(other) and \
            self.tmp_idx == other.tmp_idx and \
            self.bits == other.bits

    def __hash__(self):
        return hash((self.tmp_idx, self.bits))


class Register(Atom):
    def __init__(self, idx, variable, register_offset, bits, **kwargs):
        super(Register, self).__init__(idx, variable, **kwargs)

        self.register_offset = register_offset
        self.bits = bits

    def __str__(self):
        if hasattr(self, 'reg_name'):
            return "%s<%d>" % (self.reg_name, self.bits / 8)
        else:
            return "reg_%d<%d>" % (self.register_offset, self.bits / 8)

    def __eq__(self, other):
        return type(self) is type(other) and \
            self.register_offset == other.register_offset and \
            self.bits == other.bits


class Op(Expression):
    def __init__(self, idx, op, **kwargs):
        super(Op, self).__init__(idx, **kwargs)
        self.op = op


class UnaryOp(Op):
    def __init__(self, idx, op, operand, **kwargs):
        super(UnaryOp, self).__init__(idx, op, **kwargs)

        self.operand = operand


class BinaryOp(Op):
    def __init__(self, idx, op, operands, **kwargs):
        super(BinaryOp, self).__init__(idx, op, **kwargs)

        assert len(operands) == 2
        self.operands = operands

    def __str__(self):
        return "(%s %s %s)" % (str(self.operands[0]), self.op, str(self.operands[1]))

    def has_atom(self, atom):
        for op in self.operands:
            if op == atom or op.has_atom(atom):
                return True
        return False


class DirtyExpression(Expression):
    def __init__(self, idx, dirty_expr, **kwargs):
        super(DirtyExpression, self).__init__(idx, **kwargs)
        self.dirty_expr = dirty_expr

    def __repr__(self):
        return "DirtyStatement (%s)" % type(self.dirty_expr)

    def __str__(self):
        return "[D] %s" % str(self.dirty_expr)
