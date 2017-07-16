
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

    def replace(self, old_expr, new_expr):
        if self is old_expr:
            r = True
            replaced = new_expr
        elif not isinstance(self, Atom):
            r, replaced = self.replace(old_expr, new_expr)
        else:
            r, replaced = False, self

        return r, replaced

    def __add__(self, other):
        return BinaryOp(None, 'Add', [ self, other ])

    def __sub__(self, other):
        return BinaryOp(None, 'Sub', [ self, other ])


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

    @property
    def sign_bit(self):
        return self.value >> (self.bits - 1)


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

    def __str__(self):
        return "(%s %s)" % (self.op, str(self.operand))

    def replace(self, old_expr, new_expr):
        r, replaced_operand = self.operand.replace(old_expr, new_expr)

        if r:
            return True, UnaryOp(self.idx, self.op, replaced_operand, **self.tags)
        else:
            return False, self


class Convert(UnaryOp):
    def __init__(self, idx, from_bits, to_bits, operand, **kwargs):
        super(Convert, self).__init__(idx, 'Convert', operand, **kwargs)

        self.from_bits = from_bits
        self.to_bits = to_bits

    def __str__(self):
        return "Conv(%d->%d, %s)" % (self.from_bits, self.to_bits, self.operand)

    def replace(self, old_expr, new_expr):
        r, replaced_operand = self.operand.replace(old_expr, new_expr)

        if r:
            return True, Convert(self.idx, self.from_bits, self.to_bits, replaced_operand, **self.tags)
        else:
            return False, self


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

    def replace(self, old_expr, new_expr):
        r0, replaced_operand_0 = self.operands[0].replace(old_expr, new_expr)
        r1, replaced_operand_1 = self.operands[1].replace(old_expr, new_expr)

        if r0 or r1:
            return True, BinaryOp(self.idx, self.op, [ replaced_operand_0, replaced_operand_1 ], **self.tags)
        else:
            return False, self


class Load(Expression):
    def __init__(self, idx, addr, endness, **kwargs):
        super(Load, self).__init__(idx, **kwargs)

        self.addr = addr
        self.endness = endness

    def __str__(self):
        return "Load(addr=%s, endness=%s)" % (self.addr, self.endness)

    def has_atom(self, atom):
        if type(self.addr) in (int, long):
            return False
        return self.addr.has_atom(atom)

    def replace(self, old_expr, new_expr):
        r, replaced_addr = self.addr.replace(old_expr, new_expr)

        if r:
            return True, Load(self.idx, replaced_addr, self.endness, **self.tags)
        else:
            return False, self


class DirtyExpression(Expression):
    def __init__(self, idx, dirty_expr, **kwargs):
        super(DirtyExpression, self).__init__(idx, **kwargs)
        self.dirty_expr = dirty_expr

    def __repr__(self):
        return "DirtyStatement (%s)" % type(self.dirty_expr)

    def __str__(self):
        return "[D] %s" % str(self.dirty_expr)
