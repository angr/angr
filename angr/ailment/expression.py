
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

    @property
    def size(self):
        return self.bits // 8

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "%#x<%d>" % (self.value, self.bits)

    def __eq__(self, other):
        return type(self) is type(other) and \
            self.value == other.value and \
            self.bits == other.bits

    def __hash__(self):
        return hash((self.value, self.bits))

    @property
    def sign_bit(self):
        return self.value >> (self.bits - 1)


class Tmp(Atom):
    def __init__(self, idx, variable, tmp_idx, bits, **kwargs):
        super(Tmp, self).__init__(idx, variable, **kwargs)

        self.tmp_idx = tmp_idx
        self.bits = bits

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "t%d" % self.tmp_idx

    def __eq__(self, other):
        return type(self) is type(other) and \
            self.tmp_idx == other.tmp_idx and \
            self.bits == other.bits

    def __hash__(self):
        return hash(('tmp', self.tmp_idx, self.bits))


class Register(Atom):
    def __init__(self, idx, variable, reg_offset, bits, **kwargs):
        super(Register, self).__init__(idx, variable, **kwargs)

        self.reg_offset = reg_offset
        self.bits = bits

    @property
    def size(self):
        return self.bits // 8

    def __repr__(self):
        return str(self)

    def __str__(self):
        if self.variable is None:
            if hasattr(self, 'reg_name'):
                return "%s<%d>" % (self.reg_name, self.bits // 8)
            else:
                return "reg_%d<%d>" % (self.reg_offset, self.bits // 8)
        else:
            return "%s" % str(self.variable.name)

    def __eq__(self, other):
        return type(self) is type(other) and \
               self.reg_offset == other.reg_offset and \
            self.bits == other.bits

    def __hash__(self):
        return hash(('reg', self.reg_offset, self.bits))


class Op(Expression):
    def __init__(self, idx, op, **kwargs):
        super(Op, self).__init__(idx, **kwargs)
        self.op = op


class UnaryOp(Op):
    def __init__(self, idx, op, operand, **kwargs):
        super(UnaryOp, self).__init__(idx, op, **kwargs)

        self.operand = operand
        self.bits = operand.bits

    def __str__(self):
        return "(%s %s)" % (self.op, str(self.operand))

    def __repr__(self):
        return str(self)

    def replace(self, old_expr, new_expr):
        r, replaced_operand = self.operand.replace(old_expr, new_expr)

        if r:
            return True, UnaryOp(self.idx, self.op, replaced_operand, **self.tags)
        else:
            return False, self


class Convert(UnaryOp):
    def __init__(self, idx, from_bits, to_bits, is_signed, operand, **kwargs):
        super(Convert, self).__init__(idx, 'Convert', operand, **kwargs)

        self.from_bits = from_bits
        self.to_bits = to_bits
        # override the size
        self.bits = to_bits
        self.is_signed = is_signed

    def __str__(self):
        return "Conv(%d->%d, %s)" % (self.from_bits, self.to_bits, self.operand)

    def __repr__(self):
        return str(self)

    def replace(self, old_expr, new_expr):
        r, replaced_operand = self.operand.replace(old_expr, new_expr)

        if r:
            return True, Convert(self.idx, self.from_bits, self.to_bits, self.is_signed, replaced_operand, **self.tags)
        else:
            return False, self


class BinaryOp(Op):
    OPSTR_MAP = {
        'Add': '+',
        'Sub': '-',
        'CmpEQ': '==',
        'CmpNE': '!=',
        'CmpLT': '<',
        'CmpLE': '<=',
        'CmpGT': '>',
        'CmpGE': '>=',
    }

    def __init__(self, idx, op, operands, **kwargs):
        super(BinaryOp, self).__init__(idx, op, **kwargs)

        assert len(operands) == 2
        self.operands = operands
        self.bits = operands[0].bits if type(operands[0]) is not int else operands[1].bits

        # TODO: sanity check of operands' sizes for some ops
        # assert self.bits == operands[1].bits

    def __str__(self):
        op_str = self.OPSTR_MAP.get(self.op, self.op)
        return "(%s %s %s)" % (str(self.operands[0]), op_str, str(self.operands[1]))

    def __repr__(self):
        return "%s(%s, %s)" % (self.op, self.operands[0], self.operands[1])

    def __eq__(self, other):
        return type(other) is BinaryOp and \
               self.operands == other.operands and \
               self.op == other.op and \
               self.bits == other.bits

    def __hash__(self):
        return hash((self.op, tuple(self.operands), self.bits))

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
    def __init__(self, idx, addr, size, endness, **kwargs):
        super(Load, self).__init__(idx, **kwargs)

        self.addr = addr
        self.size = size
        self.endness = endness

    @property
    def bits(self):
        return self.size * 8

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "Load(addr=%s, size=%d, endness=%s)" % (self.addr, self.size, self.endness)

    def has_atom(self, atom):
        if type(self.addr) is int:
            return False
        return self.addr.has_atom(atom)

    def replace(self, old_expr, new_expr):
        r, replaced_addr = self.addr.replace(old_expr, new_expr)

        if r:
            return True, Load(self.idx, replaced_addr, self.size, self.endness, **self.tags)
        else:
            return False, self

    def __eq__(self, other):
        return type(other) is Load and \
               self.addr == other.addr and \
               self.size == other.size and \
               self.endness == other.endness

    def __hash__(self):
        return hash(('Load', self.addr, self.size, self.endness))


class ITE(Expression):
    def __init__(self, idx, cond, iffalse, iftrue, **kwargs):
        super(ITE, self).__init__(idx, **kwargs)

        self.cond = cond
        self.iffalse = iffalse
        self.iftrue = iftrue
        self.bits = iftrue.bits

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "((%s) ? (%s) : (%s))" % (self.cond, self.iftrue, self.iffalse)

    def has_atom(self, atom):
        return self.cond.has_atom(atom) or self.iftrue.has_atom(atom) or self.iffalse.has_atom(atom)

    def replace(self, old_expr, new_expr):
        cond_replaced, new_cond = self.cond.replace(old_expr, new_expr)
        iffalse_replaced, new_iffalse = self.iffalse.replace(old_expr, new_expr)
        iftrue_replaced, new_iftrue = self.iftrue.replace(old_expr, new_expr)
        replaced = cond_replaced or iftrue_replaced or iffalse_replaced

        if replaced:
            return True, ITE(self.idx, new_cond, new_iffalse, new_iftrue, **self.tags)
        else:
            return False, self


class DirtyExpression(Expression):
    def __init__(self, idx, dirty_expr, **kwargs):
        super(DirtyExpression, self).__init__(idx, **kwargs)
        self.dirty_expr = dirty_expr

    def replace(self, old_expr, new_expr):
        return False, self

    def __repr__(self):
        return "DirtyExpression (%s)" % type(self.dirty_expr)

    def __str__(self):
        return "[D] %s" % str(self.dirty_expr)


#
# Special (Dummy) expressions
#


class BasePointerOffset(Expression):
    def __init__(self, idx, bits, base, offset, **kwargs):
        super().__init__(idx, **kwargs)
        self.bits = bits
        self.base = base
        self.offset = offset

    @property
    def size(self):
        return self.bits // 8

    def __repr__(self):
        if self.offset is None:
            return "BaseOffset(%s)" % self.base
        return "BaseOffset(%s, %d)" % (self.base, self.offset)

    def __str__(self):
        if self.offset is None:
            return str(self.base)
        return "%s%+d" % (self.base, self.offset)

    def __eq__(self, other):
        return type(other) is type(self) and \
               self.bits == other.bits and \
               self.base == other.base and \
               self.offset == other.offset

    def __hash__(self):
        return hash((self.bits, self.base, self.offset))

    def replace(self, old_expr, new_expr):
        if isinstance(self.base, Expression):
            base_replaced, new_base = self.base.replace(old_expr, new_expr)
        else:
            base_replaced, new_base = False, self.base
        if isinstance(self.offset, Expression):
            offset_replaced, new_offset = self.offset.replace(old_expr, new_expr)
        else:
            offset_replaced, new_offset = False, self.offset

        if base_replaced or offset_replaced:
            return True, BasePointerOffset(self.idx, self.bits, new_base, new_offset, **self.tags)
        return False, self

    def copy(self):
        return BasePointerOffset(self.idx, self.bits, self.base, self.offset, **self.tags)


class StackBaseOffset(BasePointerOffset):
    def __init__(self, idx, bits, offset, **kwargs):
        super().__init__(idx, bits, 'stack_base', offset, **kwargs)

    def copy(self):
        return StackBaseOffset(self.idx, self.bits, self.offset, **self.tags)
