# pylint:disable=arguments-renamed,isinstance-second-argument-not-valid-type,missing-class-docstring
from typing import Optional, List, TYPE_CHECKING

try:
    import claripy
except ImportError:
    claripy = None

from .tagged_object import TaggedObject
from .utils import get_bits, stable_hash, is_none_or_likeable

if TYPE_CHECKING:
    from .statement import Statement


class Expression(TaggedObject):
    """
    The base class of all AIL expressions.
    """

    __slots__ = ("depth",)

    def __init__(self, idx, depth, **kwargs):
        super().__init__(idx, **kwargs)
        self.depth = depth

    def __repr__(self):
        raise NotImplementedError()

    def has_atom(self, atom, identity=True):
        if identity:
            return self is atom
        else:
            return self.likes(atom)

    def __eq__(self, other):
        return type(self) is type(other) and self.likes(other) and self.idx == other.idx

    def likes(self, atom):  # pylint:disable=unused-argument,no-self-use
        raise NotImplementedError()

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
        return BinaryOp(None, "Add", [self, other], False)

    def __sub__(self, other):
        return BinaryOp(None, "Sub", [self, other], False)


class Atom(Expression):
    __slots__ = (
        "variable",
        "variable_offset",
    )

    def __init__(self, idx, variable, variable_offset=0, **kwargs):
        super().__init__(idx, 0, **kwargs)
        self.variable = variable
        self.variable_offset = variable_offset

    def __repr__(self):
        return "Atom (%d)" % self.idx

    def copy(self):  # pylint:disable=no-self-use
        return NotImplementedError()


class Const(Atom):
    __slots__ = (
        "value",
        "bits",
    )

    def __init__(self, idx, variable, value, bits, **kwargs):
        super().__init__(idx, variable, **kwargs)

        self.value = value
        self.bits = bits

    @property
    def size(self):
        return self.bits // 8

    def __repr__(self):
        return str(self)

    def __str__(self):
        try:
            return "%#x<%d>" % (self.value, self.bits)
        except TypeError:
            return "%f<%d>" % (self.value, self.bits)

    def likes(self, other):
        return type(self) is type(other) and self.value == other.value and self.bits == other.bits

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((self.value, self.bits))

    @property
    def sign_bit(self):
        return self.value >> (self.bits - 1)

    def copy(self) -> "Const":
        return Const(self.idx, self.variable, self.value, self.bits, **self.tags)


class Tmp(Atom):
    __slots__ = (
        "tmp_idx",
        "bits",
    )

    def __init__(self, idx, variable, tmp_idx, bits, **kwargs):
        super().__init__(idx, variable, **kwargs)

        self.tmp_idx = tmp_idx
        self.bits = bits

    @property
    def size(self):
        return self.bits // 8

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "t%d" % self.tmp_idx

    def likes(self, other):
        return type(self) is type(other) and self.tmp_idx == other.tmp_idx and self.bits == other.bits

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash(("tmp", self.tmp_idx, self.bits))

    def copy(self) -> "Tmp":
        return Tmp(self.idx, self.variable, self.tmp_idx, self.bits, **self.tags)


class Register(Atom):
    __slots__ = (
        "reg_offset",
        "bits",
    )

    def __init__(self, idx, variable, reg_offset, bits, **kwargs):
        super().__init__(idx, variable, **kwargs)

        self.reg_offset = reg_offset
        self.bits = bits

    @property
    def size(self):
        return self.bits // 8

    def likes(self, atom):
        return type(self) is type(atom) and self.reg_offset == atom.reg_offset and self.bits == atom.bits

    def __repr__(self):
        return str(self)

    def __str__(self):
        if hasattr(self, "reg_name"):
            return "%s<%d>" % (self.reg_name, self.bits // 8)
        if self.variable is None:
            return "reg_%d<%d>" % (self.reg_offset, self.bits // 8)
        else:
            return "%s" % str(self.variable.name)

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash(("reg", self.reg_offset, self.bits, self.idx))

    def copy(self) -> "Register":
        return Register(self.idx, self.variable, self.reg_offset, self.bits, **self.tags)


class Op(Expression):
    __slots__ = ("op",)

    def __init__(self, idx, depth, op, **kwargs):
        super().__init__(idx, depth, **kwargs)
        self.op = op

    @property
    def verbose_op(self):
        return self.op


class UnaryOp(Op):
    __slots__ = (
        "operand",
        "bits",
        "variable",
        "variable_offset",
    )

    def __init__(self, idx, op, operand, variable=None, variable_offset=None, **kwargs):
        super().__init__(idx, (operand.depth if isinstance(operand, Expression) else 0) + 1, op, **kwargs)

        self.operand = operand
        self.bits = operand.bits
        self.variable = variable
        self.variable_offset = variable_offset

    def __str__(self):
        return f"({self.op} {str(self.operand)})"

    def __repr__(self):
        return str(self)

    def likes(self, other):
        return (
            type(other) is UnaryOp and self.op == other.op and self.bits == other.bits and self.operand == other.operand
        )

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((self.op, self.operand, self.bits))

    def replace(self, old_expr, new_expr):
        r, replaced_operand = self.operand.replace(old_expr, new_expr)

        if r:
            return True, UnaryOp(self.idx, self.op, replaced_operand, **self.tags)
        else:
            return False, self

    @property
    def operands(self):
        return [self.operand]

    @property
    def size(self):
        return self.bits // 8

    def copy(self) -> "UnaryOp":
        return UnaryOp(
            self.idx, self.op, self.operand, variable=self.variable, variable_offset=self.variable_offset, **self.tags
        )

    def has_atom(self, atom, identity=True):
        if super().has_atom(atom, identity=identity):
            return True
        return self.operand.has_atom(atom, identity=identity)


class Convert(UnaryOp):
    TYPE_INT = 0
    TYPE_FP = 1

    __slots__ = (
        "from_bits",
        "to_bits",
        "is_signed",
        "from_type",
        "to_type",
        "rounding_mode",
    )

    def __init__(
        self,
        idx,
        from_bits,
        to_bits,
        is_signed,
        operand,
        from_type=TYPE_INT,
        to_type=TYPE_INT,
        rounding_mode=None,
        **kwargs,
    ):
        super().__init__(idx, "Convert", operand, **kwargs)

        self.from_bits = from_bits
        self.to_bits = to_bits
        # override the size
        self.bits = to_bits
        self.is_signed = is_signed
        self.from_type = from_type
        self.to_type = to_type
        self.rounding_mode = rounding_mode

    def __str__(self):
        return "Conv(%d->%s%d, %s)" % (self.from_bits, "s" if self.is_signed else "", self.to_bits, self.operand)

    def __repr__(self):
        return str(self)

    def likes(self, other):
        return (
            type(other) is Convert
            and self.from_bits == other.from_bits
            and self.to_bits == other.to_bits
            and self.bits == other.bits
            and self.is_signed == other.is_signed
            and self.operand.likes(other.operand)
            and self.from_type == other.from_type
            and self.to_type == other.to_type
            and self.rounding_mode == other.rounding_mode
        )

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash(
            (
                self.operand,
                self.from_bits,
                self.to_bits,
                self.bits,
                self.is_signed,
                self.from_type,
                self.to_type,
                self.rounding_mode,
            )
        )

    def replace(self, old_expr, new_expr):
        if self.operand == old_expr:
            r0 = True
            replaced_operand = new_expr
        else:
            r0, replaced_operand = self.operand.replace(old_expr, new_expr)

        if self.rounding_mode is not None:
            if self.rounding_mode.likes(old_expr):
                r1 = True
                replaced_rm = new_expr
            else:
                r1, replaced_rm = self.rounding_mode.replace(old_expr, new_expr)
        else:
            r1 = False
            replaced_rm = None

        if r0 or r1:
            return True, Convert(
                self.idx,
                self.from_bits,
                self.to_bits,
                self.is_signed,
                replaced_operand if replaced_operand is not None else self.operand,
                from_type=self.from_type,
                to_type=self.to_type,
                rounding_mode=replaced_rm if replaced_rm is not None else self.rounding_mode,
                **self.tags,
            )
        else:
            return False, self

    def copy(self) -> "Convert":
        return Convert(
            self.idx,
            self.from_bits,
            self.to_bits,
            self.is_signed,
            self.operand,
            from_type=self.from_type,
            to_type=self.to_type,
            rounding_mode=self.rounding_mode,
            **self.tags,
        )


class Reinterpret(UnaryOp):
    __slots__ = (
        "from_bits",
        "from_type",
        "to_bits",
        "to_type",
    )

    def __init__(self, idx, from_bits: int, from_type: str, to_bits: int, to_type: str, operand, **kwargs):
        super().__init__(idx, "Reinterpret", operand, **kwargs)

        assert (from_type == "I" and to_type == "F") or (from_type == "F" and to_type == "I")

        self.from_bits = from_bits
        self.from_type = from_type
        self.to_bits = to_bits
        self.to_type = to_type

        self.bits = self.to_bits

    def __str__(self):
        return f"Reinterpret({self.from_type}{self.from_bits}->{self.to_type}{self.to_bits}, {self.operand})"

    def __repr__(self):
        return str(self)

    def likes(self, other):
        return (
            type(other) is Reinterpret
            and self.from_bits == other.from_bits
            and self.from_type == other.from_type
            and self.to_bits == other.to_bits
            and self.to_type == other.to_type
            and self.operand == other.operand
        )

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash(
            (
                self.operand,
                self.from_bits,
                self.from_type,
                self.to_bits,
                self.to_type,
            )
        )

    def replace(self, old_expr, new_expr):
        if self.operand == old_expr:
            r = True
            replaced_operand = new_expr
        else:
            r, replaced_operand = self.operand.replace(old_expr, new_expr)

        if r:
            return True, Reinterpret(
                self.idx, self.from_bits, self.from_type, self.to_bits, self.to_type, replaced_operand, **self.tags
            )
        else:
            return False, self

    def copy(self) -> "Reinterpret":
        return Reinterpret(
            self.idx, self.from_bits, self.from_type, self.to_bits, self.to_type, self.operand, **self.tags
        )


class BinaryOp(Op):
    __slots__ = (
        "operands",
        "bits",
        "signed",
        "variable",
        "variable_offset",
        "floating_point",
        "rounding_mode",
    )

    OPSTR_MAP = {
        "Add": "+",
        "AddF": "+",
        "Sub": "-",
        "SubF": "-",
        "Mul": "*",
        "MulF": "*",
        "Div": "/",
        "DivF": "/",
        "DivMod": "/m",
        "Xor": "^",
        "And": "&",
        "LogicalAnd": "&&",
        "Or": "|",
        "LogicalOr": "||",
        "Shl": "<<",
        "Shr": ">>",
        "Sar": ">>a",
        "CmpF": "CmpF",
        "CmpEQ": "==",
        "CmpNE": "!=",
        "CmpLT": "<",
        "CmpLE": "<=",
        "CmpGT": ">",
        "CmpGE": ">=",
        "CmpLTs": "<s",
        "CmpLEs": "<=s",
        "CmpGTs": ">s",
        "CmpGEs": ">=s",
        "Concat": "CONCAT",
    }

    COMPARISON_NEGATION = {
        "CmpEQ": "CmpNE",
        "CmpNE": "CmpEQ",
        "CmpLT": "CmpGE",
        "CmpGE": "CmpLT",
        "CmpLE": "CmpGT",
        "CmpGT": "CmpLE",
        "CmpLTs": "CmpGEs",
        "CmpGEs": "CmpLTs",
        "CmpLEs": "CmpGTs",
        "CmpGTs": "CmpLEs",
    }

    def __init__(
        self,
        idx,
        op,
        operands,
        signed,
        variable=None,
        variable_offset=None,
        bits=None,
        floating_point=False,
        rounding_mode=None,
        **kwargs,
    ):
        depth = (
            max(
                operands[0].depth if isinstance(operands[0], Expression) else 0,
                operands[1].depth if isinstance(operands[1], Expression) else 0,
            )
            + 1
        )
        super().__init__(idx, depth, op, **kwargs)

        assert len(operands) == 2
        self.operands = operands

        if bits is not None:
            self.bits = bits
        elif self.op == "CmpF":
            self.bits = 32  # floating point comparison
        elif self.op.startswith("Cmp"):
            self.bits = 1
        elif self.op == "Concat":
            self.bits = get_bits(operands[0]) + get_bits(operands[1])
        else:
            self.bits = get_bits(operands[0]) if type(operands[0]) is not int else get_bits(operands[1])
        self.signed = signed
        self.variable = variable
        self.variable_offset = variable_offset
        self.floating_point = floating_point
        self.rounding_mode = rounding_mode

        # TODO: sanity check of operands' sizes for some ops
        # assert self.bits == operands[1].bits

    def __str__(self):
        op_str = self.OPSTR_MAP.get(self.verbose_op, self.verbose_op)
        return f"({str(self.operands[0])} {op_str} {str(self.operands[1])})"

    def __repr__(self):
        return f"{self.verbose_op}({self.operands[0]}, {self.operands[1]})"

    def likes(self, other):
        return (
            type(other) is BinaryOp
            and self.op == other.op
            and self.bits == other.bits
            and self.signed == other.signed
            and is_none_or_likeable(self.operands, other.operands, is_list=True)
            and self.floating_point == other.floating_point
            and self.rounding_mode == other.rounding_mode
        )

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash(
            (self.op, tuple(self.operands), self.bits, self.signed, self.floating_point, self.rounding_mode)
        )

    def has_atom(self, atom, identity=True):
        if super().has_atom(atom, identity=identity):
            return True

        for op in self.operands:
            if identity and op == atom:
                return True
            if not identity and isinstance(op, Expression) and op.likes(atom):
                return True
            if isinstance(op, Expression) and op.has_atom(atom, identity=identity):
                return True

        if self.rounding_mode is not None:
            if identity and self.rounding_mode == atom:
                return True
            if not identity and isinstance(self.rounding_mode, Atom) and self.rounding_mode.likes(atom):
                return True
            if isinstance(self.rounding_mode, Atom) and self.rounding_mode.has_atom(atom, identity=identity):
                return True

        return False

    def replace(self, old_expr, new_expr):
        if self.operands[0] == old_expr:
            r0 = True
            replaced_operand_0 = new_expr
        elif isinstance(self.operands[0], Expression):
            r0, replaced_operand_0 = self.operands[0].replace(old_expr, new_expr)
        else:
            r0, replaced_operand_0 = False, None

        if self.operands[1] == old_expr:
            r1 = True
            replaced_operand_1 = new_expr
        elif isinstance(self.operands[1], Expression):
            r1, replaced_operand_1 = self.operands[1].replace(old_expr, new_expr)
        else:
            r1, replaced_operand_1 = False, None

        if self.rounding_mode is not None:
            if self.rounding_mode == old_expr:
                r2 = True
                replaced_rm = new_expr
            elif isinstance(self.rounding_mode, Expression):
                r2, replaced_rm = self.rounding_mode.replace(old_expr, new_expr)
            else:
                r2, replaced_rm = False, None

        if r0 or r1:
            return True, BinaryOp(
                self.idx,
                self.op,
                [replaced_operand_0, replaced_operand_1],
                self.signed,
                bits=self.bits,
                floating_point=self.floating_point,
                rounding_mode=self.rounding_mode,
                **self.tags,
            )
        else:
            return False, self

    @property
    def verbose_op(self):
        op = self.op
        if self.floating_point:
            op += "F"
        else:
            if self.signed:
                op += "s"
        return op

    @property
    def size(self):
        return self.bits // 8

    def copy(self) -> "BinaryOp":
        return BinaryOp(
            self.idx,
            self.op,
            self.operands[::],
            self.signed,
            variable=self.variable,
            variable_offset=self.variable_offset,
            bits=self.bits,
            floating_point=self.floating_point,
            rounding_mode=self.rounding_mode,
            **self.tags,
        )


class TernaryOp(Op):
    OPSTR_MAP = {}

    __slots__ = (
        "operands",
        "bits",
    )

    def __init__(self, idx, op, operands, bits=None, **kwargs):
        depth = (
            max(
                operands[0].depth if isinstance(operands[0], Expression) else 0,
                operands[1].depth if isinstance(operands[1], Expression) else 0,
                operands[2].depth if isinstance(operands[1], Expression) else 0,
            )
            + 1
        )
        super().__init__(idx, depth, op, **kwargs)

        assert len(operands) == 3
        self.operands = operands
        self.bits = bits

    def __str__(self):
        return f"{self.verbose_op}({self.operands[0]}, {self.operands[1]}, {self.operands[2]})"

    def __repr__(self):
        return f"{self.verbose_op}({self.operands[0]}, {self.operands[1]}, {self.operands[2]})"

    def likes(self, other):
        return (
            type(other) is TernaryOp
            and self.op == other.op
            and self.bits == other.bits
            and self.operands == other.operands
        )

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((self.op, tuple(self.operands), self.bits))

    def has_atom(self, atom, identity=True):
        if super().has_atom(atom, identity=identity):
            return True

        for op in self.operands:
            if identity and op == atom:
                return True
            if not identity and isinstance(op, Atom) and op.likes(atom):
                return True
            if isinstance(op, Atom) and op.has_atom(atom, identity=identity):
                return True
        return False

    def replace(self, old_expr, new_expr):
        if self.operands[0] == old_expr:
            r0 = True
            replaced_operand_0 = new_expr
        elif isinstance(self.operands[0], Expression):
            r0, replaced_operand_0 = self.operands[0].replace(old_expr, new_expr)
        else:
            r0, replaced_operand_0 = False, None

        if self.operands[1] == old_expr:
            r1 = True
            replaced_operand_1 = new_expr
        elif isinstance(self.operands[1], Expression):
            r1, replaced_operand_1 = self.operands[1].replace(old_expr, new_expr)
        else:
            r1, replaced_operand_1 = False, None

        if self.operands[2] == old_expr:
            r2 = True
            replaced_operand_2 = new_expr
        elif isinstance(self.operands[2], Expression):
            r2, replaced_operand_2 = self.operands[2].replace(old_expr, new_expr)
        else:
            r2, replaced_operand_2 = False, None

        if r0 or r1 or r2:
            return True, TernaryOp(
                self.idx,
                self.op,
                [replaced_operand_0, replaced_operand_1, replaced_operand_2],
                bits=self.bits,
                **self.tags,
            )
        else:
            return False, self

    @property
    def verbose_op(self):
        return self.op

    @property
    def size(self):
        return self.bits // 8

    def copy(self) -> "TernaryOp":
        return TernaryOp(self.idx, self.op, self.operands[::], bits=self.bits, **self.tags)


class Load(Expression):
    __slots__ = (
        "addr",
        "size",
        "endness",
        "variable",
        "variable_offset",
        "guard",
        "alt",
    )

    def __init__(self, idx, addr, size, endness, variable=None, variable_offset=None, guard=None, alt=None, **kwargs):
        depth = max(addr.depth, size.depth if isinstance(size, Expression) else 0) + 1
        super().__init__(idx, depth, **kwargs)

        self.addr = addr
        self.size = size
        self.endness = endness
        self.guard = guard
        self.alt = alt
        self.variable = variable
        self.variable_offset = variable_offset

    @property
    def bits(self):
        return self.size * 8

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "Load(addr=%s, size=%d, endness=%s)" % (self.addr, self.size, self.endness)

    def has_atom(self, atom, identity=True):
        if super().has_atom(atom, identity=identity):
            return True

        if claripy is not None and isinstance(self.addr, (int, claripy.ast.Base)):
            return False
        return self.addr.has_atom(atom, identity=identity)

    def replace(self, old_expr, new_expr):
        if self.addr == old_expr:
            r = True
            replaced_addr = new_expr
        else:
            r, replaced_addr = self.addr.replace(old_expr, new_expr)

        if r:
            return True, Load(self.idx, replaced_addr, self.size, self.endness, **self.tags)
        else:
            return False, self

    def _likes_addr(self, other_addr):
        if hasattr(self.addr, "likes") and hasattr(other_addr, "likes"):
            return self.addr.likes(other_addr)

        return self.addr == other_addr

    def likes(self, other):
        return (
            type(other) is Load
            and self._likes_addr(other.addr)
            and self.size == other.size
            and self.endness == other.endness
            and self.guard == other.guard
            and self.alt == other.alt
        )

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash(("Load", self.addr, self.size, self.endness))

    def copy(self) -> "Load":
        return Load(
            self.idx,
            self.addr,
            self.size,
            self.endness,
            variable=self.variable,
            variable_offset=self.variable_offset,
            guard=self.guard,
            alt=self.alt,
            **self.tags,
        )


class ITE(Expression):
    __slots__ = (
        "cond",
        "iffalse",
        "iftrue",
        "bits",
        "variable",
        "variable_offset",
    )

    def __init__(self, idx, cond, iffalse, iftrue, variable=None, variable_offset=None, **kwargs):
        depth = (
            max(
                cond.depth if isinstance(cond, Expression) else 0,
                iffalse.depth if isinstance(iffalse, Expression) else 0,
                iftrue.depth if isinstance(iftrue, Expression) else 0,
            )
            + 1
        )
        super().__init__(idx, depth, **kwargs)

        self.cond = cond
        self.iffalse = iffalse
        self.iftrue = iftrue
        self.bits = iftrue.bits
        self.variable = variable
        self.variable_offset = variable_offset

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f"(({self.cond}) ? ({self.iftrue}) : ({self.iffalse}))"

    def likes(self, atom):
        return (
            type(atom) is ITE
            and self.cond == atom.cond
            and self.iffalse == atom.iffalse
            and self.iftrue == atom.iftrue
            and self.bits == atom.bits
        )

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((ITE, self.cond, self.iffalse, self.iftrue, self.bits))

    def has_atom(self, atom, identity=True):
        if super().has_atom(atom, identity=identity):
            return True

        return (
            self.cond.has_atom(atom, identity=identity)
            or self.iftrue.has_atom(atom, identity=identity)
            or self.iffalse.has_atom(atom, identity=identity)
        )

    def replace(self, old_expr, new_expr):
        cond_replaced, new_cond = self.cond.replace(old_expr, new_expr)
        iffalse_replaced, new_iffalse = self.iffalse.replace(old_expr, new_expr)
        iftrue_replaced, new_iftrue = self.iftrue.replace(old_expr, new_expr)
        replaced = cond_replaced or iftrue_replaced or iffalse_replaced

        if replaced:
            return True, ITE(self.idx, new_cond, new_iffalse, new_iftrue, **self.tags)
        else:
            return False, self

    @property
    def size(self):
        return self.bits // 8

    def copy(self) -> "ITE":
        return ITE(self.idx, self.cond, self.iffalse, self.iftrue, **self.tags)


class DirtyExpression(Expression):
    __slots__ = (
        "dirty_expr",
        "bits",
    )

    def __init__(self, idx, dirty_expr, bits=None, **kwargs):
        super().__init__(idx, 1, **kwargs)
        self.dirty_expr = dirty_expr
        self.bits = bits

    def likes(self, other):
        return type(other) is DirtyExpression and other.dirty_expr == self.dirty_expr

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((DirtyExpression, self.dirty_expr))

    def __repr__(self):
        return "DirtyExpression (%s)" % type(self.dirty_expr)

    def __str__(self):
        return "[D] %s" % str(self.dirty_expr)

    def copy(self) -> "DirtyExpression":
        return DirtyExpression(self.idx, self.dirty_expr, bits=self.bits, **self.tags)

    def replace(self, old_expr, new_expr):
        if old_expr is self.dirty_expr:
            return True, DirtyExpression(self.idx, new_expr, bits=self.bits, **self.tags)

        if isinstance(self.dirty_expr, Expression):
            replaced, new_dirty_expr = self.dirty_expr.replace(old_expr, new_expr)
        else:
            replaced = False
            new_dirty_expr = None
        if replaced:
            return True, DirtyExpression(self.idx, new_dirty_expr, bits=self.bits, **self.tags)
        else:
            return False, self

    @property
    def size(self):
        return self.bits // 8


class VEXCCallExpression(Expression):
    __slots__ = (
        "cee_name",
        "operands",
        "bits",
    )

    def __init__(self, idx, cee_name, operands, bits=None, **kwargs):
        super().__init__(idx, max(operand.depth for operand in operands), **kwargs)
        self.cee_name = cee_name
        self.operands = operands
        self.bits = bits

    def likes(self, other):
        return (
            type(other) is VEXCCallExpression
            and other.cee_name == self.cee_name
            and len(self.operands) == len(other.operands)
            and self.bits == other.bits
            and all(op1.likes(op2) for op1, op2 in zip(other.operands, self.operands))
        )

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((VEXCCallExpression, self.cee_name, self.bits, tuple(self.operands)))

    def __repr__(self):
        return f"VEXCCallExpression [{self.cee_name}]"

    def __str__(self):
        operands_str = ", ".join(repr(op) for op in self.operands)
        return f"{self.cee_name}({operands_str})"

    def copy(self) -> "VEXCCallExpression":
        return VEXCCallExpression(self.idx, self.cee_name, self.operands, bits=self.bits, **self.tags)

    def replace(self, old_expr, new_expr):
        new_operands = []
        replaced = False
        for operand in self.operands:
            if operand is old_expr:
                new_operands.append(new_expr)
                replaced = True
            else:
                operand_replaced, new_operand = operand.replace(old_expr, new_expr)
                if operand_replaced:
                    new_operands.append(new_operand)
                    replaced = True
                else:
                    new_operands.append(operand)

        if replaced:
            return True, VEXCCallExpression(self.idx, self.cee_name, tuple(new_operands), bits=self.bits, **self.tags)
        else:
            return False, self

    @property
    def size(self):
        return self.bits // 8


class MultiStatementExpression(Expression):
    """
    For representing comma-separated statements and expression in C.
    """

    __slots__ = (
        "stmts",
        "expr",
    )

    def __init__(self, idx: Optional[int], stmts: List["Statement"], expr: Expression, **kwargs):
        super().__init__(idx, expr.depth + 1, **kwargs)
        self.stmts = stmts
        self.expr = expr

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((MultiStatementExpression,) + tuple(self.stmts) + (self.expr,))

    def __repr__(self):
        return f"MultiStatementExpression({self.stmts}, {self.expr})"

    def __str__(self):
        stmts_str = [str(stmt) for stmt in self.stmts]
        expr_str = str(self.expr)
        concatenated_str = ", ".join(stmts_str + [expr_str])
        return f"({concatenated_str})"

    @property
    def bits(self):
        return self.expr.bits

    @property
    def size(self):
        return self.expr.size

    def replace(self, old_expr, new_expr):
        replaced = False

        new_stmts = []
        for stmt in self.stmts:
            r, new_stmt = stmt.replace(old_expr, new_expr)
            new_stmts.append(new_stmt if new_stmt is not None else stmt)
            replaced |= r

        if self.expr is old_expr:
            replaced = True
            new_expr_ = new_expr
        else:
            r, new_expr_ = self.expr.replace(old_expr, new_expr)
            replaced |= r

        if replaced:
            return True, MultiStatementExpression(
                self.idx, new_stmts, new_expr_ if new_expr_ is not None else self.expr, **self.tags
            )
        return False, self


#
# Special (Dummy) expressions
#


class BasePointerOffset(Expression):
    __slots__ = (
        "bits",
        "base",
        "offset",
        "variable",
        "variable_offset",
    )

    def __init__(self, idx, bits, base, offset, variable=None, variable_offset=None, **kwargs):
        super().__init__(idx, (offset.depth if isinstance(offset, Expression) else 0) + 1, **kwargs)
        self.bits = bits
        self.base = base
        self.offset = offset
        self.variable = variable
        self.variable_offset = variable_offset

    @property
    def size(self):
        return self.bits // 8

    def __repr__(self):
        if self.offset is None:
            return "BaseOffset(%s)" % self.base
        if isinstance(self.offset, int):
            return "BaseOffset(%s, %d)" % (self.base, self.offset)
        return f"BaseOffset({self.base}, {self.offset})"

    def __str__(self):
        if self.offset is None:
            return str(self.base)
        if isinstance(self.offset, int):
            return "%s%+d" % (self.base, self.offset)
        return f"{self.base}+{self.offset}"

    def likes(self, other):
        return (
            type(other) is type(self)
            and self.bits == other.bits
            and self.base == other.base
            and self.offset == other.offset
        )

    __hash__ = TaggedObject.__hash__

    def _hash_core(self):
        return stable_hash((self.bits, self.base, self.offset))

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

    def copy(self) -> "BasePointerOffset":
        return BasePointerOffset(self.idx, self.bits, self.base, self.offset, **self.tags)


class StackBaseOffset(BasePointerOffset):
    __slots__ = ()

    def __init__(self, idx, bits, offset, **kwargs):
        # stack base offset is always signed
        if offset >= (1 << (bits - 1)):
            offset -= 1 << bits
        super().__init__(idx, bits, "stack_base", offset, **kwargs)

    def copy(self) -> "StackBaseOffset":
        return StackBaseOffset(self.idx, self.bits, self.offset, **self.tags)
