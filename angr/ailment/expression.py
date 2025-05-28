# pylint:disable=arguments-renamed,isinstance-second-argument-not-valid-type,missing-class-docstring,too-many-boolean-expressions
from __future__ import annotations
from typing import TYPE_CHECKING, cast
from collections.abc import Sequence
from enum import Enum, IntEnum
from abc import abstractmethod
from typing_extensions import Self


try:
    import claripy
except ImportError:
    claripy = None

from .tagged_object import TaggedObject
from .utils import get_bits, stable_hash, is_none_or_likeable, is_none_or_matchable

if TYPE_CHECKING:
    from .statement import Statement


class Expression(TaggedObject):
    """
    The base class of all AIL expressions.
    """

    bits: int

    __slots__ = (
        "bits",
        "depth",
    )

    def __init__(self, idx, depth, **kwargs):
        super().__init__(idx, **kwargs)
        self.depth = depth

    @abstractmethod
    def __repr__(self):
        raise NotImplementedError

    def has_atom(self, atom, identity=True):
        if identity:
            return self is atom
        return self.likes(atom)

    def __eq__(self, other):
        if self is other:
            return True
        return type(self) is type(other) and self.likes(other) and self.idx == other.idx

    @abstractmethod
    def likes(self, other):  # pylint:disable=unused-argument,no-self-use
        raise NotImplementedError

    @abstractmethod
    def matches(self, other):  # pylint:disable=unused-argument,no-self-use
        raise NotImplementedError

    def replace(self, old_expr: Expression, new_expr: Expression) -> tuple[bool, Self]:
        if self is old_expr:
            r = True
            replaced = cast(Self, new_expr)
        elif not isinstance(self, Atom):
            r, replaced = self.replace(old_expr, new_expr)
        else:
            r, replaced = False, self

        return r, replaced

    def __add__(self, other):
        return BinaryOp(None, "Add", [self, other], signed=False, **self.tags)

    def __sub__(self, other):
        return BinaryOp(None, "Sub", [self, other], signed=False, **self.tags)


class Atom(Expression):
    __slots__ = (
        "variable",
        "variable_offset",
    )

    def __init__(self, idx: int | None, variable=None, variable_offset=0, **kwargs):
        super().__init__(idx, 0, **kwargs)
        self.variable = variable
        self.variable_offset = variable_offset

    def __repr__(self) -> str:
        return f"Atom ({self.idx})"

    def copy(self) -> Self:  # pylint:disable=no-self-use
        raise NotImplementedError


class Const(Atom):
    __slots__ = ("value",)

    def __init__(self, idx: int | None, variable, value: int | float, bits: int, **kwargs):
        super().__init__(idx, variable, **kwargs)

        self.value = value
        self.bits = bits

    @property
    def size(self):
        return self.bits // 8

    def __repr__(self):
        return str(self)

    def __str__(self):
        if isinstance(self.value, int):
            return f"{self.value:#x}<{self.bits}>"
        if isinstance(self.value, float):
            return f"{self.value:f}<{self.bits}>"
        return f"{self.value}<{self.bits}>"

    def likes(self, other):
        # nan is nan, but nan != nan
        return (
            type(self) is type(other)
            and (self.value is other.value or self.value == other.value)
            and self.bits == other.bits
        )

    matches = likes
    __hash__ = TaggedObject.__hash__  # type: ignore

    def _hash_core(self):
        return stable_hash((self.value, self.bits))

    @property
    def sign_bit(self):
        if not self.is_int:
            raise TypeError("Sign bit is only available for int constants.")
        assert isinstance(self.value, int)
        return self.value >> (self.bits - 1)

    def copy(self) -> Const:
        return Const(self.idx, self.variable, self.value, self.bits, **self.tags)

    @property
    def is_int(self) -> bool:
        return isinstance(self.value, int)


class Tmp(Atom):
    __slots__ = ("tmp_idx",)

    def __init__(self, idx: int | None, variable, tmp_idx: int, bits, **kwargs):
        super().__init__(idx, variable, **kwargs)

        self.tmp_idx = tmp_idx
        self.bits = bits

    @property
    def size(self):
        return self.bits // 8

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f"t{self.tmp_idx}"

    def likes(self, other):
        return type(self) is type(other) and self.tmp_idx == other.tmp_idx and self.bits == other.bits

    matches = likes
    __hash__ = TaggedObject.__hash__  # type: ignore

    def _hash_core(self):
        return stable_hash(("tmp", self.tmp_idx, self.bits))

    def copy(self) -> Tmp:
        return Tmp(self.idx, self.variable, self.tmp_idx, self.bits, **self.tags)


class Register(Atom):
    __slots__ = ("reg_offset",)

    def __init__(self, idx: int | None, variable, reg_offset: int, bits: int, **kwargs):
        super().__init__(idx, variable, **kwargs)

        self.reg_offset = reg_offset
        self.bits = bits

    @property
    def size(self):
        return self.bits // 8

    def likes(self, other):
        return type(self) is type(other) and self.reg_offset == other.reg_offset and self.bits == other.bits

    def __repr__(self):
        return str(self)

    def __str__(self):
        if hasattr(self, "reg_name"):
            return f"{self.reg_name}<{self.bits // 8}>"
        if self.variable is None:
            return f"reg_{self.reg_offset}<{self.bits // 8}>"
        return f"{self.variable.name!s}"

    matches = likes
    __hash__ = TaggedObject.__hash__  # type: ignore

    def _hash_core(self):
        return stable_hash(("reg", self.reg_offset, self.bits, self.idx))

    def copy(self) -> Register:
        return Register(self.idx, self.variable, self.reg_offset, self.bits, **self.tags)


class VirtualVariableCategory(IntEnum):
    REGISTER = 0
    STACK = 1
    MEMORY = 2
    PARAMETER = 3
    TMP = 4
    UNKNOWN = 5


class VirtualVariable(Atom):

    __slots__ = (
        "category",
        "oident",
        "varid",
    )

    def __init__(
        self,
        idx,
        varid: int,
        bits,
        category: VirtualVariableCategory,
        oident: int | str | tuple | None = None,
        **kwargs,
    ):
        super().__init__(idx, **kwargs)

        self.varid = varid
        self.category = category
        self.oident = oident
        self.bits = bits

    @property
    def size(self):
        return self.bits // 8

    @property
    def was_reg(self) -> bool:
        return self.category == VirtualVariableCategory.REGISTER

    @property
    def was_stack(self) -> bool:
        return self.category == VirtualVariableCategory.STACK

    @property
    def was_parameter(self) -> bool:
        return self.category == VirtualVariableCategory.PARAMETER

    @property
    def was_tmp(self) -> bool:
        return self.category == VirtualVariableCategory.TMP

    @property
    def reg_offset(self) -> int:
        if self.was_reg:
            assert isinstance(self.oident, int)
            return self.oident
        if self.was_parameter and self.parameter_category == VirtualVariableCategory.REGISTER:
            return self.parameter_reg_offset  # type: ignore
        raise TypeError("Is not a register")

    @property
    def stack_offset(self) -> int:
        if self.was_stack:
            assert isinstance(self.oident, int)
            return self.oident
        if self.was_parameter and self.parameter_category == VirtualVariableCategory.STACK:
            return self.parameter_stack_offset  # type: ignore
        raise TypeError("Is not a stack variable")

    @property
    def tmp_idx(self) -> int | None:
        if self.was_tmp:
            assert isinstance(self.oident, int)
            return self.oident
        return None

    @property
    def parameter_category(self) -> VirtualVariableCategory | None:
        if self.was_parameter:
            assert isinstance(self.oident, tuple)
            return self.oident[0]
        return None

    @property
    def parameter_reg_offset(self) -> int | None:
        if self.was_parameter and self.parameter_category == VirtualVariableCategory.REGISTER:
            assert isinstance(self.oident, tuple)
            return self.oident[1]
        return None

    @property
    def parameter_stack_offset(self) -> int | None:
        if self.was_parameter and self.parameter_category == VirtualVariableCategory.STACK:
            assert isinstance(self.oident, tuple)
            return self.oident[1]
        return None

    def likes(self, other):
        return (
            isinstance(other, VirtualVariable)
            and self.varid == other.varid
            and self.bits == other.bits
            and self.category == other.category
            and self.oident == other.oident
        )

    def matches(self, other):
        return (
            isinstance(other, VirtualVariable)
            and self.bits == other.bits
            and self.category == other.category
            and self.oident == other.oident
        )

    def __repr__(self):
        ori_str = ""
        match self.category:
            case VirtualVariableCategory.REGISTER:
                ori_str = f"{{reg {self.reg_offset}}}"
            case VirtualVariableCategory.STACK:
                ori_str = f"{{stack {self.oident}}}"
        return f"vvar_{self.varid}{ori_str}"

    __hash__ = TaggedObject.__hash__  # type: ignore

    def _hash_core(self):
        return stable_hash(("var", self.varid, self.bits, self.category, self.oident))

    def copy(self) -> VirtualVariable:
        return VirtualVariable(
            self.idx,
            self.varid,
            self.bits,
            self.category,
            oident=self.oident,
            variable=self.variable,
            variable_offset=self.variable_offset,
            **self.tags,
        )


class Phi(Atom):

    __slots__ = ("src_and_vvars",)

    def __init__(
        self,
        idx,
        bits,
        src_and_vvars: list[tuple[tuple[int, int | None], VirtualVariable | None]],
        **kwargs,
    ):
        super().__init__(idx, **kwargs)
        self.bits = bits
        self.src_and_vvars = src_and_vvars

    @property
    def size(self) -> int:
        return self.bits // 8

    @property
    def op(self) -> str:
        return "Phi"

    @property
    def verbose_op(self) -> str:
        return "Phi"

    def likes(self, other) -> bool:
        if isinstance(other, Phi) and self.bits == other.bits:
            self_src_and_vvarids = {(src, vvar.varid if vvar is not None else None) for src, vvar in self.src_and_vvars}
            other_src_and_vvarids = {
                (src, vvar.varid if vvar is not None else None) for src, vvar in other.src_and_vvars
            }
            return self_src_and_vvarids == other_src_and_vvarids
        return False

    def matches(self, other) -> bool:
        if isinstance(other, Phi) and self.bits == other.bits:
            if len(self.src_and_vvars) != len(other.src_and_vvars):
                return False
            self_src_and_vvars = dict(self.src_and_vvars)
            other_src_and_vvars = dict(other.src_and_vvars)
            for src, self_vvar in self_src_and_vvars.items():
                if src not in other_src_and_vvars:
                    return False
                other_vvar = other_src_and_vvars[src]
                if self_vvar is None and other_vvar is None:
                    continue
                if (
                    (self_vvar is None and other_vvar is not None)
                    or (self_vvar is not None and other_vvar is None)
                    or (self_vvar is not None and other_vvar is not None and not self_vvar.matches(other_vvar))
                ):
                    return False
            return True
        return False

    def __repr__(self):
        return f"𝜙@{self.bits}b {self.src_and_vvars}"

    __hash__ = TaggedObject.__hash__  # type: ignore

    def _hash_core(self):
        return stable_hash(("phi", self.bits, tuple(sorted(self.src_and_vvars, key=self._src_and_vvar_filter))))

    def copy(self) -> Phi:
        return Phi(
            self.idx,
            self.bits,
            self.src_and_vvars[::],
            variable=self.variable,
            variable_offset=self.variable_offset,
            **self.tags,
        )

    def replace(self, old_expr, new_expr):
        replaced = False
        new_src_and_vvars = []
        for src, vvar in self.src_and_vvars:
            if vvar == old_expr and isinstance(new_expr, VirtualVariable):
                replaced = True
                new_src_and_vvars.append((src, new_expr))
            else:
                new_src_and_vvars.append((src, vvar))

        if replaced:
            return True, Phi(
                self.idx,
                self.bits,
                new_src_and_vvars,
                variable=self.variable,
                variable_offset=self.variable_offset,
                **self.tags,
            )
        return False, self

    @staticmethod
    def _src_and_vvar_filter(
        src_and_vvar: tuple[tuple[int, int | None], VirtualVariable | None],
    ) -> tuple[tuple[int, int], int]:
        src, vvar = src_and_vvar
        if src[1] is None:
            src = src[0], -1
        vvar_id = vvar.varid if vvar is not None else -1
        return src, vvar_id  # type: ignore


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
        "variable",
        "variable_offset",
    )

    def __init__(
        self,
        idx: int | None,
        op: str,
        operand: Expression,
        variable=None,
        variable_offset: int | None = None,
        bits=None,
        **kwargs,
    ):
        super().__init__(idx, (operand.depth if isinstance(operand, Expression) else 0) + 1, op, **kwargs)

        self.operand = operand
        self.bits = operand.bits if bits is None else bits
        self.variable = variable
        self.variable_offset = variable_offset

    def __str__(self):
        return f"({self.op} {self.operand!s})"

    def __repr__(self):
        return str(self)

    def likes(self, other):
        return (
            type(other) is UnaryOp
            and self.op == other.op
            and self.bits == other.bits
            and self.operand.likes(other.operand)
        )

    def matches(self, other):
        return (
            type(other) is UnaryOp
            and self.op == other.op
            and self.bits == other.bits
            and self.operand.matches(other.operand)
        )

    __hash__ = TaggedObject.__hash__  # type: ignore

    def _hash_core(self):
        return stable_hash((self.op, self.operand, self.bits))

    def replace(self, old_expr, new_expr):
        if self.operand == old_expr:
            r = True
            replaced_operand = new_expr
        else:
            r, replaced_operand = self.operand.replace(old_expr, new_expr)

        if r:
            return True, UnaryOp(self.idx, self.op, replaced_operand, bits=self.bits, **self.tags)
        return False, self

    @property
    def operands(self):
        return [self.operand]

    @property
    def size(self):
        return self.bits // 8

    def copy(self) -> UnaryOp:
        return UnaryOp(
            self.idx,
            self.op,
            self.operand,
            variable=self.variable,
            variable_offset=self.variable_offset,
            bits=self.bits,
            **self.tags,
        )

    def has_atom(self, atom, identity=True):
        if super().has_atom(atom, identity=identity):
            return True
        return self.operand.has_atom(atom, identity=identity)


class ConvertType(Enum):
    TYPE_INT = 0
    TYPE_FP = 1


class Convert(UnaryOp):
    TYPE_INT = ConvertType.TYPE_INT
    TYPE_FP = ConvertType.TYPE_FP

    __slots__ = (
        "from_bits",
        "from_type",
        "is_signed",
        "rounding_mode",
        "to_bits",
        "to_type",
    )

    def __init__(
        self,
        idx: int | None,
        from_bits: int,
        to_bits: int,
        is_signed: bool,
        operand: Expression,
        from_type: ConvertType = TYPE_INT,
        to_type: ConvertType = TYPE_INT,
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
        return f"Conv({self.from_bits}->{'s' if self.is_signed else ''}{self.to_bits}, {self.operand})"

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

    def matches(self, other):
        return (
            type(other) is Convert
            and self.from_bits == other.from_bits
            and self.to_bits == other.to_bits
            and self.bits == other.bits
            and self.is_signed == other.is_signed
            and self.operand.matches(other.operand)
            and self.from_type == other.from_type
            and self.to_type == other.to_type
            and self.rounding_mode == other.rounding_mode
        )

    __hash__ = TaggedObject.__hash__  # type: ignore

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
        return False, self

    def copy(self) -> Convert:
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
            and self.operand.likes(other.operand)
        )

    def matches(self, other):
        return (
            type(other) is Reinterpret
            and self.from_bits == other.from_bits
            and self.from_type == other.from_type
            and self.to_bits == other.to_bits
            and self.to_type == other.to_type
            and self.operand.matches(other.operand)
        )

    __hash__ = TaggedObject.__hash__  # type: ignore

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
        return False, self

    def copy(self) -> Reinterpret:
        return Reinterpret(
            self.idx, self.from_bits, self.from_type, self.to_bits, self.to_type, self.operand, **self.tags
        )


class BinaryOp(Op):
    __slots__ = (
        "floating_point",
        "operands",
        "rounding_mode",
        "signed",
        "variable",
        "variable_offset",
        "vector_count",
        "vector_size",
    )

    OPSTR_MAP = {
        "Add": "+",
        "AddF": "+",
        "AddV": "+",
        "Sub": "-",
        "SubF": "-",
        "Mul": "*",
        "MulF": "*",
        "MulV": "*",
        "Div": "/",
        "DivF": "/",
        "Mod": "%",
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
        "CmpLT (signed)": "<s",
        "CmpLE (signed)": "<=s",
        "CmpGT (signed)": ">s",
        "CmpGE (signed)": ">=s",
        "Concat": "CONCAT",
        "Ror": "ROR",
        "Rol": "ROL",
        "Carry": "CARRY",
        "SCarry": "SCARRY",
        "SBorrow": "SBORROW",
    }

    COMPARISON_NEGATION = {
        "CmpEQ": "CmpNE",
        "CmpNE": "CmpEQ",
        "CmpLT": "CmpGE",
        "CmpGE": "CmpLT",
        "CmpLE": "CmpGT",
        "CmpGT": "CmpLE",
    }

    def __init__(
        self,
        idx: int | None,
        op: str,
        operands: Sequence[Expression],
        signed: bool = False,
        *,
        variable=None,
        variable_offset=None,
        bits=None,
        floating_point=False,
        rounding_mode=None,
        vector_count: int | None = None,
        vector_size: int | None = None,
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
        elif self.op in {
            "CmpEQ",
            "CmpNE",
            "CmpLT",
            "CmpGE",
            "CmpLE",
            "CmpGT",
            "ExpCmpNE",
        }:
            self.bits = 1
        elif self.op in {"Carry", "SCarry", "SBorrow"}:
            self.bits = 8
        elif self.op == "Concat":
            self.bits = get_bits(operands[0]) + get_bits(operands[1])
        elif self.op == "Mull":
            self.bits = get_bits(operands[0]) * 2 if not isinstance(operands[0], int) else get_bits(operands[1]) * 2
        else:
            self.bits = get_bits(operands[0]) if not isinstance(operands[0], int) else get_bits(operands[1])
        self.signed = signed
        self.variable = variable
        self.variable_offset = variable_offset
        self.floating_point = floating_point
        self.rounding_mode: str | None = rounding_mode
        self.vector_count = vector_count
        self.vector_size = vector_size

        # TODO: sanity check of operands' sizes for some ops
        # assert self.bits == operands[1].bits

    def __str__(self):
        op_str = self.OPSTR_MAP.get(self.verbose_op, self.verbose_op)
        return f"({self.operands[0]!s} {op_str} {self.operands[1]!s})"

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

    def matches(self, other):
        return (
            type(other) is BinaryOp
            and self.op == other.op
            and self.bits == other.bits
            and self.signed == other.signed
            and is_none_or_matchable(self.operands, other.operands, is_list=True)
            and self.floating_point == other.floating_point
            and self.rounding_mode == other.rounding_mode
        )

    __hash__ = TaggedObject.__hash__  # type: ignore

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

    def replace(self, old_expr: Expression, new_expr: Expression) -> tuple[bool, BinaryOp]:
        if self.operands[0] == old_expr:
            r0 = True
            replaced_operand_0 = new_expr
        elif isinstance(self.operands[0], Expression):
            r0, replaced_operand_0 = self.operands[0].replace(old_expr, new_expr)
        else:
            r0, replaced_operand_0 = False, new_expr

        if self.operands[1] == old_expr:
            r1 = True
            replaced_operand_1 = new_expr
        elif isinstance(self.operands[1], Expression):
            r1, replaced_operand_1 = self.operands[1].replace(old_expr, new_expr)
        else:
            r1, replaced_operand_1 = False, new_expr

        r2, replaced_rm = False, None
        if self.rounding_mode is not None and self.rounding_mode == old_expr:
            r2 = True
            replaced_rm = new_expr

        if r0 or r1:
            return True, BinaryOp(
                self.idx,
                self.op,
                [replaced_operand_0 if r0 else self.operands[0], replaced_operand_1 if r1 else self.operands[1]],
                signed=self.signed,
                bits=self.bits,
                floating_point=self.floating_point,
                rounding_mode=replaced_rm if r2 else self.rounding_mode,
                **self.tags,
            )
        return False, self

    @property
    def verbose_op(self):
        op = self.op
        if self.floating_point:
            op += " (float)"
        else:
            if self.signed:
                op += " (signed)"
        return op

    @property
    def size(self):
        return self.bits // 8

    def copy(self) -> BinaryOp:
        return BinaryOp(
            self.idx,
            self.op,
            self.operands[::],
            variable=self.variable,
            signed=self.signed,
            variable_offset=self.variable_offset,
            bits=self.bits,
            floating_point=self.floating_point,
            rounding_mode=self.rounding_mode,
            **self.tags,
        )


class Load(Expression):
    __slots__ = (
        "addr",
        "alt",
        "endness",
        "guard",
        "size",
        "variable",
        "variable_offset",
    )

    def __init__(
        self,
        idx: int | None,
        addr: Expression,
        size: int,
        endness: str,
        variable=None,
        variable_offset=None,
        guard=None,
        alt=None,
        **kwargs,
    ):
        depth = max(addr.depth, size.depth if isinstance(size, Expression) else 0) + 1
        super().__init__(idx, depth, **kwargs)

        self.addr = addr
        self.size = size
        self.endness = endness
        self.guard = guard
        self.alt = alt
        self.variable = variable
        self.variable_offset = variable_offset
        self.bits = self.size * 8

    def __repr__(self):
        return str(self)

    def __str__(self):
        return f"Load(addr={self.addr}, size={self.size}, endness={self.endness})"

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

    def _matches_addr(self, other_addr):
        if hasattr(self.addr, "matches") and hasattr(other_addr, "matches"):
            return self.addr.matches(other_addr)
        return self.addr == other_addr

    def matches(self, other):
        return (
            type(other) is Load
            and self._matches_addr(other.addr)
            and self.size == other.size
            and self.endness == other.endness
            and self.guard == other.guard
            and self.alt == other.alt
        )

    __hash__ = TaggedObject.__hash__  # type: ignore

    def _hash_core(self):
        return stable_hash(("Load", self.addr, self.size, self.endness))

    def copy(self) -> Load:
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
        "variable",
        "variable_offset",
    )

    def __init__(
        self,
        idx: int | None,
        cond: Expression,
        iffalse: Expression,
        iftrue: Expression,
        variable=None,
        variable_offset=None,
        **kwargs,
    ):
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

    def likes(self, other):
        return (
            type(other) is ITE
            and self.cond.likes(other.cond)
            and self.iffalse == other.iffalse
            and self.iftrue == other.iftrue
            and self.bits == other.bits
        )

    def matches(self, other):
        return (
            type(other) is ITE
            and self.cond.matches(other.cond)
            and self.iffalse == other.iffalse
            and self.iftrue == other.iftrue
            and self.bits == other.bits
        )

    __hash__ = TaggedObject.__hash__  # type: ignore

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
        if self.cond == old_expr:
            cond_replaced = True
            new_cond = new_expr
        else:
            cond_replaced, new_cond = self.cond.replace(old_expr, new_expr)

        if self.iffalse == old_expr:
            iffalse_replaced = True
            new_iffalse = new_expr
        else:
            iffalse_replaced, new_iffalse = self.iffalse.replace(old_expr, new_expr)

        if self.iftrue == old_expr:
            iftrue_replaced = True
            new_iftrue = new_expr
        else:
            iftrue_replaced, new_iftrue = self.iftrue.replace(old_expr, new_expr)

        replaced = cond_replaced or iftrue_replaced or iffalse_replaced

        if replaced:
            return True, ITE(self.idx, new_cond, new_iffalse, new_iftrue, **self.tags)
        return False, self

    @property
    def size(self):
        return self.bits // 8

    def copy(self) -> ITE:
        return ITE(self.idx, self.cond, self.iffalse, self.iftrue, **self.tags)


class DirtyExpression(Expression):
    __slots__ = (
        "callee",
        "guard",
        "maddr",
        "mfx",
        "msize",
        "operands",
    )

    def __init__(
        self,
        idx,
        callee: str,
        operands: list[Expression],
        *,
        guard: Expression | None = None,
        mfx: str | None = None,
        maddr: Expression | None = None,
        msize: int | None = None,
        # TODO: fxstate (guest state effects) is not modeled yet
        bits: int,
        **kwargs,
    ):
        super().__init__(idx, 1, **kwargs)

        self.callee = callee
        self.guard = guard
        self.operands = operands
        self.mfx = mfx
        self.maddr = maddr
        self.msize = msize
        self.bits = bits

    @property
    def op(self) -> str:
        return self.callee

    @property
    def verbose_op(self) -> str:
        return self.op

    def likes(self, other):
        return (
            type(other) is DirtyExpression
            and other.callee == self.callee
            and is_none_or_likeable(other.guard, self.guard)
            and len(self.operands) == len(other.operands)
            and all(op1.likes(op2) for op1, op2 in zip(self.operands, other.operands))
            and other.mfx == self.mfx
            and is_none_or_likeable(other.maddr, self.maddr)
            and other.msize == self.msize
            and self.bits == other.bits
        )

    def matches(self, other):
        return (
            type(other) is DirtyExpression
            and other.callee == self.callee
            and is_none_or_matchable(other.guard, self.guard)
            and len(self.operands) == len(other.operands)
            and all(op1.matches(op2) for op1, op2 in zip(self.operands, other.operands))
            and other.mfx == self.mfx
            and is_none_or_matchable(other.maddr, self.maddr)
            and other.msize == self.msize
            and self.bits == other.bits
        )

    __hash__ = TaggedObject.__hash__  # type: ignore

    def _hash_core(self):
        return stable_hash(
            (
                DirtyExpression,
                self.callee,
                self.guard,
                tuple(self.operands),
                self.mfx,
                self.maddr,
                self.msize,
                self.bits,
            )
        )

    def __repr__(self):
        return f"[D] {self.callee}({', '.join(repr(op) for op in self.operands)})"

    def __str__(self):
        return f"[D] {self.callee}({', '.join(repr(op) for op in self.operands)})"

    def copy(self) -> DirtyExpression:
        return DirtyExpression(
            self.idx,
            self.callee,
            self.operands,
            guard=self.guard,
            mfx=self.mfx,
            maddr=self.maddr,
            msize=self.msize,
            bits=self.bits,
            **self.tags,
        )

    def replace(self, old_expr: Expression, new_expr: Expression):
        new_operands = []
        replaced = False
        for op in self.operands:
            if old_expr == op:
                replaced = True
                new_operands.append(new_expr)
            else:
                r, new_op = op.replace(old_expr, new_expr)
                if r:
                    replaced = True
                    new_operands.append(new_op)
                else:
                    new_operands.append(op)

        if replaced:
            return True, DirtyExpression(
                self.idx,
                self.callee,
                new_operands,
                guard=self.guard,
                mfx=self.mfx,
                maddr=self.maddr,
                msize=self.msize,
                bits=self.bits,
                **self.tags,
            )
        return False, self

    @property
    def size(self):
        if self.bits is None:
            return None
        return self.bits // 8


class VEXCCallExpression(Expression):
    __slots__ = (
        "callee",
        "operands",
    )

    def __init__(self, idx: int | None, callee: str, operands: tuple[Expression, ...], bits: int, **kwargs):
        super().__init__(idx, max(operand.depth for operand in operands), **kwargs)
        self.callee = callee
        self.operands = operands
        self.bits = bits

    @property
    def op(self) -> str:
        return self.callee

    @property
    def verbose_op(self) -> str:
        return self.op

    def likes(self, other):
        return (
            type(other) is VEXCCallExpression
            and other.callee == self.callee
            and len(self.operands) == len(other.operands)
            and self.bits == other.bits
            and all(op1.likes(op2) for op1, op2 in zip(other.operands, self.operands))
        )

    def matches(self, other):
        return (
            type(other) is VEXCCallExpression
            and other.callee == self.callee
            and len(self.operands) == len(other.operands)
            and self.bits == other.bits
            and all(op1.matches(op2) for op1, op2 in zip(other.operands, self.operands))
        )

    __hash__ = TaggedObject.__hash__  # type: ignore

    def _hash_core(self):
        return stable_hash((VEXCCallExpression, self.callee, self.bits, tuple(self.operands)))

    def __repr__(self):
        return f"VEXCCallExpression [{self.callee}({', '.join(repr(op) for op in self.operands)})]"

    def __str__(self):
        operands_str = ", ".join(repr(op) for op in self.operands)
        return f"{self.callee}({operands_str})"

    def copy(self) -> VEXCCallExpression:
        return VEXCCallExpression(self.idx, self.callee, self.operands, bits=self.bits, **self.tags)

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
            return True, VEXCCallExpression(self.idx, self.callee, tuple(new_operands), bits=self.bits, **self.tags)
        return False, self

    @property
    def size(self):
        if self.bits is None:
            return None
        return self.bits // 8


class MultiStatementExpression(Expression):
    """
    For representing comma-separated statements and expression in C.
    """

    __slots__ = (
        "expr",
        "stmts",
    )

    def __init__(self, idx: int | None, stmts: list[Statement], expr: Expression, **kwargs):
        super().__init__(idx, expr.depth + 1, **kwargs)
        self.stmts = stmts
        self.expr = expr
        self.bits = self.expr.bits

    __hash__ = TaggedObject.__hash__  # type: ignore

    def _hash_core(self):
        return stable_hash((MultiStatementExpression, *tuple(self.stmts), self.expr))

    def likes(self, other):
        return (
            type(self) is type(other)
            and len(self.stmts) == len(other.stmts)
            and all(s_stmt.likes(o_stmt) for s_stmt, o_stmt in zip(self.stmts, other.stmts))
            and self.expr.likes(other.expr)
        )

    def matches(self, other):
        return (
            type(self) is type(other)
            and len(self.stmts) == len(other.stmts)
            and all(s_stmt.matches(o_stmt) for s_stmt, o_stmt in zip(self.stmts, other.stmts))
            and self.expr.matches(other.expr)
        )

    def __repr__(self):
        return f"MultiStatementExpression({self.stmts}, {self.expr})"

    def __str__(self):
        stmts_str = [str(stmt) for stmt in self.stmts]
        expr_str = str(self.expr)
        concatenated_str = ", ".join([*stmts_str, expr_str])
        return f"({concatenated_str})"

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

    def copy(self) -> MultiStatementExpression:
        return MultiStatementExpression(self.idx, self.stmts[::], self.expr, **self.tags)


#
# Special (Dummy) expressions
#


class BasePointerOffset(Expression):
    __slots__ = (
        "base",
        "offset",
        "variable",
        "variable_offset",
    )

    def __init__(
        self,
        idx: int | None,
        bits: int,
        base: Expression | str,
        offset: int,
        variable=None,
        variable_offset=None,
        **kwargs,
    ):
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
            return f"BaseOffset({self.base})"
        return f"BaseOffset({self.base}, {self.offset})"

    def __str__(self):
        if self.offset is None:
            return str(self.base)
        if isinstance(self.offset, int):
            return f"{self.base}{self.offset:+d}"
        return f"{self.base}+{self.offset}"

    def likes(self, other):
        return (
            type(other) is type(self)
            and self.bits == other.bits
            and self.base == other.base
            and self.offset == other.offset
        )

    matches = likes
    __hash__ = TaggedObject.__hash__  # type: ignore

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

    def copy(self) -> BasePointerOffset:
        return BasePointerOffset(self.idx, self.bits, self.base, self.offset, **self.tags)


class StackBaseOffset(BasePointerOffset):
    __slots__ = ()

    def __init__(self, idx: int | None, bits: int, offset: int, **kwargs):
        # stack base offset is always signed
        if offset >= (1 << (bits - 1)):
            offset -= 1 << bits
        super().__init__(idx, bits, "stack_base", offset, **kwargs)

    def copy(self) -> StackBaseOffset:
        return StackBaseOffset(self.idx, self.bits, self.offset, **self.tags)


def negate(expr: Expression) -> Expression:
    if isinstance(expr, UnaryOp) and expr.op == "Not":
        # unpack
        return expr.operand
    if isinstance(expr, BinaryOp) and expr.op in BinaryOp.COMPARISON_NEGATION:
        return BinaryOp(
            expr.idx,
            BinaryOp.COMPARISON_NEGATION[expr.op],
            expr.operands,
            signed=expr.signed,
            bits=expr.bits,
            floating_point=expr.floating_point,
            rounding_mode=expr.rounding_mode,
            **expr.tags,
        )
    return UnaryOp(None, "Not", expr, **expr.tags)
