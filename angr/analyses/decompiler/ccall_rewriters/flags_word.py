from __future__ import annotations

from typing import TYPE_CHECKING, Any

from angr.ailment import Expr
from angr.analyses.decompiler.peephole_optimizations.and_mask_pruning import _is_pure
from angr.engines.vex.claripy.ccall import data

if TYPE_CHECKING:
    from angr.ailment.manager import Manager
    from angr.engines.vex.claripy.ccall import Platform


def _families(platform: Platform) -> dict[int, tuple[str, int]]:
    ops = data[platform]["OpTypes"]
    out = {}
    for fam in ("ADD", "SUB", "LOGIC", "INC", "DEC", "SHL", "SHR"):
        for suffix, nbits in (("B", 8), ("W", 16), ("L", 32), ("Q", 64)):
            op = ops.get(f"G_CC_OP_{fam}{suffix}")
            if op is not None:
                out[op] = (fam, nbits)
    return out


_FAMILIES = {p: _families(p) for p in ("AMD64", "X86")}


def flags_word_ccall(expr) -> tuple[Platform, int] | None:
    """(platform, cc_op) of a {x86g_calculate_eflags,amd64g_calculate_rflags}_all ccall with a constant cc_op."""
    if not isinstance(expr, Expr.VEXCCallExpression):
        return None
    callee = expr.callee
    if callee == "_ccall":
        callee = expr.tags.get("vex_callee", callee)
    platform = {"x86g_calculate_eflags_all": "X86", "amd64g_calculate_rflags_all": "AMD64"}.get(callee)
    if platform is None or len(expr.operands) != 4 or expr.bits != data[platform]["size"]:
        return None
    op = expr.operands[0]
    if not (isinstance(op, Expr.Const) and isinstance(op.value, int)):
        return None
    return platform, op.value_int


def flag_bits(platform: Platform, names: str = "OSZACP") -> int:
    masks = data[platform]["CondBitMasks"]
    out = 0
    for name in names:
        out |= masks[f"G_CC_MASK_{name}"]
    return out


def flags_word_support(platform: Platform, op_v: int) -> int | None:
    """The bits a flags word of cc_op ``op_v`` can have set (COPY: None, the word is cc_dep1's flag bits)."""
    if op_v == data[platform]["OpTypes"]["G_CC_OP_COPY"]:
        return None
    family = _FAMILIES[platform].get(op_v)
    return flag_bits(platform, "PZS" if family is not None and family[0] == "LOGIC" else "OSZACP")


class FlagsWordBuilder:
    """
    Rebuilds the packed flags word that {amd64g_calculate_rflags,x86g_calculate_eflags}_all returns for a constant
    cc_op: bit C(0), P(2), A(4), Z(6), S(7), O(11); all other bits are zero. Mirrors VEX's ACTIONS_* macros.
    """

    __slots__ = ("bits", "manager", "masks", "offsets", "platform", "tags")

    def __init__(self, manager: Manager, platform: Platform, tags: Any):
        self.manager = manager
        self.platform = platform
        self.bits = data[platform]["size"]
        self.masks = data[platform]["CondBitMasks"]
        self.offsets = data[platform]["CondBitOffsets"]
        self.tags = tags

    def build(
        self, op_v: int, dep_1: Expr.Expression, dep_2: Expr.Expression, ndep: Expr.Expression, idx: int
    ) -> Expr.Expression | None:
        bits = self.bits
        if op_v == data[self.platform]["OpTypes"]["G_CC_OP_COPY"]:
            if dep_1.bits != bits:
                return None
            return self._binop("And", dep_1, self._const(flag_bits(self.platform), bits), idx=idx)

        family_nbits = _FAMILIES[self.platform].get(op_v)
        if family_nbits is None:
            return None
        family, nbits = family_nbits
        if dep_1.bits != bits or dep_2.bits != bits or ndep.bits != bits:
            return None
        if not (_is_pure(dep_1) and _is_pure(dep_2)):
            # the operands are repeated in the word; a call would run once per copy
            return None

        d1 = self._narrow(dep_1, nbits)
        terms: list[Expr.Expression] = []
        if family == "LOGIC":
            res = d1
            terms.append(self._parity_term(res, nbits))
            terms.append(self._bit_term(self._is_zero(res), "Z"))
            terms.append(self._bit_term(self._is_neg(res), "S"))
        elif family in {"ADD", "SUB"}:
            d2 = self._narrow(dep_2, nbits)
            res = self._binop("Add" if family == "ADD" else "Sub", d1, d2)
            if family == "ADD":
                cf = self._binop("CmpLT", res, d1)
                same_signs = self._unop("BitwiseNeg", self._binop("Xor", d1, d2))
                of_word = self._binop("And", same_signs, self._binop("Xor", d1, res))
            else:
                cf = self._binop("CmpLT", d1, d2)
                of_word = self._binop("And", self._binop("Xor", d1, d2), self._binop("Xor", d1, res))
            terms.append(self._bit_term(cf, "C"))
            terms.append(self._parity_term(res, nbits))
            terms.append(self._af_term(res, d1, d2))
            terms.append(self._bit_term(self._is_zero(res), "Z"))
            terms.append(self._bit_term(self._is_neg(res), "S"))
            terms.append(self._bit_term(self._is_neg(of_word), "O"))
        elif family in {"INC", "DEC"}:
            # cc_dep1 is the result; CF is carried over from cc_ndep
            res = d1
            one = self._const(1, nbits)
            other = self._binop("Sub" if family == "INC" else "Add", res, one)
            extreme = 1 << (nbits - 1) if family == "INC" else (1 << (nbits - 1)) - 1
            terms.append(self._binop("And", ndep, self._const(self.masks["G_CC_MASK_C"], bits)))
            terms.append(self._parity_term(res, nbits))
            terms.append(self._af_term(res, other, one))
            terms.append(self._bit_term(self._is_zero(res), "Z"))
            terms.append(self._bit_term(self._is_neg(res), "S"))
            terms.append(self._bit_term(self._binop("CmpEQ", res, self._const(extreme, nbits)), "O"))
        else:
            # SHL/SHR: cc_dep1 is the result, cc_dep2 the value shifted by one less; AF is 0
            res = d1
            shifted = self._narrow(dep_2, nbits)
            if family == "SHL":
                terms.append(self._bit_term(self._is_neg(shifted), "C"))
            else:
                terms.append(self._binop("And", self._widen(shifted), self._const(1, bits)))
            terms.append(self._parity_term(res, nbits))
            terms.append(self._bit_term(self._is_zero(res), "Z"))
            terms.append(self._bit_term(self._is_neg(res), "S"))
            terms.append(self._bit_term(self._is_neg(self._binop("Xor", shifted, res)), "O"))

        result = terms[0]
        for i, term in enumerate(terms[1:]):
            result = self._binop("Or", result, term, idx=idx if i == len(terms) - 2 else None)
        return result

    def _is_zero(self, expr):
        return self._binop("CmpEQ", expr, self._const(0, expr.bits))

    def _is_neg(self, expr):
        # signed < 0 is exactly the most significant bit
        return self._binop("CmpLT", expr, self._const(0, expr.bits), signed=True)

    def _bit_term(self, bit_expr, flag: str):
        """Widen a 1-bit flag expression to the word and move it to its flag position."""
        shift = self.offsets[f"G_CC_SHIFT_{flag}"]
        widened = Expr.Convert(self.manager.next_atom(), bit_expr.bits, self.bits, False, bit_expr, **self.tags)
        if shift == 0:
            return widened
        return self._binop("Shl", widened, self._const(shift, 8))

    def _af_term(self, res, arg_l, arg_r):
        """AF = bit 4 of (res ^ arg_l ^ arg_r); the mask leaves it already in position."""
        xored = self._binop("Xor", self._binop("Xor", res, arg_l), arg_r)
        return self._widen(self._binop("And", xored, self._const(self.masks["G_CC_MASK_A"], res.bits)))

    def _parity_term(self, res, nbits: int):
        """
        PF = 1 iff the low byte of the result has an even number of set bits: fold the byte down to a nibble and
        index the 16-entry even-parity table 0x9669. A pure expression, so dead flag computations stay removable.
        """
        low_byte = self._narrow(res, 8) if nbits > 8 else res
        folded = self._binop("Xor", low_byte, self._binop("Shr", low_byte, self._const(4, 8)))
        index = self._binop("And", folded, self._const(0xF, 8))
        table = self._binop("Shr", self._const(0x9669, self.bits), index)
        bit = self._binop("And", table, self._const(1, self.bits))
        return self._binop("Shl", bit, self._const(self.offsets["G_CC_SHIFT_P"], 8))

    def _const(self, value: int, bits: int) -> Expr.Const:
        return Expr.Const(self.manager.next_atom(), value & ((1 << bits) - 1), bits)

    def _unop(self, op: str, operand):
        return Expr.UnaryOp(self.manager.next_atom(), op, operand, **self.tags)

    def _binop(self, op: str, op0, op1, signed: bool = False, idx: int | None = None):
        return Expr.BinaryOp(self.manager.next_atom() if idx is None else idx, op, [op0, op1], signed, **self.tags)

    def _narrow(self, expr, nbits: int):
        if expr.bits == nbits:
            return expr
        if isinstance(expr, Expr.Const):
            return self._const(expr.value_int, nbits)
        return Expr.Convert(self.manager.next_atom(), expr.bits, nbits, False, expr, **self.tags)

    def _widen(self, expr):
        if expr.bits == self.bits:
            return expr
        return Expr.Convert(self.manager.next_atom(), expr.bits, self.bits, False, expr, **self.tags)
