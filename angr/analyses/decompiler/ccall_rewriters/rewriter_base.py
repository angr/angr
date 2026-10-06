from __future__ import annotations

from typing import TYPE_CHECKING, Any

from angr import ailment
from angr.ailment.expression import negate
from angr.sim_type import SimTypeDouble, SimTypeFunction, SimTypeInt, SimTypeLongLong, SimTypeShort

if TYPE_CHECKING:
    from angr.ailment.manager import Manager
    from angr.rustylib.ailment import TagsView

# VEX condition codes shared by x86 and amd64 (odd code = negation of the even one below it)
_COND_B = 2
_COND_Z = 4
_COND_S = 8


def _strip_converts(expr: ailment.Expr.Expression) -> ailment.Expr.Expression:
    while isinstance(expr, ailment.Expr.Convert) and not expr.is_signed:
        expr = expr.operand
    return expr


class CCallRewriterBase:
    """
    The base class for CCall rewriters.
    """

    __slots__ = (
        "ail_manager",
        "livein_vvar_ids",
        "project",
        "result",
    )

    def __init__(
        self,
        ccall: ailment.Expr.VEXCCallExpression,
        project,
        ail_manager: Manager,
        rename_ccalls: bool = False,
        livein_vvar_ids: set[int] | None = None,
    ):
        self.project = project
        self.ail_manager = ail_manager
        # ids of vvars whose value is the one on function entry (no definition in the function)
        self.livein_vvar_ids = livein_vvar_ids
        self.result: ailment.Expr.Expression | None = self._rewrite(ccall)
        assert self.result is None or self.result.bits == ccall.bits, (
            f"Rewritten ccall expression has {self.result.bits} bits, expecting {ccall.bits} bits"
        )
        if rename_ccalls and self.result is None and ccall.callee != "_ccall":
            # keep the original callee so the ccall can still be rewritten once its operands become constant
            self.result = ailment.Expr.VEXCCallExpression(
                ccall.idx, "_ccall", ccall.operands, ccall.bits, **{**ccall.tags, "vex_callee": ccall.callee}
            )

    @staticmethod
    def _original_callee(ccall: ailment.Expr.VEXCCallExpression) -> str:
        if ccall.callee == "_ccall":
            callee = ccall.tags.get("vex_callee")
            if isinstance(callee, str):
                return callee
        return ccall.callee

    def _rewrite_fxam(self, ccall: ailment.Expr.VEXCCallExpression) -> ailment.Expr.Expression | None:
        """
        ``calculate_FXAM(tag, dbl)`` -> ``__fxam(value)``: the x87 tag is dropped (registers are assumed valid) and the
        I64 operand is viewed as the double it carries.
        """
        if len(ccall.operands) != 2:
            return None
        value = ccall.operands[1]
        if isinstance(value, ailment.Expr.Reinterpret) and value.from_type == "F" and value.to_type == "I":
            value = value.operand
        else:
            value = ailment.Expr.Reinterpret(self.ail_manager.next_atom(), 64, "I", 64, "F", value, **ccall.tags)
        return ailment.Expr.Call(
            ccall.idx,
            "__fxam",
            calling_convention=None,
            prototype=SimTypeFunction([SimTypeDouble()], SimTypeInt(signed=False)).with_arch(self.project.arch),
            args=(value,),
            bits=ccall.bits,
            **ccall.tags,
        )

    def _rewrite_control_word_read(
        self, ccall: ailment.Expr.VEXCCallExpression, helper: str
    ) -> ailment.Expr.Expression | None:
        """
        ``create_mxcsr(sseround)`` (stmxcsr) -> ``_mm_getcsr()`` and ``create_fpucw(fpround)`` (fnstcw) ->
        ``__fnstcw()``: VEX rebuilds the register from the modelled rounding mode, so read the real one instead.
        """
        if helper == "create_mxcsr":
            name, ret_ty = "_mm_getcsr", SimTypeInt(signed=False)
        elif helper == "create_fpucw":
            name, ret_ty = "__fnstcw", SimTypeShort(signed=False)
        else:
            return None
        ret_bits = ret_ty.with_arch(self.project.arch).size
        assert ret_bits is not None and ret_bits <= ccall.bits
        call = ailment.Expr.Call(
            ccall.idx if ret_bits == ccall.bits else self.ail_manager.next_atom(),
            name,
            calling_convention=None,
            prototype=SimTypeFunction([], ret_ty).with_arch(self.project.arch),
            args=(),
            bits=ret_bits,
            **ccall.tags,
        )
        if ret_bits == ccall.bits:
            return call
        return ailment.Expr.Convert(ccall.idx, ret_bits, ccall.bits, False, call, **ccall.tags)

    def _rewrite(self, ccall: ailment.Expr.VEXCCallExpression) -> ailment.Expr.Expression | None:
        raise NotImplementedError

    def _is_livein_flags_thunk(
        self, thunk: tuple[ailment.Expr.Expression, ...] | list[ailment.Expr.Expression]
    ) -> bool:
        if not self.livein_vvar_ids or len(thunk) != 4:
            return False
        for expr, reg_name in zip(thunk, ("cc_op", "cc_dep1", "cc_dep2", "cc_ndep")):
            if not (
                isinstance(expr, ailment.Expr.VirtualVariable)
                and expr.was_reg
                and expr.reg_offset == self.project.arch.registers[reg_name][0]
                and expr.varid in self.livein_vvar_ids
            ):
                return False
        return True

    def _rewrite_livein_flags(
        self, ccall: ailment.Expr.VEXCCallExpression, callee: str, prefix: str, flags_all: str, flags_c: str
    ) -> ailment.Expr.Expression | None:
        """
        A flags thunk (cc_op, cc_dep1, cc_dep2, cc_ndep) that is entirely live-in means no flag-setting instruction ran
        between function entry and this point, so the flags here are the entry flags: read them with __readeflags().
        """
        if callee == f"{prefix}calculate_condition":
            if len(ccall.operands) != 5 or not isinstance(ccall.operands[0], ailment.Expr.Const):
                return None
            thunk = ccall.operands[1:]
        elif callee in {flags_all, flags_c}:
            thunk = ccall.operands
        else:
            return None
        if not self._is_livein_flags_thunk(thunk):
            return None

        tags = ccall.tags
        if callee == flags_all:
            # O|S|Z|A|C|P
            return self._masked_flags(ccall, 0x8D5, ccall.idx)
        if callee == flags_c:
            return self._masked_flags(ccall, 0x1, ccall.idx)

        cond = ccall.operands[0]
        assert isinstance(cond, ailment.Expr.Const)
        cond_v = cond.value_int
        # VEX condition codes: even numbers test the condition, odd numbers its negation
        negate = bool(cond_v & 1)
        base = cond_v & ~1
        masks = {0: 0x800, 2: 0x1, 4: 0x40, 6: 0x41, 8: 0x80, 10: 0x4}  # O, B, Z, BE, S, P
        if base in masks:
            r = self._flags_test(ccall, masks[base], not negate)
        elif base in {12, 14}:
            # L: SF != OF, i.e. ((flags >> 7) ^ (flags >> 11)) & 1; LE: ZF | L
            sf, of = (
                ailment.Expr.BinaryOp(
                    self.ail_manager.next_atom(),
                    "Shr",
                    [self._read_flags(ccall), ailment.Expr.Const(self.ail_manager.next_atom(), shift, 8)],
                    False,
                    **tags,
                )
                for shift in (7, 11)
            )
            sf_xor_of = ailment.Expr.BinaryOp(
                self.ail_manager.next_atom(),
                "And",
                [
                    ailment.Expr.BinaryOp(self.ail_manager.next_atom(), "Xor", [sf, of], False, **tags),
                    ailment.Expr.Const(self.ail_manager.next_atom(), 1, sf.bits),
                ],
                False,
                **tags,
            )
            r = ailment.Expr.BinaryOp(
                self.ail_manager.next_atom(),
                "CmpEQ" if negate else "CmpNE",
                (sf_xor_of, ailment.Expr.Const(self.ail_manager.next_atom(), 0, sf.bits)),
                False,
                **tags,
            )
            if base == 14:
                zf = self._flags_test(ccall, 0x40, not negate)
                r = ailment.Expr.BinaryOp(
                    self.ail_manager.next_atom(), "LogicalAnd" if negate else "LogicalOr", (zf, r), False, **tags
                )
        else:
            return None
        return ailment.Expr.Convert(ccall.idx, r.bits, ccall.bits, False, r, **tags)

    #
    # adc / sbb thunks: DEP1 = argL, DEP2 = argR ^ oldC, NDEP = oldC (libVEX ACTIONS_ADC / ACTIONS_SBB)
    #

    def _to_bits(
        self, expr: ailment.Expr.Expression, bits: int, tags: TagsView | dict[str, Any]
    ) -> ailment.Expr.Expression:
        """Resize *expr* to *bits* as an unsigned value, folding constants and unsigned-widening Converts."""
        if expr.bits == bits:
            return expr
        if isinstance(expr, ailment.Expr.Const):
            return ailment.Expr.Const(self.ail_manager.next_atom(), expr.value_int & ((1 << bits) - 1), bits, **tags)
        if (
            isinstance(expr, ailment.Expr.Convert)
            and not expr.is_signed
            and expr.from_bits <= expr.to_bits
            and expr.from_bits <= bits
        ):
            return self._to_bits(expr.operand, bits, tags)
        return ailment.Expr.Convert(self.ail_manager.next_atom(), expr.bits, bits, False, expr, **tags)

    def _carry_in(
        self, ndep: ailment.Expr.Expression, bits: int, tags: TagsView | dict[str, Any]
    ) -> ailment.Expr.Expression:
        """oldC = NDEP & 1, at *bits*; the mask is dropped when NDEP is visibly a 0/1 value."""
        if isinstance(ndep, ailment.Expr.Const):
            return ailment.Expr.Const(self.ail_manager.next_atom(), ndep.value_int & 1, bits, **tags)
        inner = ndep
        while isinstance(inner, ailment.Expr.Convert) and not inner.is_signed and inner.from_bits <= inner.to_bits:
            inner = inner.operand
        is_bit = inner.bits == 1 or (
            isinstance(inner, ailment.Expr.BinaryOp)
            and inner.op == "And"
            and isinstance(inner.operands[1], ailment.Expr.Const)
            and inner.operands[1].value_int == 1
        )
        resized = self._to_bits(ndep, bits, tags)
        if is_bit:
            return resized
        return ailment.Expr.BinaryOp(
            self.ail_manager.next_atom(),
            "And",
            [resized, ailment.Expr.Const(self.ail_manager.next_atom(), 1, bits, **tags)],
            False,
            bits=bits,
            **tags,
        )

    def _adc_sbb_operands(
        self,
        ccall: ailment.Expr.VEXCCallExpression,
        nbits: int,
        dep_1: ailment.Expr.Expression,
        dep_2: ailment.Expr.Expression,
        ndep: ailment.Expr.Expression,
    ) -> tuple[ailment.Expr.Expression, ailment.Expr.Expression, ailment.Expr.Expression]:
        """Recover (argL, argR, oldC) at the operation width; argR = DEP2 ^ oldC is undone syntactically when
        possible (e.g. ``adc x, 0`` stores DEP2 == NDEP)."""
        tags = ccall.tags
        arg_l = self._to_bits(dep_1, nbits, tags)
        old_c = self._carry_in(ndep, nbits, tags)
        d2 = self._to_bits(dep_2, nbits, tags)
        cores = (_strip_converts(old_c), _strip_converts(ndep))

        def is_old_c(e: ailment.Expr.Expression) -> bool:
            # oldC is a 0/1 value, so any chain of unsigned resizes of it is still oldC
            core = _strip_converts(e)
            return any(core.likes(c) for c in cores)

        if isinstance(d2, ailment.Expr.Const) and isinstance(old_c, ailment.Expr.Const):
            arg_r = ailment.Expr.Const(
                self.ail_manager.next_atom(), (d2.value_int ^ old_c.value_int) & ((1 << nbits) - 1), nbits, **tags
            )
        elif is_old_c(d2):
            arg_r = ailment.Expr.Const(self.ail_manager.next_atom(), 0, nbits, **tags)
        elif isinstance(d2, ailment.Expr.BinaryOp) and d2.op == "Xor" and is_old_c(d2.operands[1]):
            arg_r = d2.operands[0]
        elif isinstance(d2, ailment.Expr.BinaryOp) and d2.op == "Xor" and is_old_c(d2.operands[0]):
            arg_r = d2.operands[1]
        else:
            arg_r = ailment.Expr.BinaryOp(self.ail_manager.next_atom(), "Xor", [d2, old_c], False, bits=nbits, **tags)
        return arg_l, arg_r, old_c

    @staticmethod
    def _is_cheap(expr: ailment.Expr.Expression) -> bool:
        """An operand that the carry formulas may repeat: an atom, or an atom resized or masked to one bit."""
        while isinstance(expr, ailment.Expr.Convert | ailment.Expr.Extract):
            expr = expr.operand if isinstance(expr, ailment.Expr.Convert) else expr.base
        if (
            isinstance(expr, ailment.Expr.BinaryOp)
            and expr.op == "And"
            and isinstance(expr.operands[1], ailment.Expr.Const)
            and expr.operands[1].value_int == 1
        ):
            return CCallRewriterBase._is_cheap(expr.operands[0])
        return isinstance(
            expr,
            ailment.Expr.VirtualVariable
            | ailment.Expr.Const
            | ailment.Expr.Register
            | ailment.Expr.Tmp
            | ailment.Expr.StackBaseOffset,
        )

    def _adc_sbb_carry(
        self,
        ccall: ailment.Expr.VEXCCallExpression,
        nbits: int,
        is_adc: bool,
        dep_1: ailment.Expr.Expression,
        dep_2: ailment.Expr.Expression,
        ndep: ailment.Expr.Expression,
    ) -> ailment.Expr.Expression | None:
        """
        Carry-out of ``argL + argR + oldC`` (adc) or borrow-out of ``argL - argR - oldC`` (sbb), as a 1-bit value.

        libVEX: adc cf = oldC ? res <=u argL : res <u argL; sbb cf = oldC ? argL <=u argR : argL <u argR. Emitted as
        adc: ``argL + argR <u argL || argL + argR + oldC <u argL + argR``; sbb: ``argL <u argR || oldC && argL == argR``.

        The formulas repeat argL/argR; None when a repeated operand is not an atom, since in an adc chain each
        carry is the next adc's operand and repeating propagated expressions grows them exponentially.
        """
        tags = ccall.tags
        arg_l, arg_r, old_c = self._adc_sbb_operands(ccall, nbits, dep_1, dep_2, ndep)
        zero_r = isinstance(arg_r, ailment.Expr.Const) and arg_r.value_int == 0
        if not (self._is_cheap(arg_l) and (zero_r or self._is_cheap(arg_r))) and not (zero_r and not is_adc):
            return None

        def cmp(op: str, a: ailment.Expr.Expression, b: ailment.Expr.Expression) -> ailment.Expr.BinaryOp:
            return ailment.Expr.BinaryOp(self.ail_manager.next_atom(), op, [a, b], False, bits=1, **tags)

        def arith(op: str, a: ailment.Expr.Expression, b: ailment.Expr.Expression) -> ailment.Expr.BinaryOp:
            return ailment.Expr.BinaryOp(self.ail_manager.next_atom(), op, [a, b], False, bits=nbits, **tags)

        if is_adc:
            if zero_r:
                return cmp("CmpLT", arith("Add", arg_l, old_c), arg_l)
            partial = arith("Add", arg_l, arg_r)
            first, second = cmp("CmpLT", partial, arg_l), cmp("CmpLT", arith("Add", partial, old_c), partial)
        else:
            second = cmp("LogicalAnd", self._as_bool(old_c, tags), cmp("CmpEQ", arg_l, arg_r))
            if zero_r:
                return second
            first = cmp("CmpLT", arg_l, arg_r)
        return cmp("LogicalOr", first, second)

    def _as_bool(self, expr: ailment.Expr.Expression, tags: TagsView | dict[str, Any]) -> ailment.Expr.Expression:
        """*expr* != 0 as a 1-bit value, unwrapping a zero-extended 1-bit value."""
        if expr.bits == 1:
            return expr
        if isinstance(expr, ailment.Expr.Convert) and not expr.is_signed and expr.from_bits == 1:
            return expr.operand
        zero = ailment.Expr.Const(self.ail_manager.next_atom(), 0, expr.bits, **tags)
        return ailment.Expr.BinaryOp(self.ail_manager.next_atom(), "CmpNE", [expr, zero], False, bits=1, **tags)

    def _adc_sbb_result(
        self,
        ccall: ailment.Expr.VEXCCallExpression,
        nbits: int,
        is_adc: bool,
        dep_1: ailment.Expr.Expression,
        dep_2: ailment.Expr.Expression,
        ndep: ailment.Expr.Expression,
    ) -> ailment.Expr.Expression:
        """``argL + argR + oldC`` (adc) or ``argL - argR - oldC`` (sbb) at the operation width."""
        tags = ccall.tags
        arg_l, arg_r, old_c = self._adc_sbb_operands(ccall, nbits, dep_1, dep_2, ndep)
        op = "Add" if is_adc else "Sub"
        res = arg_l
        if not (isinstance(arg_r, ailment.Expr.Const) and arg_r.value_int == 0):
            res = ailment.Expr.BinaryOp(self.ail_manager.next_atom(), op, [res, arg_r], False, bits=nbits, **tags)
        return ailment.Expr.BinaryOp(self.ail_manager.next_atom(), op, [res, old_c], False, bits=nbits, **tags)

    def _adc_sbb_condition(
        self,
        ccall: ailment.Expr.VEXCCallExpression,
        cond_v: int,
        nbits: int,
        is_adc: bool,
        dep_1: ailment.Expr.Expression,
        dep_2: ailment.Expr.Expression,
        ndep: ailment.Expr.Expression,
    ) -> ailment.Expr.Expression | None:
        """calculate_condition over an adc/sbb thunk for the carry (B/NB), zero (Z/NZ) and sign (S/NS) codes."""
        tags = ccall.tags
        base = cond_v & ~1
        if base == _COND_B:
            r = self._adc_sbb_carry(ccall, nbits, is_adc, dep_1, dep_2, ndep)
            if r is None:
                return None
        elif base in {_COND_Z, _COND_S}:
            res = self._adc_sbb_result(ccall, nbits, is_adc, dep_1, dep_2, ndep)
            zero = ailment.Expr.Const(self.ail_manager.next_atom(), 0, nbits, **tags)
            r = ailment.Expr.BinaryOp(
                self.ail_manager.next_atom(),
                "CmpEQ" if base == _COND_Z else "CmpLT",
                [res, zero],
                base == _COND_S,
                bits=1,
                **tags,
            )
        else:
            return None
        if cond_v & 1:
            r = negate(r, self.ail_manager)
        return ailment.Expr.Convert(ccall.idx, 1, ccall.bits, False, r, **tags)

    def _adc_sbb_carry_flag(
        self,
        ccall: ailment.Expr.VEXCCallExpression,
        nbits: int,
        is_adc: bool,
        dep_1: ailment.Expr.Expression,
        dep_2: ailment.Expr.Expression,
        ndep: ailment.Expr.Expression,
    ) -> ailment.Expr.Expression | None:
        """calculate_eflags_c / calculate_rflags_c over an adc/sbb thunk: the carry as a 0/1 value of the ccall width."""
        r = self._adc_sbb_carry(ccall, nbits, is_adc, dep_1, dep_2, ndep)
        if r is None:
            return None
        return ailment.Expr.Convert(ccall.idx, 1, ccall.bits, False, r, **ccall.tags)

    def _read_flags(self, ccall: ailment.Expr.VEXCCallExpression) -> ailment.Expr.Call:
        ret_ty = SimTypeLongLong(signed=False) if self.project.arch.bits == 64 else SimTypeInt(signed=False)
        return ailment.Expr.Call(
            self.ail_manager.next_atom(),
            "__readeflags",
            calling_convention=None,
            prototype=SimTypeFunction([], ret_ty).with_arch(self.project.arch),
            args=(),
            bits=self.project.arch.bits,
            **ccall.tags,
        )

    def _masked_flags(self, ccall: ailment.Expr.VEXCCallExpression, mask: int, idx: int) -> ailment.Expr.Expression:
        flags = self._read_flags(ccall)
        r = ailment.Expr.BinaryOp(
            idx if flags.bits == ccall.bits else self.ail_manager.next_atom(),
            "And",
            [flags, ailment.Expr.Const(self.ail_manager.next_atom(), mask, flags.bits)],
            False,
            **ccall.tags,
        )
        if r.bits == ccall.bits:
            return r
        return ailment.Expr.Convert(idx, r.bits, ccall.bits, False, r, **ccall.tags)

    def _flags_test(self, ccall: ailment.Expr.VEXCCallExpression, mask: int, flag_set: bool) -> ailment.Expr.BinaryOp:
        """(__readeflags() & mask) != 0, or == 0 when *flag_set* is False."""
        masked = self._masked_flags(ccall, mask, self.ail_manager.next_atom())
        zero = ailment.Expr.Const(self.ail_manager.next_atom(), 0, masked.bits)
        return ailment.Expr.BinaryOp(
            self.ail_manager.next_atom(), "CmpNE" if flag_set else "CmpEQ", (masked, zero), False, **ccall.tags
        )

    def _copied_flag_test(
        self, ccall: ailment.Expr.VEXCCallExpression, flags: ailment.Expr.Expression, mask: int, flag_set: bool
    ) -> ailment.Expr.Expression:
        """A condition on flags stored verbatim (G_CC_OP_COPY): (flags & mask) != 0, or == 0 when the flags of
        *mask* must be clear."""
        masked = ailment.Expr.BinaryOp(
            self.ail_manager.next_atom(),
            "And",
            [flags, ailment.Expr.Const(self.ail_manager.next_atom(), mask, flags.bits)],
            False,
            **ccall.tags,
        )
        zero = ailment.Expr.Const(self.ail_manager.next_atom(), 0, flags.bits)
        r = ailment.Expr.BinaryOp(ccall.idx, "CmpNE" if flag_set else "CmpEQ", (masked, zero), False, **ccall.tags)
        return ailment.Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
