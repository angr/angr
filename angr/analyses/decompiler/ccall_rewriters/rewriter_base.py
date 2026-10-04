from __future__ import annotations

from typing import TYPE_CHECKING

from angr import ailment
from angr.sim_type import SimTypeDouble, SimTypeFunction, SimTypeInt, SimTypeLongLong, SimTypeShort

if TYPE_CHECKING:
    from angr.ailment.manager import Manager


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
