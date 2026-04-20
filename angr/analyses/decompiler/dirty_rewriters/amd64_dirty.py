from __future__ import annotations

from angr.ailment.statement import DirtyStatement, Statement, SideEffectStatement, Store
from angr.ailment.expression import Call, Const, DirtyExpression, Expression, Load, Reinterpret
from angr import sim_type
from .rewriter_base import DirtyRewriterBase


class AMD64DirtyRewriter(DirtyRewriterBase):
    """
    Rewrites AMD64 DirtyStatement and DirtyExpression.
    """

    __slots__ = ()

    def _rewrite_stmt(self, dirty: DirtyStatement) -> Statement | None:
        match dirty.dirty.callee:
            case "amd64g_dirtyhelper_storeF80le":
                return self._rewrite_storeF80le(dirty)

        call_expr = self._rewrite_expr_to_call(dirty.dirty)
        if call_expr is None:
            return None
        return SideEffectStatement(dirty.idx, call_expr, **dirty.tags)

    def _rewrite_expr(self, dirty: DirtyExpression) -> Expression | None:
        match dirty.callee:
            case "amd64g_dirtyhelper_loadF80le":
                return self._rewrite_loadF80le(dirty)

        return self._rewrite_expr_to_call(dirty)

    def _rewrite_expr_to_call(self, dirty: DirtyExpression) -> Call | None:
        match dirty.callee:
            case "amd64g_dirtyhelper_IN":
                if len(dirty.operands) != 2:
                    return None
                portno, size = dirty.operands
                if not isinstance(size, Const):
                    return None
                bits = size.value_int * self.arch.byte_width
                return Call(
                    idx=dirty.idx,
                    target=f"__in{self._inout_intrinsic_suffix(bits)}",
                    calling_convention=None,
                    prototype=sim_type.SimTypeFunction(
                        [self._inout_intrinsic_type(16)], self._inout_intrinsic_type(bits)
                    ).with_arch(self.arch),
                    args=(portno,),
                    bits=dirty.bits,
                    **dirty.tags,
                )
            case "amd64g_dirtyhelper_OUT":
                if len(dirty.operands) != 3:
                    return None
                portno, data, size = dirty.operands
                if not isinstance(size, Const):
                    return None
                bits = size.value_int * self.arch.byte_width
                return Call(
                    dirty.idx,
                    target=f"__out{self._inout_intrinsic_suffix(bits)}",
                    calling_convention=None,
                    prototype=sim_type.SimTypeFunction(
                        [self._inout_intrinsic_type(16), self._inout_intrinsic_type(bits)], sim_type.SimTypeBottom()
                    ).with_arch(self.arch),
                    args=(portno, data),
                    bits=None,
                    **dirty.tags,
                )
        return None

    #
    # x87 FP helpers
    #

    def _rewrite_storeF80le(self, dirty: DirtyStatement) -> Store | None:
        """
        storeF80le(addr, Reinterpret(F64->I64, fp_val)) -> Store(addr, fp_val, size=10)

        Rewrites the dirty helper into a regular 10-byte memory store.
        The size must match loadF80le (also 10 bytes) so that stack
        round-trips (fstpt/fldt) are recognized as the same variable.
        """
        expr = dirty.dirty
        if len(expr.operands) != 2:
            return None
        addr = expr.operands[0]
        value = expr.operands[1]
        # Unwrap Reinterpret(F64->I64, fp_val) to get the actual FP value
        if isinstance(value, Reinterpret) and value.from_type == "F" and value.to_type == "I":
            value = value.operand
        return Store(dirty.idx, addr, value, 10, "Iend_LE", **dirty.tags)

    @staticmethod
    def _rewrite_loadF80le(dirty: DirtyExpression) -> Load | None:
        """
        loadF80le(addr) -> Load(addr, size=10, long_double_load=True)

        Rewrites the dirty helper into a regular 10-byte memory load.
        The long_double_load tag marks the value as x87 extended precision
        so that downstream passes (codegen, type inference) can interpret
        the raw 80-bit encoding correctly.
        """
        if len(dirty.operands) != 1:
            return None
        addr = dirty.operands[0]
        tags = dict(dirty.tags)
        tags["long_double_load"] = True
        return Load(dirty.idx, addr, 10, "Iend_LE", **tags)

    #
    # in, out
    #

    @staticmethod
    def _inout_intrinsic_suffix(bits: int) -> str:
        match bits:
            case 8:
                return "byte"
            case 16:
                return "word"
            case 32:
                return "dword"
            case _:
                return f"_{bits}"

    @staticmethod
    def _inout_intrinsic_type(bits: int) -> sim_type.SimType:
        return sim_type.SimTypeNum(bits, signed=False)
