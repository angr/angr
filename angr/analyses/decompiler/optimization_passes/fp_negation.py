from __future__ import annotations

import logging

from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Convert, Expression, Extract, UnaryOp, VirtualVariable
from angr.ailment.statement import Assignment, Statement
from angr.analyses.decompiler.ail_simplifier import AILBlockRewriter
from angr.calling_conventions import SimRegArg
from angr.sim_type import SimTypeFloat

from .optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(__name__)

# Sign-bit masks emitted for FP negation, keyed by the XOR width.  Scalar
# negation flips the single sign bit (float 32-bit, double 64-bit); SSE vector
# negation (xorps/xorpd) may set just lane 0 or every lane, so accept both.
# Because every rewrite is gated on the operand actually being floating point,
# matching narrow scalar XORs here is safe (it won't touch integer INT_MIN xor).
_FP_SIGN_MASKS_BY_WIDTH: dict[int, set[int]] = {
    32: {0x80000000},
    64: {0x8000000000000000},
    128: {
        0x80000000,  # float, lane-0 sign bit
        0x80000000_80000000_80000000_80000000,  # float, all four lanes
        0x8000000000000000,  # double, lane-0 sign bit
        0x80000000000000008000000000000000,  # double, both lanes
    },
}


class _SignFlipRewriter(AILBlockRewriter):
    """Rewrite FP sign-bit XORs into negations, gated on FP data domain."""

    def __init__(self, is_fp):
        super().__init__()
        self._is_fp = is_fp
        self.changed = False

    def _handle_expr(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None):
        rewritten = self._rewrite(expr)
        if rewritten is not None:
            self.changed = True
            return rewritten
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)

    def _rewrite(self, expr: Expression) -> Expression | None:
        # SSE form: Extract(Conv(N->128, x) ^ sign_mask, N@0)  =>  Neg(x)
        if isinstance(expr, Extract) and expr.is_lsb_extract():
            xored = self._match_xor_sign(expr.base)
            if isinstance(xored, Convert) and xored.to_bits > xored.from_bits:
                inner = xored.operand
                if inner.bits == expr.bits and self._is_fp(inner):
                    return UnaryOp(expr.idx, "Neg", inner, floating_point=True, **expr.tags)

        # Scalar form: (x ^ sign_mask)  =>  Neg(x), for FP x of matching width.
        if isinstance(expr, BinaryOp):
            xored = self._match_xor_sign(expr)
            if xored is not None and xored.bits == expr.bits and self._is_fp(xored):
                return UnaryOp(expr.idx, "Neg", xored, floating_point=True, **expr.tags)

        return None

    @staticmethod
    def _match_xor_sign(expr: Expression) -> Expression | None:
        """Match ``v ^ sign_mask`` at the FP width of *expr* and return ``v``."""
        if not isinstance(expr, BinaryOp) or expr.op != "Xor":
            return None
        masks = _FP_SIGN_MASKS_BY_WIDTH.get(expr.bits)
        if masks is None:
            return None
        lhs, rhs = expr.operands
        if isinstance(rhs, Const) and rhs.value in masks:
            return lhs
        if isinstance(lhs, Const) and lhs.value in masks:
            return rhs
        return None


class FpNegation(OptimizationPass):
    """
    Rewrite floating-point sign-bit XORs (``xorps``/``xorpd``) into negation.

    The lifter cannot tell an FP sign flip from an arbitrary 128-bit integer
    XOR with a sign-shaped constant; both produce the same AIL.  This pass runs
    after variable recovery so it can consult the recovered data domain and only
    rewrite when the XORed value is actually floating-point (recovered FP type,
    an FP argument register, or FP provenance in the expression).
    """

    ARCHES = ["X86", "AMD64"]
    PLATFORMS = ["linux", "windows"]
    STAGE = OptimizationPassStage.AFTER_VARIABLE_RECOVERY
    NAME = "Rewrite FP sign-bit XOR to negation"
    DESCRIPTION = __doc__.strip()

    def __init__(self, func, *args, **kwargs):
        super().__init__(func, *args, **kwargs)
        self.analyze()

    def _check(self):
        if self._graph is None:
            return False, None
        for block in self._graph.nodes():
            if self._block_has_sign_xor(block):
                return True, None
        return False, None

    @staticmethod
    def _block_has_sign_xor(block: Block) -> bool:
        stack: list = list(block.statements)
        while stack:
            node = stack.pop()
            if _SignFlipRewriter._match_xor_sign(node) is not None:
                return True
            stack.extend(_subexprs(node))
        return False

    def _analyze(self, cache=None):
        assert self._graph is not None
        var_manager = None
        if self._variable_kb is not None:
            try:
                var_manager = self._variable_kb.variables[self._func.addr]
            except KeyError:
                var_manager = None
        fp_arg_offsets = self._fp_arg_reg_offsets()

        # Map each virtual variable to its defining source expression so we can
        # trace FP-ness through locals (e.g. a local that holds the result of an
        # earlier FP negation is itself FP, even though typehoon types it as int).
        vvar_defs: dict[int, Expression] = {}
        for block in self._graph.nodes():
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    vvar_defs[stmt.dst.varid] = stmt.src

        def is_fp(expr: Expression) -> bool:
            return self._value_is_fp(expr, var_manager, fp_arg_offsets, vvar_defs, set())

        for block in list(self._graph.nodes()):
            rewriter = _SignFlipRewriter(is_fp)
            new_block = rewriter.walk(block)
            if rewriter.changed and new_block is not None and new_block is not block:
                self._update_block(block, new_block)

    def _fp_arg_reg_offsets(self) -> set[int]:
        """Register offsets that hold FP arguments for this function's prototype."""
        offsets: set[int] = set()
        cc = self._func.calling_convention
        proto = self._func.prototype
        if cc is None or proto is None or proto.args is None:
            return offsets
        try:
            arg_locs = cc.arg_locs(proto)
        except (ValueError, TypeError):
            return offsets
        regs = self.project.arch.registers
        for loc in arg_locs:
            if isinstance(loc, SimRegArg) and loc.is_fp and loc.reg_name in regs:
                offsets.add(regs[loc.reg_name][0])
        return offsets

    @classmethod
    def _value_is_fp(
        cls,
        expr: Expression,
        var_manager,
        fp_arg_offsets: set[int],
        vvar_defs: dict[int, Expression],
        seen: set[int],
    ) -> bool:
        # FP provenance in the expression itself.
        if isinstance(expr, Convert) and Convert.TYPE_FP in (expr.from_type, expr.to_type):
            return True
        if isinstance(expr, (UnaryOp, BinaryOp)) and getattr(expr, "floating_point", False):
            return True

        # Recovered variable type.
        var = getattr(expr, "variable", None)
        if var is not None and var_manager is not None:
            try:
                vartype = var_manager.get_variable_type(var)
            except (KeyError, AttributeError):
                vartype = None
            if isinstance(vartype, SimTypeFloat):
                return True

        if isinstance(expr, VirtualVariable):
            # FP value in an FP argument register (typehoon infers integer from
            # the bare sign-flip XOR, so the prototype is the source of truth).
            if (
                expr.was_parameter
                and isinstance(expr.parameter_reg_offset, int)
                and expr.parameter_reg_offset in fp_arg_offsets
            ):
                return True
            # Trace through the variable's definition (e.g. a local that holds the
            # result of an earlier FP op / sign flip is itself FP).
            if expr.varid not in seen and expr.varid in vvar_defs:
                seen.add(expr.varid)
                return cls._value_is_fp(vvar_defs[expr.varid], var_manager, fp_arg_offsets, vvar_defs, seen)

        # Unwrap widening/narrowing Converts and Extracts.
        if isinstance(expr, Convert):
            return cls._value_is_fp(expr.operand, var_manager, fp_arg_offsets, vvar_defs, seen)
        if isinstance(expr, Extract):
            return cls._value_is_fp(expr.base, var_manager, fp_arg_offsets, vvar_defs, seen)

        # A sign-flip XOR of an FP value is itself FP.
        inner = _SignFlipRewriter._match_xor_sign(expr)
        if inner is not None:
            return cls._value_is_fp(inner, var_manager, fp_arg_offsets, vvar_defs, seen)

        return False


def _subexprs(node) -> list:
    out = []
    for attr in ("operands", "args"):
        seq = getattr(node, attr, None)
        if seq:
            out.extend(seq)
    for attr in ("src", "data", "condition", "operand", "base", "addr", "ret_expr", "cond", "iftrue", "iffalse"):
        sub = getattr(node, attr, None)
        if isinstance(sub, Expression):
            out.append(sub)
    for rexpr in getattr(node, "ret_exprs", None) or []:
        out.append(rexpr)
    return out
