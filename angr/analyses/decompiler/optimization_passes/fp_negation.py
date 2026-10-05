from __future__ import annotations

import logging

from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Const, Convert, Expression, Extract, Phi, UnaryOp, VirtualVariable
from angr.ailment.statement import Assignment, Statement
from angr.ailment.utils import is_lsb_extract
from angr.analyses.decompiler.ail_simplifier import AILBlockRewriter
from angr.calling_conventions import SimRegArg

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

    def __init__(self, is_fp, int_consumed_vvars: set[int]):
        super().__init__()
        self._is_fp = is_fp
        self._int_consumed_vvars = int_consumed_vvars
        self.changed = False
        # True while descending through an integer operation: a sign-bit XOR whose result feeds integer arithmetic or
        # an integer compare (``add ecx, 0x7fffffff`` on reloaded float bits) manipulates bits and is not a negation
        self._int_consumer = False

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None) -> Statement:
        if not (isinstance(stmt.dst, VirtualVariable) and stmt.dst.varid in self._int_consumed_vvars):
            return super()._handle_Assignment(stmt_idx, stmt, block)
        # every use of the assigned vvar reads it as an integer, so its definition is integer-consumed too
        saved = self._int_consumer
        self._int_consumer = True
        try:
            return super()._handle_Assignment(stmt_idx, stmt, block)
        finally:
            self._int_consumer = saved

    def _handle_expr(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if not self._int_consumer:
            rewritten = self._rewrite(expr)
            if rewritten is not None:
                self.changed = True
                return rewritten
        saved = self._int_consumer
        self._int_consumer = self._consumes_bits(expr, saved)
        try:
            return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
        finally:
            self._int_consumer = saved

    @staticmethod
    def _consumes_bits(expr: Expression, inherited: bool) -> bool:
        """Whether the operands of *expr* are read as integers: FP operations reset the context, integer operations
        set it, Extract passes it on, and everything else (stores, calls, phis, ITE) reads a value."""
        if isinstance(expr, (BinaryOp, UnaryOp)):
            return not expr.floating_point
        if isinstance(expr, Convert):
            return expr.from_type != Convert.TYPE_FP and expr.to_type != Convert.TYPE_FP
        if isinstance(expr, Extract):
            return inherited
        return False

    def _rewrite(self, expr: Expression) -> Expression | None:
        # SSE form: Extract(Conv(N->128, x) ^ sign_mask, N@0)  =>  Neg(x)
        if isinstance(expr, Extract) and is_lsb_extract(expr):
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
    XOR with a sign-shaped constant; both produce the same AIL.  This pass only
    rewrites when the XORed value is provably floating-point: it lives in an FP
    argument register of the prototype, or has FP provenance in the expression
    (FP conversions and operations, traced through local definitions).

    It runs right before variable recovery, ahead of KnownPatternOutliner (which
    would otherwise outline the XOR as an opaque ``fneg()`` call), so Typehoon
    sees a floating-point negation instead of an integer XOR.
    """

    ARCHES = ["X86", "AMD64"]
    PLATFORMS = ["linux", "windows"]
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
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
        fp_arg_offsets = self._fp_arg_reg_offsets()

        # Map each virtual variable to its defining source expression so we can
        # trace FP-ness through locals (e.g. a local that holds the result of an
        # earlier FP negation is itself FP, even though typehoon types it as int).
        vvar_defs: dict[int, Expression] = {}
        # Phi-defined register vvars in the function's entry block whose register holds an FP argument: when the
        # entry is a loop head (e.g. Go's stack-check back edge), the incoming parameter is the phi's implicit
        # entry source.
        entry_fp_params: set[int] = set()
        for block in self._graph.nodes():
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    vvar_defs[stmt.dst.varid] = stmt.src
                    if (
                        block.addr == self._func.addr
                        and isinstance(stmt.src, Phi)
                        and stmt.dst.was_reg
                        and stmt.dst.reg_offset in fp_arg_offsets
                    ):
                        entry_fp_params.add(stmt.dst.varid)

        def is_fp(expr: Expression) -> bool:
            return self._value_is_fp(expr, fp_arg_offsets, vvar_defs, entry_fp_params, set())

        int_consumed_vvars = self._int_consumed_vvars()
        for block in list(self._graph.nodes()):
            rewriter = _SignFlipRewriter(is_fp, int_consumed_vvars)
            new_block = rewriter.walk(block)
            if rewriter.changed and new_block is not None and new_block is not block:
                self._update_block(block, new_block)

    def _int_consumed_vvars(self) -> set[int]:
        """Vvars whose every direct use is an operand of an integer operation (phi uses do not count)."""
        assert self._graph is not None
        value_used: set[int] = set()
        int_used: set[int] = set()

        def visit(node, int_ctx: bool) -> None:
            for child in _subexprs(node):
                if isinstance(child, VirtualVariable):
                    (int_used if int_ctx else value_used).add(child.varid)
                else:
                    visit(child, _SignFlipRewriter._consumes_bits(child, int_ctx))

        phis: list[Assignment] = []
        for block in self._graph.nodes():
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi):
                    phis.append(stmt)
                    continue
                visit(stmt, False)
        # a phi reads its sources the way its own result is read
        changed = True
        while changed:
            changed = False
            for stmt in phis:
                assert isinstance(stmt.dst, VirtualVariable) and isinstance(stmt.src, Phi)
                for used in (int_used, value_used):
                    if stmt.dst.varid not in used:
                        continue
                    for _, src in stmt.src.src_and_vvars:
                        if src is not None and src.varid not in used:
                            used.add(src.varid)
                            changed = True
        return int_used - value_used

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
        fp_arg_offsets: set[int],
        vvar_defs: dict[int, Expression],
        entry_fp_params: set[int],
        seen: set[int],
    ) -> bool:
        # FP provenance in the expression itself.
        if isinstance(expr, Convert) and Convert.TYPE_FP in (expr.from_type, expr.to_type):
            return True
        if isinstance(expr, (UnaryOp, BinaryOp)) and expr.floating_point:
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
                src = vvar_defs[expr.varid]
                if isinstance(src, Phi):
                    return cls._phi_is_fp(
                        src, expr.varid in entry_fp_params, fp_arg_offsets, vvar_defs, entry_fp_params, seen
                    )
                return cls._value_is_fp(src, fp_arg_offsets, vvar_defs, entry_fp_params, seen)

        # Unwrap widening/narrowing Converts and Extracts.
        if isinstance(expr, Convert):
            return cls._value_is_fp(expr.operand, fp_arg_offsets, vvar_defs, entry_fp_params, seen)
        if isinstance(expr, Extract):
            return cls._value_is_fp(expr.base, fp_arg_offsets, vvar_defs, entry_fp_params, seen)

        # A sign-flip XOR of an FP value is itself FP.
        inner = _SignFlipRewriter._match_xor_sign(expr)
        if inner is not None:
            return cls._value_is_fp(inner, fp_arg_offsets, vvar_defs, entry_fp_params, seen)

        return False

    @classmethod
    def _phi_is_fp(
        cls,
        phi: Phi,
        fp_entry_source: bool,
        fp_arg_offsets: set[int],
        vvar_defs: dict[int, Expression],
        entry_fp_params: set[int],
        seen: set[int],
    ) -> bool:
        # FP iff at least one source is FP and every other source is FP, cyclic (already being traced), or undefined.
        found_fp = fp_entry_source
        for _, vvar in phi.src_and_vvars:
            if vvar is None or vvar.varid in seen:
                continue
            if vvar.varid not in vvar_defs and not vvar.was_parameter:
                continue
            if not cls._value_is_fp(vvar, fp_arg_offsets, vvar_defs, entry_fp_params, seen):
                return False
            found_fp = True
        return found_fp


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
    out.extend(getattr(node, "ret_exprs", None) or [])
    return out
