from __future__ import annotations

from angr.ailment import AILBlockViewer
from angr.ailment.expression import BinaryOp, Const, VirtualVariable
from angr.ailment.statement import Assignment, ConditionalJump, Label
from angr.analyses.decompiler.ccall_rewriters.flags_word import FlagsWordBuilder, flag_bits, flags_word_ccall
from angr.utils.ail import BlockDefs

from .base import PeepholeOptimizationExprBase


class _MayWriteMemory(AILBlockViewer):
    """Sets ``found`` on any expression that may write memory or that this check does not model."""

    def __init__(self):
        super().__init__()
        self.found = False

    def _flag(self, *args, **kwargs):
        self.found = True

    _handle_Call = _flag
    _handle_DirtyExpression = _flag
    _handle_FunctionLikeMacro = _flag
    _handle_MultiStatementExpression = _flag


def _may_write_memory(stmt) -> bool:
    viewer = _MayWriteMemory()
    viewer.walk_statement(stmt)
    return viewer.found


def _is_branch_test(block, stmt_idx, expr) -> bool:
    """Whether ``expr`` is what the block's conditional jump at ``stmt_idx`` tests: ``expr`` or ``expr ==/!= 0``."""
    if block is None or stmt_idx is None or not isinstance(block.statements[stmt_idx], ConditionalJump):
        return False
    cond = block.statements[stmt_idx].condition
    tests = [cond]
    if isinstance(cond, BinaryOp) and cond.op in {"CmpEQ", "CmpNE"}:
        a, b = cond.operands
        tests += [x for x, y in ((a, b), (b, a)) if isinstance(y, Const) and y.value == 0]
    return any(t.likes(expr) for t in tests)


def _block_local_def(varid: int, stmt_idx: int | None, block):
    """
    The definition of ``varid`` earlier in ``block`` when nothing between it and the use at ``stmt_idx`` (the use
    statement included) may write memory, so the definition evaluates to the same value at the use.
    """
    if block is None or stmt_idx is None:
        return None
    stmts = block.statements
    for idx in range(stmt_idx - 1, -1, -1):
        stmt = stmts[idx]
        if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.varid == varid:
            # a copy must not repeat a call
            return None if _may_write_memory(stmt) else stmt.src
        if isinstance(stmt, Label):
            continue
        if not isinstance(stmt, Assignment) or _may_write_memory(stmt):
            return None
    return None


def _copy_root(vvar: VirtualVariable, defs, pending: list) -> int:
    """The variable a chain of copies ``v = w`` starts from."""
    seen = set()
    while vvar.varid not in seen:
        seen.add(vvar.varid)
        src = defs.get(vvar.varid)
        if src is None and defs.definition(vvar.varid) is not None:
            pending.append(vvar.varid)
        if not isinstance(src, VirtualVariable):
            break
        vvar = src
    return vvar.varid


def _through_graph_defs(word, mask: int, defs, pending: list):
    """
    Follow ``word`` through graph-wide definitions, phis whose sources are copies of one variable, and ``x | C`` with
    ``C & mask == 0`` (the pushed-flags image sets IF and the reserved bits): each keeps ``word & mask``.
    """
    seen = set()
    while True:
        if isinstance(word, BinaryOp) and word.op == "Or" and not word.floating_point:
            a, b = word.operands
            if isinstance(a, Const):
                a, b = b, a
            if isinstance(b, Const) and isinstance(b.value, int) and not b.value_int & mask:
                word = a
                continue
            return word
        if not isinstance(word, VirtualVariable) or defs is None or word.varid in seen:
            return word
        seen.add(word.varid)
        src = defs.get(word.varid)
        if src is None and defs.definition(word.varid) is not None:
            # its definition still reads memory; forwarding may resolve it later
            pending.append(word.varid)
            return word
        if src is None:
            phi = defs.phi_sources().get(word.varid)
            if not phi or any(v is None for v in phi[1]):
                return word
            roots = {_copy_root(v, defs, pending) for v in phi[1]}
            if len(roots) != 1:
                return word
            # every source is a copy of one value
            src = phi[1][0]
        word = src


class ExpandMaskedFlagsWord(PeepholeOptimizationExprBase):
    """
    ``eflags_all(op, d1, d2, nd) & F`` ==> ``word(op, d1, d2, nd) & F`` for a single flag F, where ``word`` is the flags
    word spelled out flag by flag, also when the ccall is the (location-independent) definition of a virtual
    variable, or its definition earlier in the same block with no memory write in between. A whole flags word that a
    VM pushes stays a ccall; the flag tests on it reduce to the flags they read.
    """

    __slots__ = ()

    NAME = "Expand masked x86 flags words"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, *, stmt_idx=None, block=None, block_defs: BlockDefs | None = None, **kwargs):
        if expr.op != "And" or expr.floating_point:
            return None
        op0, op1 = expr.operands
        if isinstance(op0, Const):
            op0, op1 = op1, op0
        if not (isinstance(op1, Const) and isinstance(op1.value, int)):
            return None
        mask = op1.value_int & 0xFFFFFFFF
        if mask & ~flag_bits("X86") or mask.bit_count() != 1:
            # a single flag test reduces to that flag; a multi-flag merge reads better as the ccall
            return None
        defs = block_defs.all_defs if block_defs is not None else None
        pending: list[int] = []
        word = _through_graph_defs(op0, mask, defs, pending)
        if isinstance(word, VirtualVariable):
            vvar = word
            word = None
            if block_defs is not None and block_defs.all_defs is not None:
                # the graph-wide definitions are valid wherever the vvar is read
                word = block_defs.all_defs.get(vvar.varid)
            if (
                word is None
                and block_defs is not None
                and flags_word_ccall(block_defs.vvars.get(vvar.varid))
                and _is_branch_test(block, stmt_idx, expr)
            ):
                # only a flag a branch tests directly: VMProtect's flag selects fold from the ccall form
                word = _block_local_def(vvar.varid, stmt_idx, block)
                if word is not None and _may_write_memory(block.statements[stmt_idx]):
                    word = None
                if word is None:
                    # a write between the definition and the use may go away later
                    self.fixpoint_reached = False
            if word is None:
                if pending:
                    self.fixpoint_reached = False
                return None
            word = _through_graph_defs(word, mask, defs, pending)
        split = flags_word_ccall(word)
        if split is None or split[0] != "X86":
            if pending:
                self.fixpoint_reached = False
            return None
        builder = FlagsWordBuilder(self.manager, "X86", word.tags)
        built = builder.build(split[1], *word.operands[1:], self.manager.next_atom())
        if built is None:
            return None
        return BinaryOp(expr.idx, "And", [built, op1], expr.signed, bits=expr.bits, **expr.tags)
