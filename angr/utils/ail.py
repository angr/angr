from __future__ import annotations

from collections import ChainMap
from collections.abc import Iterator, Mapping, Sequence
from typing import TYPE_CHECKING

from angr.ailment import AILBlockRewriter, AILBlockViewer, UnaryOp
from angr.ailment.block import Block
from angr.ailment.block_walker import _ExprContinue, _ExprHandled
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Convert,
    DirtyExpression,
    Expression,
    FunctionLikeMacro,
    Load,
    MultiStatementExpression,
    Phi,
    Register,
    Tmp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, ConditionalJump, Statement
from angr.rustylib.ailment import Statement as _RustStatement  # pylint:disable=import-error,no-name-in-module

if TYPE_CHECKING:
    import networkx

    from angr.analyses.s_reaching_definitions import SRDAModel


# dirty helpers lifted from VEX Dirty statements that are pure functions of their operands and memory
_PURE_DIRTY_HELPERS = frozenset({"x86g_dirtyhelper_loadF80le", "amd64g_dirtyhelper_loadF80le"})


class BlockDefs:
    """Same-block definition maps: VirtualVariable id and Tmp index -> defining expression (last assignment wins)."""

    __slots__ = ("all_defs", "stmt_has_call", "tmps", "vvars")

    def __init__(self, statements: Sequence[Statement] = (), all_defs: GraphVVarDefs | None = None):
        self.vvars: dict[int, Expression] = {}
        self.tmps: dict[int, Expression] = {}
        # by statement index; memo for scans that must stop at calls
        self.stmt_has_call: dict[int, bool] = {}
        # whole-graph definitions, consulted after the block-local ones
        self.all_defs = all_defs
        for stmt in statements:
            if isinstance(stmt, Assignment):
                if isinstance(stmt.dst, VirtualVariable):
                    self.vvars[stmt.dst.varid] = stmt.src
                elif isinstance(stmt.dst, Tmp):
                    self.tmps[stmt.dst.tmp_idx] = stmt.src

    @staticmethod
    def of(block: Block | None, block_defs: BlockDefs | None = None) -> BlockDefs:
        """Return the precomputed defs when the caller passed them, otherwise build them for block."""
        if block_defs is not None:
            return block_defs
        return BlockDefs(block.statements if block is not None else ())

    def vvar_defs(self, reg_offsets: frozenset[int] | None = None) -> Mapping[int, Expression]:
        """
        VirtualVariable definitions: block-local first, then the unique whole-graph ones (if available), optionally
        limited to the register vvars at ``reg_offsets``.
        """
        if self.all_defs is None:
            return self.vvars
        return ChainMap(self.vvars, self.all_defs if reg_offsets is None else self.all_defs.restrict(reg_offsets))


class _TmpInliner(AILBlockRewriter):
    """Substitute Tmps by their definitions; ``unresolved`` is set when a Tmp has none (or the chain is too deep)."""

    MAX_DEPTH = 16

    def __init__(self, tmps: dict[int, Expression]):
        super().__init__(update_block=False)
        self._tmps = tmps
        self._depth = 0
        self.unresolved = False

    def _handle_Tmp(self, expr_idx: int, expr: Tmp, stmt_idx: int, stmt: Statement | None, block: Block | None):
        src = self._tmps.get(expr.tmp_idx)
        if src is None or self._depth >= self.MAX_DEPTH:
            self.unresolved = True
            return expr
        self._depth += 1
        try:
            return self._handle_expr(0, src, stmt_idx, stmt, block)
        finally:
            self._depth -= 1


class _BlockBoundFinder(AILBlockViewer):
    """Finds sub-expressions whose value is only meaningful where they are evaluated (memory, calls, ...)."""

    def __init__(self):
        super().__init__()
        self.found = False

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self.found = True

    def _handle_Register(
        self, expr_idx: int, expr: Register, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        self.found = True

    def _handle_Tmp(self, expr_idx: int, expr: Tmp, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self.found = True

    def _handle_Call(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self.found = True

    def _handle_DirtyExpression(
        self, expr_idx: int, expr: DirtyExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        self.found = True

    def _handle_MultiStatementExpression(
        self, expr_idx: int, expr: MultiStatementExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        self.found = True

    def _handle_Phi(self, expr_idx: int, expr: Phi, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self.found = True


class GraphVVarDefs(Mapping[int, Expression]):
    """
    VirtualVariable id -> defining expression for the vvars that are defined exactly once in an AIL graph, by
    something other than a phi. The defining block's Tmps are inlined; definitions that still depend on where they are
    evaluated (memory loads, calls, leftover Tmps, raw registers) are left out, so every expression returned is valid in
    any block the vvar is used in. Built on first lookup.
    """

    __slots__ = ("_defs", "_graph", "_resolved")

    def __init__(self, graph: networkx.DiGraph):
        self._graph = graph
        # varid -> (definition, Tmp definitions of its block, register offset of the vvar or None)
        self._defs: dict[int, tuple[Expression, dict[int, Expression], int | None]] | None = None
        self._resolved: dict[int, Expression | None] = {}

    def _build(self) -> dict[int, tuple[Expression, dict[int, Expression], int | None]]:
        if self._defs is None:
            defs: dict[int, tuple[Expression, dict[int, Expression], int | None] | None] = {}
            for block in self._graph.nodes():
                tmps = BlockDefs(block.statements).tmps
                for stmt in block.statements:
                    if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                        dst = stmt.dst
                        # a second definition (even within one block) disqualifies the vvar
                        if dst.varid in defs or isinstance(stmt.src, Phi):
                            defs[dst.varid] = None
                        else:
                            reg = dst.oident if dst.category == VirtualVariableCategory.REGISTER else None
                            defs[dst.varid] = (stmt.src, tmps, reg)
            self._defs = {varid: d for varid, d in defs.items() if d is not None}
        return self._defs

    def _resolve(self, varid: int) -> Expression | None:
        if varid in self._resolved:
            return self._resolved[varid]
        expr: Expression | None = None
        d = self._build().get(varid)
        if d is not None:
            src, tmps, _ = d
            inliner = _TmpInliner(tmps)
            src = inliner.walk_expression(src)
            finder = _BlockBoundFinder()
            finder.walk_expression(src)
            if not inliner.unresolved and not finder.found:
                expr = src
        self._resolved[varid] = expr
        return expr

    def register_offset(self, varid: int) -> int | None:
        d = self._build().get(varid)
        return None if d is None else d[2]

    def restrict(self, reg_offsets: frozenset[int]) -> Mapping[int, Expression]:
        """The definitions of the register vvars at the given offsets only."""
        return _RegisterVVarDefs(self, reg_offsets)

    def __getitem__(self, varid: int) -> Expression:
        expr = self._resolve(varid)
        if expr is None:
            raise KeyError(varid)
        return expr

    def __contains__(self, varid: object) -> bool:
        return isinstance(varid, int) and self._resolve(varid) is not None

    def __iter__(self) -> Iterator[int]:
        return (varid for varid in self._build() if self._resolve(varid) is not None)

    def __len__(self) -> int:
        return sum(1 for _ in self)


class _RegisterVVarDefs(Mapping[int, Expression]):
    """A view of GraphVVarDefs limited to the register vvars at the given offsets (e.g., the flag registers)."""

    __slots__ = ("_defs", "_reg_offsets")

    def __init__(self, defs: GraphVVarDefs, reg_offsets: frozenset[int]):
        self._defs = defs
        self._reg_offsets = reg_offsets

    def _wanted(self, varid: int) -> bool:
        reg = self._defs.register_offset(varid)
        return reg is not None and reg in self._reg_offsets

    def __getitem__(self, varid: int) -> Expression:
        if not self._wanted(varid):
            raise KeyError(varid)
        return self._defs[varid]

    def __contains__(self, varid: object) -> bool:
        return isinstance(varid, int) and self._wanted(varid) and varid in self._defs

    def __iter__(self) -> Iterator[int]:
        return (varid for varid in self._defs if self._wanted(varid))

    def __len__(self) -> int:
        return sum(1 for _ in self)


def dirty_has_side_effects(expr: DirtyExpression) -> bool:
    """
    A dirty helper lifted from a VEX Dirty statement (mfx is set) may write memory or guest state (FLDENV, FSTENV, ...)
    or observe the outside world (IN, RDTSC): it must survive even when its result is dead, and must neither be
    duplicated nor moved. Placeholders for unsupported operations and the 80-bit load are pure.
    """
    return expr.mfx is not None and expr.callee not in _PURE_DIRTY_HELPERS


def is_phi_assignment(stmt: Statement) -> bool:
    return isinstance(stmt, _RustStatement) and stmt.is_phi_assignment


def is_scalar_int_convert(expr: Convert) -> bool:
    """
    True for a plain integer width conversion: not lane-wise (vector_count is None) and neither side is floating
    point. Only these converts admit the usual integer rewrites (folding cascaded conversions, masking, etc.).
    """
    return expr.vector_count is None and expr.from_type == Convert.TYPE_INT and expr.to_type == Convert.TYPE_INT


class HasExprWalker(AILBlockViewer):
    """
    Test if any expressions in exprs_to_check is used in another AIL expression.
    """

    def __init__(self, exprs_to_check: set[Expression]) -> None:
        super().__init__()

        self.exprs_to_check: set[Expression] = exprs_to_check
        self.contains_exprs: bool = False

    def _enter_expr(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if expr in self.exprs_to_check:
            self.contains_exprs = True
        if self.contains_exprs:
            return _ExprHandled(None)
        return _ExprContinue(expr)


def is_head_controlled_loop_block(block: Block) -> bool:
    """
    Determine if the block is a "head-controlled loop." A head-controlled loop (for the lack of a better term) is a
    single-block that contains a conditional jump towards the beginning of the block. This conditional jump controls
    whether the loop body (the remaining statements after the conditional jump) will be executed or not. It is usually
    the result of lifting rep stosX instructions on x86 and amd64.

    A head-controlled loop block looks like the following (lifted from rep stosq qword ptr [rdi], rax):

    ## Block 4036df
    00 | 0x4036df | LABEL_4036df:
    01 | 0x4036df | vvar_27{reg 72} = 𝜙@64b []
    02 | 0x4036df | vvar_28{reg 24} = 𝜙@64b []
    03 | 0x4036df | t1 = rcx<8>
    04 | 0x4036df | t4 = (t1 == 0x0<64>)
    05 | 0x4036df | if (t4) { Goto 0x4036e2<64> } else { Goto 0x4036df<64> }
    06 | 0x4036df | t5 = (t1 - 0x1<64>)
    07 | 0x4036df | rcx<8> = t5
    08 | 0x4036df | t7 = d<8>
    09 | 0x4036df | t6 = (t7 << 0x3<8>)
    10 | 0x4036df | t2 = rax<8>
    11 | 0x4036df | t3 = rdi<8>
    12 | 0x4036df | STORE(addr=t3, data=t2, size=8, endness=Iend_LE, guard=None)
    13 | 0x4036df | t8 = (t3 + t6)
    14 | 0x4036df | rdi<8> = t8

    Where statement 5 is the conditional jump that controls the execution of the remaining statements of this block.

    :param block:   An AIL block.
    :return:        True if the block represents a head-controlled loop block, False otherwise.
    """

    if not block.statements:
        return False
    last_stmt = block.statements[-1]
    if isinstance(last_stmt, ConditionalJump):
        return False
    return any(
        isinstance(stmt, ConditionalJump) and is_head_controlled_loop_jump(block, stmt)
        for stmt in block.statements[:-1]
    )


def is_head_controlled_loop_jump(block: Block, stmt: ConditionalJump) -> bool:
    """
    Determine if a conditional jump in the middle of a block controls a head-controlled loop, i.e., it can leave the
    block. Jumps whose concrete targets all lie inside the block (e.g., libVEX alignment-check exits emitted for
    AArch64 ldar/stlr) cannot, and the SSA rewriting engine does not record a side-exit state for them.
    """
    targets = [t.value for t in (stmt.true_target, stmt.false_target) if isinstance(t, Const)]
    if not targets:
        return False
    assert block.original_size is not None
    return not all(block.addr <= t < block.addr + block.original_size for t in targets)


def extract_partial_expr(base_expr: Expression, off: int, size: int, ail_manager, byte_width: int = 8) -> Expression:
    bits = size * byte_width
    if off == 0 and bits == base_expr.bits:
        return base_expr
    if off * byte_width >= base_expr.bits:
        raise ValueError("Offset is greater than or equal to expression size")
    if base_expr.bits - off * byte_width < bits:
        raise ValueError("Insufficient expression bits")

    base_mask = ((1 << bits) - 1) << (off * byte_width)
    base_mask = Const(ail_manager.next_atom(), base_mask, base_expr.bits)
    masked_base_expr = BinaryOp(
        ail_manager.next_atom(),
        "And",
        [base_expr, base_mask],
        False,
        bits=base_expr.bits,
        **base_expr.tags,
    )
    if off > 0:
        shift_amount = Const(ail_manager.next_atom(), off * byte_width, byte_width)
        shifted_vvar = BinaryOp(
            ail_manager.next_atom(),
            "Shr",
            [
                masked_base_expr,
                shift_amount,
            ],
            bits=masked_base_expr.bits,
            **masked_base_expr.tags,
        )
    else:
        shifted_vvar = masked_base_expr
    truncated_expr = Convert(
        ail_manager.next_atom(),
        shifted_vvar.bits,
        bits,
        False,
        shifted_vvar,
        **shifted_vvar.tags,
    )
    assert truncated_expr.bits == bits
    return truncated_expr


def is_expr_used_as_reg_base_value(stmt: Statement, expr: Expression, srda: SRDAModel) -> bool:
    """
    Determine if the expression `expr` is used as the base value of an assignment of a full register in `stmt`.

    This method returns True if the following conditions hold:
    - The statement is an assignment to a reg vvar A;
    - The src of the assignment statement is a bitwise-or expression;
    - One of the operands of the src expr is the high bits of `expr`;
    - `expr` is a phi var that relies on reg vvar A.
    """

    if not isinstance(stmt, Assignment):
        return False
    if not isinstance(stmt.dst, VirtualVariable):
        return False
    if not stmt.dst.was_reg:
        return False
    if not isinstance(expr, VirtualVariable):
        return False
    if not expr.was_reg:
        return False
    if expr.varid not in srda.phivarid_to_varids:
        return False
    if stmt.dst.varid not in srda.phivarid_to_varids[expr.varid]:
        return False

    if not (isinstance(stmt.src, BinaryOp) and stmt.src.op == "Or"):
        return False

    operands = stmt.src.operands
    for op0 in operands:
        op1 = operands[0] if op0.idx == operands[1].idx else operands[1]
        if (
            isinstance(op1, Convert)
            and op1.from_type == Convert.TYPE_INT
            and op1.to_type == Convert.TYPE_INT
            and op1.from_bits < op1.to_bits
        ):
            expected_mask = ((1 << op1.to_bits) - 1) ^ ((1 << op1.from_bits) - 1)
            if isinstance(op0, BinaryOp) and op0.op == "And":
                if (
                    isinstance(op0.operands[0], Const)
                    and op0.operands[0].value == expected_mask
                    and isinstance(op0.operands[1], VirtualVariable)
                    and op0.operands[1].varid == expr.varid
                ):
                    return True
                if (
                    isinstance(op0.operands[1], Const)
                    and op0.operands[1].value == expected_mask
                    and isinstance(op0.operands[0], VirtualVariable)
                    and op0.operands[0].varid == expr.varid
                ):
                    return True

    return False


class CallFinder(AILBlockViewer):
    """Find the first Call statement or expression in a block."""

    def __init__(self, include_macro=False):
        super().__init__()
        self.call = None
        self.include_macro = include_macro

    def _handle_Call(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement | None, block: Block | None):  # pylint: disable=unused-argument
        if not self.call:
            self.call = expr

    def _handle_FunctionLikeMacro(
        self, expr_idx: int, expr: FunctionLikeMacro, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        if not self.call and self.include_macro:
            self.call = expr


def find_call(obj: Block | Statement | Expression, include_macro=False):
    walker = CallFinder(include_macro)
    if isinstance(obj, Block):
        walker.walk(obj)
    elif isinstance(obj, Statement):
        walker.walk_statement(obj)
    elif isinstance(obj, Expression):
        walker.walk_expression(obj)
    return walker.call


def has_call(obj: Block | Statement | Expression, include_macro=False):
    return find_call(obj, include_macro) is not None


def get_terminal_call(block: Block):
    if block.statements:
        terminal = block.statements[-1]
        if isinstance(terminal, Call):
            return terminal
        finder = CallFinder()
        finder.walk_statement(terminal)
        return finder.call
    return None


def unwrap_stack_vvar_reference(expr) -> VirtualVariable | None:
    if (
        isinstance(expr, UnaryOp)
        and expr.op == "Reference"
        and isinstance(expr.operand, VirtualVariable)
        and expr.operand.was_stack
    ):
        return expr.operand
    return None


def unwrap_combo_reg_vvar_reference(expr) -> VirtualVariable | None:
    if (
        isinstance(expr, UnaryOp)
        and expr.op == "Reference"
        and isinstance(expr.operand, VirtualVariable)
        and expr.operand.was_combo_reg
    ):
        return expr.operand
    return None


def deref_vvar_and_offset(expr) -> tuple[VirtualVariable, int] | tuple[None, None]:
    """
    If expr is a dereference of a VirtualVariable (possibly with an offset), return the VirtualVariable and offset.
    Otherwise, return (None, None).
    """
    if isinstance(expr, UnaryOp) and expr.op == "Reference" and isinstance(expr.operand, VirtualVariable):
        return expr.operand, 0
    if isinstance(expr, BinaryOp) and expr.op == "Add":
        op0, op1 = expr.operands
        if (
            isinstance(op0, UnaryOp)
            and op0.op == "Reference"
            and isinstance(op0.operand, VirtualVariable)
            and isinstance(op1, Const)
        ):
            return op0.operand, op1.value_int
    return None, None


def extract_vvar_and_offset(expr) -> tuple[VirtualVariable, int] | tuple[None, None]:
    """
    If expr is a VirtualVariable (possibly with an offset), return the VirtualVariable and offset.
    Otherwise, return (None, None).
    """
    if isinstance(expr, VirtualVariable):
        return expr, 0
    if (
        isinstance(expr, BinaryOp)
        and isinstance(expr.operands[0], VirtualVariable)
        and isinstance(expr.operands[1], Const)
    ):
        return expr.operands[0], expr.operands[1].value_int
    return None, None


def unwrap_stack_vvar_reference_with_offset(expr) -> tuple[VirtualVariable, int] | tuple[None, None]:
    if isinstance(expr, UnaryOp) and expr.op == "Reference":
        if isinstance(expr.operand, VirtualVariable) and expr.operand.was_stack:
            return expr.operand, 0
        if (
            isinstance(expr.operand, BinaryOp)
            and expr.op == "Add"
            and isinstance(expr.operand.operands[0], VirtualVariable)
            and expr.operand.operands[0].was_stack
            and isinstance(expr.operand.operands[1], Const)
        ):
            return expr.operand.operands[0], expr.operand.operands[1].value_int
    return None, None


class CallVisitor(AILBlockViewer):
    """Visit all Call statements and expressions in a graph, invoking a callback."""

    def __init__(self, callback):
        super().__init__()
        self.callback = callback

    def _handle_Call(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement | None, block: Block | None):  # pylint: disable=unused-argument
        self.callback(expr, block, stmt, is_expr=True)

    def visit(self, graph):
        for block in graph.nodes:
            self.walk(block)
