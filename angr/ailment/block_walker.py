# pylint:disable=unused-argument,no-self-use
from __future__ import annotations

from abc import abstractmethod
from collections import OrderedDict
from collections.abc import Callable
from typing import Any, cast

from angr.rustylib.ailment import Expression as _RustExpression  # pylint:disable=import-error
from angr.rustylib.ailment import Statement as _RustStatement  # pylint:disable=import-error

from . import Block
from .expression import (
    ITE,
    Array,
    Atom,
    BasePointerOffset,
    BinaryOp,
    Call,
    ComboRegister,
    Const,
    Convert,
    DirtyExpression,
    Expression,
    Extract,
    FunctionLikeMacro,
    Insert,
    Let,
    Load,
    Macro,
    MultiStatementExpression,
    Phi,
    Register,
    Reinterpret,
    RustEnum,
    StackBaseOffset,
    StringLiteral,
    Struct,
    Tmp,
    UnaryOp,
    VEXCCallExpression,
    VirtualVariable,
)
from .statement import (
    CAS,
    Assignment,
    ConditionalJump,
    DirtyStatement,
    Jump,
    Label,
    NoOp,
    Return,
    SideEffectStatement,
    Statement,
    Store,
    WeakAssignment,
)

_DEFAULT_STMT_HANDLER_TYPES = {
    Assignment,
    WeakAssignment,
    CAS,
    SideEffectStatement,
    Store,
    ConditionalJump,
    Jump,
    Return,
    DirtyStatement,
}

_DEFAULT_EXPR_HANDLER_TYPES = {
    Call,
    Load,
    BinaryOp,
    UnaryOp,
    Convert,
    ITE,
    DirtyExpression,
    VEXCCallExpression,
    Tmp,
    Register,
    ComboRegister,
    Reinterpret,
    Const,
    MultiStatementExpression,
    VirtualVariable,
    Phi,
    Extract,
    Insert,
    RustEnum,
    Struct,
    Array,
    FunctionLikeMacro,
    StringLiteral,
}


def _dispatch_key(obj):
    """Resolve a handler-dict key for ``obj``.

    Every AIL Expression/Statement is the universal ``Expression``
    or ``Statement`` pyclass; ``type(obj)`` returns the same class for all
    variants and dispatch keyed on per-class types breaks. The fat-enum
    surfaces the variant tag as ``obj.kind`` (a string), and this module's
    marker classes are stored in the handler dict keyed by class; we map
    ``kind`` -> marker class via the per-class ``_kinds``/``_kind`` attrs.

    Pure-Python instances (e.g. structurer helper statements) that
    don't expose a known ``kind`` fall back to ``type(obj)``.
    """
    # Fast path: fat-enum instances are the overwhelming majority
    # of dispatches (~4M / decompile on ``doit``). Dispatch on the
    # cached ``pykind`` (a ``Py<int>``) instead of ``kind`` (a fresh
    # ``ExpressionKind`` / ``StatementKind`` pyclass per access).
    # Expression / Statement integer tag spaces overlap (both start at
    # 0), so route through per-side tables. ``type(obj) is`` (the
    # pyclasses are final) is a C-level identity check, cheaper than
    # ``isinstance`` and its metaclass path.
    t = type(obj)
    if t is _RustExpression:
        return _EXPR_KIND_TO_MARKER.get(obj.pykind, _RustExpression)
    if t is _RustStatement:
        return _STMT_KIND_TO_MARKER.get(obj.pykind, _RustStatement)
    # Slow path: pure-Python instances may not expose ``kind``.
    kind = getattr(obj, "kind", None)
    if kind is None:
        return type(obj)
    return _KIND_TO_MARKER.get(kind, type(obj))


# Build per-side lookups ``kind -> marker class``. Expression and
# Statement integer tag spaces overlap (both start at 0) so the dicts
# can't be merged when keyed on ``ExpressionKind`` / ``StatementKind``
# values (or their integer aliases via ``pykind``). The combined
# ``_KIND_TO_MARKER`` is preserved for the pure-Python slow path.
_EXPR_MARKERS = (
    Const,
    Tmp,
    Register,
    ComboRegister,
    VirtualVariable,
    Phi,
    UnaryOp,
    BinaryOp,
    Convert,
    Reinterpret,
    Load,
    ITE,
    Extract,
    Insert,
    Call,
    DirtyExpression,
    VEXCCallExpression,
    MultiStatementExpression,
    StringLiteral,
    Struct,
    RustEnum,
    Array,
    Let,
    Macro,
    FunctionLikeMacro,
    BasePointerOffset,
    StackBaseOffset,
)
_STMT_MARKERS = (
    Assignment,
    WeakAssignment,
    Store,
    Jump,
    ConditionalJump,
    SideEffectStatement,
    Return,
    CAS,
    DirtyStatement,
    Label,
    NoOp,
)
_EXPR_KIND_TO_MARKER: dict = {}
_STMT_KIND_TO_MARKER: dict = {}
_KIND_TO_MARKER: dict = {}
_marker = None
_kind_attr = None
for _marker in _EXPR_MARKERS:
    _kind_attr = _marker.__dict__.get("_kind")
    if _kind_attr is not None:
        _EXPR_KIND_TO_MARKER.setdefault(_kind_attr, _marker)
        _KIND_TO_MARKER.setdefault(_kind_attr, _marker)
for _marker in _STMT_MARKERS:
    _kind_attr = _marker.__dict__.get("_kind")
    if _kind_attr is not None:
        _STMT_KIND_TO_MARKER.setdefault(_kind_attr, _marker)
        # _KIND_TO_MARKER may have an EK collision here -- skip if so.
        if _kind_attr not in _KIND_TO_MARKER:
            _KIND_TO_MARKER.setdefault(_kind_attr, _marker)
del _marker, _kind_attr


class AILBlockWalker[ExprType, StmtType, BlockType]:
    """
    Walks all statements and expressions of an AIL node and construct arbitrary values based on them.

    Note that we lazily initialize self._stmt_handlers and self._expr_handlers when they are accessed. This is to
    support the existing pattern of updating stmt/expr handlers in-place after creating a block walker, and is slightly
    slower. Overridding handler methods in a new class is the fastest approach.
    """

    _default_stmt_funcs: dict[type, Callable]
    _default_expr_funcs: dict[type, Callable]
    # pykind (int) -> handler shadows of the default tables, for zero-frame
    # single-lookup dispatch of Rust nodes that use the default handler set.
    _default_stmt_funcs_by_pykind: dict
    _default_expr_funcs_by_pykind: dict

    def __init__(self, stmt_handlers=None, expr_handlers=None):
        self._stmt_handlers: dict[type, Callable[[int, Any, Block | None], StmtType]] | None = stmt_handlers or None
        self._expr_handlers: dict[type, Callable[[int, Any, int, Statement | None, Block | None], ExprType]] | None = (
            expr_handlers or None
        )

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.rebuild_default_handler_funcs()

    @classmethod
    def rebuild_default_handler_funcs(cls) -> None:
        cls._default_stmt_funcs = {t: getattr(cls, f"_handle_{t.__name__}") for t in _DEFAULT_STMT_HANDLER_TYPES}
        cls._default_expr_funcs = {t: getattr(cls, f"_handle_{t.__name__}") for t in _DEFAULT_EXPR_HANDLER_TYPES}
        # pykind-keyed shadows: for Rust nodes on the default handler set,
        # dispatch becomes one int-keyed lookup with no marker-class step.
        cls._default_stmt_funcs_by_pykind = {
            k: f for t, f in cls._default_stmt_funcs.items() if (k := t.__dict__.get("_kind")) is not None
        }
        cls._default_expr_funcs_by_pykind = {
            k: f for t, f in cls._default_expr_funcs.items() if (k := t.__dict__.get("_kind")) is not None
        }

    @property
    def stmt_handlers(self) -> dict[type, Callable[[int, Any, Block | None], StmtType]]:
        if self._stmt_handlers is None:
            self._stmt_handlers = {t: getattr(self, f"_handle_{t.__name__}") for t in _DEFAULT_STMT_HANDLER_TYPES}
        return self._stmt_handlers

    @stmt_handlers.setter
    def stmt_handlers(self, value) -> None:
        self._stmt_handlers = value

    @property
    def expr_handlers(self) -> dict[type, Callable[[int, Any, int, Statement | None, Block | None], ExprType]]:
        if self._expr_handlers is None:
            self._expr_handlers = {t: getattr(self, f"_handle_{t.__name__}") for t in _DEFAULT_EXPR_HANDLER_TYPES}
        return self._expr_handlers

    @expr_handlers.setter
    def expr_handlers(self, value) -> None:
        self._expr_handlers = value

    def reset(self) -> None:
        """
        Reset per-walk state variables so that this walker can be reused for another walk. Subclasses that updates
        state across a walk must override this to clear that state.
        """

    def walk(self, block: Block) -> BlockType:
        i = 0
        results = []
        while i < len(block.statements):
            stmt = block.statements[i]
            results.append(self._handle_stmt(i, stmt, block))
            i += 1
        return self._handle_block_end(results, block)

    @abstractmethod
    def _handle_block_end(self, stmt_results: list[StmtType], block: Block) -> BlockType:
        raise NotImplementedError

    def walk_statement(self, stmt: Statement, block: Block | None = None, stmt_idx: int = 0) -> StmtType:
        return self._handle_stmt(stmt_idx, stmt, block)

    def walk_expression(
        self,
        expr: Expression,
        stmt_idx: int | None = None,
        stmt: Statement | None = None,
        block: Block | None = None,
    ) -> ExprType:
        return self._handle_expr(0, expr, stmt_idx or 0, stmt, block)

    def _handle_stmt(self, stmt_idx: int, stmt: Statement, block: Block | None) -> StmtType:
        # Inline the stmt-side dispatch: a Rust statement (the common case,
        # ~1M/decompile) skips the ``_dispatch_key`` frame and the redundant
        # expr-side check, dispatching on the cached ``pykind`` int directly.
        handlers = self._stmt_handlers
        if handlers is None:
            if type(stmt) is _RustStatement:
                func = self._default_stmt_funcs_by_pykind.get(stmt.pykind)
            else:
                func = self._default_stmt_funcs.get(_dispatch_key(stmt))
            if func is None:
                return self._stmt_top(stmt_idx, stmt, block)
            return func(self, stmt_idx, stmt, block)
        if type(stmt) is _RustStatement:
            key = _STMT_KIND_TO_MARKER.get(stmt.pykind, _RustStatement)
        else:
            key = _dispatch_key(stmt)
        handler = handlers.get(key)
        if handler is None:
            return self._stmt_top(stmt_idx, stmt, block)
        return handler(stmt_idx, stmt, block)

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        # Inline the expr-side dispatch: a Rust expression (the common case)
        # dispatches on the cached ``pykind`` int with no ``_dispatch_key``
        # frame and no redundant stmt-side check.
        handlers = self._expr_handlers
        if handlers is None:
            if type(expr) is _RustExpression:
                func = self._default_expr_funcs_by_pykind.get(expr.pykind)
            else:
                func = self._default_expr_funcs.get(_dispatch_key(expr))
            if func is None:
                return self._top(expr_idx, expr, stmt_idx, stmt, block)
            return func(self, expr_idx, expr, stmt_idx, stmt, block)
        if type(expr) is _RustExpression:
            key = _EXPR_KIND_TO_MARKER.get(expr.pykind, _RustExpression)
        else:
            key = _dispatch_key(expr)
        handler = handlers.get(key)
        if handler is None:
            return self._top(expr_idx, expr, stmt_idx, stmt, block)
        return handler(expr_idx, expr, stmt_idx, stmt, block)

    @abstractmethod
    def _top(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        raise NotImplementedError

    @abstractmethod
    def _stmt_top(self, stmt_idx: int, stmt: Statement, block: Block | None) -> StmtType:
        raise NotImplementedError

    #
    # Default handlers
    #

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None) -> StmtType:
        self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_WeakAssignment(self, stmt_idx: int, stmt: WeakAssignment, block: Block | None) -> StmtType:
        self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_CAS(self, stmt_idx: int, stmt: CAS, block: Block | None) -> StmtType:
        self._handle_expr(0, stmt.addr, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.data_lo, stmt_idx, stmt, block)
        if stmt.data_hi is not None:
            self._handle_expr(2, stmt.data_hi, stmt_idx, stmt, block)
        self._handle_expr(3, stmt.expd_lo, stmt_idx, stmt, block)
        if stmt.expd_hi is not None:
            self._handle_expr(4, stmt.expd_hi, stmt_idx, stmt, block)
        self._handle_expr(5, stmt.old_lo, stmt_idx, stmt, block)
        if stmt.old_hi is not None:
            self._handle_expr(6, stmt.old_hi, stmt_idx, stmt, block)
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_SideEffectStatement(self, stmt_idx: int, stmt: SideEffectStatement, block: Block | None) -> StmtType:
        self._handle_expr(0, stmt.expr, stmt_idx, stmt, block)
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Block | None) -> StmtType:
        self._handle_expr(0, stmt.addr, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.data, stmt_idx, stmt, block)
        if stmt.guard is not None:
            self._handle_expr(2, stmt.guard, stmt_idx, stmt, block)
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_Jump(self, stmt_idx: int, stmt: Jump, block: Block | None) -> StmtType:
        self._handle_expr(0, stmt.target, stmt_idx, stmt, block)
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_ConditionalJump(self, stmt_idx: int, stmt: ConditionalJump, block: Block | None) -> StmtType:
        self._handle_expr(0, stmt.condition, stmt_idx, stmt, block)
        if stmt.true_target is not None:
            self._handle_expr(1, stmt.true_target, stmt_idx, stmt, block)
        if stmt.false_target is not None:
            self._handle_expr(2, stmt.false_target, stmt_idx, stmt, block)
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_Return(self, stmt_idx: int, stmt: Return, block: Block | None) -> StmtType:
        if stmt.ret_exprs:
            for i, ret_expr in enumerate(stmt.ret_exprs):
                self._handle_expr(i, ret_expr, stmt_idx, stmt, block)
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_DirtyStatement(self, stmt_idx: int, stmt: DirtyStatement, block: Block | None) -> StmtType:
        self._handle_expr(0, stmt.dirty, stmt_idx, stmt, block)
        return self._stmt_top(stmt_idx, stmt, block)

    def _handle_Load(
        self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        self._handle_expr(0, expr.addr, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Call(
        self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        if not isinstance(expr.target, str):
            self._handle_expr(-1, expr.target, stmt_idx, stmt, block)
        if expr.args:
            for i, arg in enumerate(expr.args):
                self._handle_expr(i, arg, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_BinaryOp(
        self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        # ``expr.operands`` mints fresh wrappers per access; cache.
        ops = expr.operands
        self._handle_expr(0, ops[0], stmt_idx, stmt, block)
        self._handle_expr(1, ops[1], stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_UnaryOp(
        self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        self._handle_expr(0, expr.operand, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Convert(
        self, expr_idx: int, expr: Convert, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Reinterpret(
        self, expr_idx: int, expr: Reinterpret, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_ITE(
        self, expr_idx: int, expr: ITE, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        self._handle_expr(0, expr.cond, stmt_idx, stmt, block)
        self._handle_expr(1, expr.iftrue, stmt_idx, stmt, block)
        self._handle_expr(2, expr.iffalse, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Tmp(
        self, expr_idx: int, expr: Tmp, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Register(
        self, expr_idx: int, expr: Register, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Const(
        self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Phi(
        self, expr_idx: int, expr: Phi, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        for idx, (_, vvar) in enumerate(expr.src_and_vvars):
            if vvar is not None:
                self._handle_expr(idx, vvar, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_MultiStatementExpression(
        self, expr_idx, expr: MultiStatementExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        for idx, stmt_ in enumerate(expr.stmts):
            self._handle_stmt(idx, stmt_, None)
        self._handle_expr(0, expr.expr, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_DirtyExpression(
        self, expr_idx: int, expr: DirtyExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        ops = expr.operands
        for idx, operand in enumerate(ops):
            self._handle_expr(idx, operand, stmt_idx, stmt, block)
        guard = expr.guard
        if guard is not None:
            self._handle_expr(len(ops) + 1, guard, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VEXCCallExpression(
        self, expr_idx: int, expr: VEXCCallExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        for idx, operand in enumerate(expr.operands):
            self._handle_expr(idx, operand, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Extract(
        self, expr_idx: int, expr: Extract, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        self._handle_expr(0, expr.base, stmt_idx, stmt, block)
        self._handle_expr(1, expr.offset, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Insert(
        self, expr_idx: int, expr: Insert, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        self._handle_expr(0, expr.base, stmt_idx, stmt, block)
        self._handle_expr(1, expr.offset, stmt_idx, stmt, block)
        self._handle_expr(2, expr.value, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_RustEnum(
        self, expr_idx: int, expr: RustEnum, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        for idx, field in enumerate(expr.fields):
            self._handle_expr(idx, field, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Struct(self, expr_idx: int, expr: Struct, stmt_idx: int, stmt: Statement | None, block: Block | None):
        for idx, field in enumerate(expr.fields.values()):
            self._handle_expr(idx, field, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Array(self, expr_idx: int, expr: Array, stmt_idx: int, stmt: Statement | None, block: Block | None):
        for idx, ele in enumerate(expr.elements):
            self._handle_expr(idx, ele, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_FunctionLikeMacro(
        self, expr_idx: int, expr: FunctionLikeMacro, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        if expr.args:
            for i, arg in enumerate(expr.args):
                self._handle_expr(i, arg, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_StringLiteral(
        self, expr_idx: int, expr: StringLiteral, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_ComboRegister(
        self, expr_idx: int, expr: ComboRegister, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        for idx, reg in enumerate(expr.registers):
            self._handle_expr(idx, reg, stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)


# __init_subclass__ only runs for subclasses; build the base class's default handler tables explicitly.
AILBlockWalker.rebuild_default_handler_funcs()


class AILBlockViewer(AILBlockWalker[None, None, None]):
    """
    Walks all statements and expressions of an AIL node and do nothing.
    """

    def _top(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None):
        return None

    def _stmt_top(self, stmt_idx: int, stmt: Statement, block: Block | None):
        return None

    def _handle_block_end(self, stmt_results: list[None], block: Block):
        return None

    # Duplicate all handlers for performance...

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None):
        self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)

    def _handle_WeakAssignment(self, stmt_idx: int, stmt: WeakAssignment, block: Block | None):
        self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.src, stmt_idx, stmt, block)

    def _handle_CAS(self, stmt_idx: int, stmt: CAS, block: Block | None):
        self._handle_expr(0, stmt.addr, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.data_lo, stmt_idx, stmt, block)
        if stmt.data_hi is not None:
            self._handle_expr(2, stmt.data_hi, stmt_idx, stmt, block)
        self._handle_expr(3, stmt.expd_lo, stmt_idx, stmt, block)
        if stmt.expd_hi is not None:
            self._handle_expr(4, stmt.expd_hi, stmt_idx, stmt, block)
        self._handle_expr(5, stmt.old_lo, stmt_idx, stmt, block)
        if stmt.old_hi is not None:
            self._handle_expr(6, stmt.old_hi, stmt_idx, stmt, block)

    def _handle_SideEffectStatement(self, stmt_idx: int, stmt: SideEffectStatement, block: Block | None):
        self._handle_expr(0, stmt.expr, stmt_idx, stmt, block)

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Block | None):
        self._handle_expr(0, stmt.addr, stmt_idx, stmt, block)
        self._handle_expr(1, stmt.data, stmt_idx, stmt, block)
        if stmt.guard is not None:
            self._handle_expr(2, stmt.guard, stmt_idx, stmt, block)

    def _handle_Jump(self, stmt_idx: int, stmt: Jump, block: Block | None):
        self._handle_expr(0, stmt.target, stmt_idx, stmt, block)

    def _handle_ConditionalJump(self, stmt_idx: int, stmt: ConditionalJump, block: Block | None):
        self._handle_expr(0, stmt.condition, stmt_idx, stmt, block)
        if stmt.true_target is not None:
            self._handle_expr(1, stmt.true_target, stmt_idx, stmt, block)
        if stmt.false_target is not None:
            self._handle_expr(2, stmt.false_target, stmt_idx, stmt, block)

    def _handle_Return(self, stmt_idx: int, stmt: Return, block: Block | None):
        if stmt.ret_exprs:
            for i, ret_expr in enumerate(stmt.ret_exprs):
                self._handle_expr(i, ret_expr, stmt_idx, stmt, block)

    def _handle_DirtyStatement(self, stmt_idx: int, stmt: DirtyStatement, block: Block | None):
        self._handle_expr(0, stmt.dirty, stmt_idx, stmt, block)

    def _handle_Load(self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self._handle_expr(0, expr.addr, stmt_idx, stmt, block)

    def _handle_Call(self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement | None, block: Block | None):
        if not isinstance(expr.target, str):
            self._handle_expr(-1, expr.target, stmt_idx, stmt, block)
        if expr.args:
            for i, arg in enumerate(expr.args):
                self._handle_expr(i, arg, stmt_idx, stmt, block)

    def _handle_BinaryOp(
        self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        # ``expr.operands`` mints fresh wrappers per access; cache.
        ops = expr.operands
        self._handle_expr(0, ops[0], stmt_idx, stmt, block)
        self._handle_expr(1, ops[1], stmt_idx, stmt, block)

    def _handle_UnaryOp(self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self._handle_expr(0, expr.operand, stmt_idx, stmt, block)

    def _handle_Convert(self, expr_idx: int, expr: Convert, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)

    def _handle_Reinterpret(
        self, expr_idx: int, expr: Reinterpret, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)

    def _handle_ITE(self, expr_idx: int, expr: ITE, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self._handle_expr(0, expr.cond, stmt_idx, stmt, block)
        self._handle_expr(1, expr.iftrue, stmt_idx, stmt, block)
        self._handle_expr(2, expr.iffalse, stmt_idx, stmt, block)

    def _handle_Tmp(self, expr_idx: int, expr: Tmp, stmt_idx: int, stmt: Statement | None, block: Block | None):
        return None

    def _handle_Register(
        self, expr_idx: int, expr: Register, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        return None

    def _handle_ComboRegister(
        self, expr_idx: int, expr: ComboRegister, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        for idx, reg in enumerate(expr.registers):
            self._handle_expr(idx, reg, stmt_idx, stmt, block)

    def _handle_Const(self, expr_idx: int, expr: Const, stmt_idx: int, stmt: Statement | None, block: Block | None):
        return None

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        return None

    def _handle_Phi(self, expr_idx: int, expr: Phi, stmt_idx: int, stmt: Statement | None, block: Block | None):
        for idx, (_, vvar) in enumerate(expr.src_and_vvars):
            if vvar is not None:
                self._handle_expr(idx, vvar, stmt_idx, stmt, block)

    def _handle_MultiStatementExpression(
        self, expr_idx, expr: MultiStatementExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        for idx, stmt_ in enumerate(expr.stmts):
            self._handle_stmt(idx, stmt_, None)
        self._handle_expr(0, expr.expr, stmt_idx, stmt, block)

    def _handle_DirtyExpression(
        self, expr_idx: int, expr: DirtyExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        ops = expr.operands
        for idx, operand in enumerate(ops):
            self._handle_expr(idx, operand, stmt_idx, stmt, block)
        guard = expr.guard
        if guard is not None:
            self._handle_expr(len(ops) + 1, guard, stmt_idx, stmt, block)

    def _handle_VEXCCallExpression(
        self, expr_idx: int, expr: VEXCCallExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        for idx, operand in enumerate(expr.operands):
            self._handle_expr(idx, operand, stmt_idx, stmt, block)

    def _handle_Extract(self, expr_idx: int, expr: Extract, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self._handle_expr(0, expr.base, stmt_idx, stmt, block)
        self._handle_expr(1, expr.offset, stmt_idx, stmt, block)

    def _handle_Insert(self, expr_idx: int, expr: Insert, stmt_idx: int, stmt: Statement | None, block: Block | None):
        self._handle_expr(0, expr.base, stmt_idx, stmt, block)
        self._handle_expr(1, expr.offset, stmt_idx, stmt, block)
        self._handle_expr(2, expr.value, stmt_idx, stmt, block)

    def _handle_RustEnum(
        self, expr_idx: int, expr: RustEnum, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        for idx, field in enumerate(expr.fields):
            self._handle_expr(idx, field, stmt_idx, stmt, block)

    def _handle_Struct(self, expr_idx: int, expr: Struct, stmt_idx: int, stmt: Statement | None, block: Block | None):
        for idx, field in enumerate(expr.fields.values()):
            self._handle_expr(idx, field, stmt_idx, stmt, block)

    def _handle_Array(self, expr_idx: int, expr: Array, stmt_idx: int, stmt: Statement | None, block: Block | None):
        for idx, ele in enumerate(expr.elements):
            self._handle_expr(idx, ele, stmt_idx, stmt, block)

    def _handle_FunctionLikeMacro(
        self, expr_idx: int, expr: FunctionLikeMacro, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        if expr.args:
            for i, arg in enumerate(expr.args):
                self._handle_expr(i, arg, stmt_idx, stmt, block)

    def _handle_StringLiteral(
        self, expr_idx: int, expr: StringLiteral, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        pass


class AILBlockRewriter(AILBlockWalker[Expression, Statement, Block]):
    """
    Walks all statements and expressions of an AIL node, and rebuilds expressions, statements, or blocks if needed.

    If you need a pure walker without rebuilding, use AILBlockViewer instead.

    :ivar update_block: True if the block should be updated in place, False if a new block should be created and
                        returned as the result of walk().
    :ivar replace_phi_stmt: True if you want _handle_Phi be called and vvars potentially replaced; False otherwise.
                            Default to False because in the most majority cases you do not want vvars in a Phi
                            variable be replaced.
    """

    def __init__(
        self, stmt_handlers=None, expr_handlers=None, update_block: bool = True, replace_phi_stmt: bool = False
    ):
        super().__init__(stmt_handlers=stmt_handlers, expr_handlers=expr_handlers)
        self._update_block = update_block
        self._replace_phi_stmt = replace_phi_stmt

    def _top(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        return expr

    def _stmt_top(self, stmt_idx: int, stmt: Statement, block: Block | None) -> Statement:
        return stmt

    def _handle_block_end(self, stmt_results: list[Statement], block: Block) -> Block:
        if all(new is None or new is old for new, old in zip(stmt_results, block.statements)):
            return block
        statements = [new or old for new, old in zip(stmt_results, block.statements)]
        if not self._update_block:
            return block.copy(statements=statements)
        block.statements = statements
        return block

    #
    # Default handlers
    #

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None) -> Statement:
        # Bind child accessors once -- ``stmt.dst``/``stmt.src`` each mint a
        # fresh Py<Expression>; comparing against the bound value keeps the
        # structural ``!=`` semantics while halving the wrapper allocations.
        dst_in = stmt.dst
        dst = self._handle_expr(0, dst_in, stmt_idx, stmt, block)
        assert isinstance(dst, Atom)
        changed = dst != dst_in

        src_in = stmt.src
        src = self._handle_expr(1, src_in, stmt_idx, stmt, block)
        changed |= src != src_in

        if changed:
            return Assignment(stmt.idx, dst, src, **stmt.tags)
        return stmt

    def _handle_WeakAssignment(self, stmt_idx: int, stmt: WeakAssignment, block: Block | None) -> Statement:
        dst_in = stmt.dst
        dst = self._handle_expr(0, dst_in, stmt_idx, stmt, block)
        assert isinstance(dst, Atom)
        changed = dst != dst_in

        src_in = stmt.src
        src = self._handle_expr(1, src_in, stmt_idx, stmt, block)
        changed |= src != src_in

        if changed:
            return WeakAssignment(stmt.idx, dst, src, **stmt.tags)
        return stmt

    def _handle_CAS(self, stmt_idx: int, stmt: CAS, block: Block | None) -> Statement:
        addr_in = stmt.addr
        addr = self._handle_expr(0, addr_in, stmt_idx, stmt, block)
        changed = addr != addr_in

        data_lo_in = stmt.data_lo
        data_lo = self._handle_expr(1, data_lo_in, stmt_idx, stmt, block)
        changed |= data_lo != data_lo_in

        data_hi = None
        data_hi_in = stmt.data_hi
        if data_hi_in is not None:
            data_hi = self._handle_expr(2, data_hi_in, stmt_idx, stmt, block)
            changed |= data_hi != data_hi_in

        expd_lo_in = stmt.expd_lo
        expd_lo = self._handle_expr(3, expd_lo_in, stmt_idx, stmt, block)
        changed |= expd_lo != expd_lo_in

        expd_hi = None
        expd_hi_in = stmt.expd_hi
        if expd_hi_in is not None:
            expd_hi = self._handle_expr(4, expd_hi_in, stmt_idx, stmt, block)
            changed |= expd_hi != expd_hi_in

        old_lo_in = stmt.old_lo
        old_lo = self._handle_expr(5, old_lo_in, stmt_idx, stmt, block)
        assert isinstance(old_lo, Atom)
        changed |= old_lo != old_lo_in

        old_hi = None
        old_hi_in = stmt.old_hi
        if old_hi_in is not None:
            old_hi = self._handle_expr(6, old_hi_in, stmt_idx, stmt, block)
            assert isinstance(old_hi, Atom)
            changed |= old_hi != old_hi_in

        if changed:
            return CAS(
                stmt.idx,
                addr,
                data_lo,
                data_hi,
                expd_lo,
                expd_hi,
                old_lo,
                old_hi,
                stmt.endness,
                **stmt.tags,
            )
        return stmt

    def _handle_SideEffectStatement(self, stmt_idx: int, stmt: SideEffectStatement, block: Block | None) -> Statement:
        expr_in = stmt.expr
        new_expr = self._handle_expr(0, expr_in, stmt_idx, stmt, block)
        changed = new_expr != expr_in

        new_ret_expr = None
        ret_expr_in = stmt.ret_expr
        if ret_expr_in is not None:
            new_ret_expr = self._handle_expr(-1, ret_expr_in, stmt_idx, stmt, block)
            if new_ret_expr is not None and new_ret_expr != ret_expr_in:
                changed = True

        if changed:
            # ``FunctionLikeMacro`` is included because it is a Call-shaped
            # expression that may legitimately replace a Call inside a
            # SideEffectStatement (e.g. format_macro_simplifier rewrites
            # ``stmt.expr`` from a Call to ``format!(...)``). Before the
            # ailment Rust flatten, FunctionLikeMacro inherited from Call
            # via the pyclass hierarchy and matched ``isinstance(_, Call)``
            # automatically; after the flatten the union must be explicit.
            side_effect_expr: Call = new_expr if isinstance(new_expr, (Call, FunctionLikeMacro)) else expr_in
            return SideEffectStatement(
                stmt.idx,
                side_effect_expr,
                ret_expr=new_ret_expr,
                fp_ret_expr=stmt.fp_ret_expr,
                **stmt.tags,
            )
        return stmt

    def _handle_Store(self, stmt_idx: int, stmt: Store, block: Block | None) -> Statement:
        addr_in = stmt.addr
        addr = self._handle_expr(0, addr_in, stmt_idx, stmt, block)
        changed = addr != addr_in

        data_in = stmt.data
        data = self._handle_expr(1, data_in, stmt_idx, stmt, block)
        changed |= data != data_in

        guard_in = stmt.guard
        guard = None if guard_in is None else self._handle_expr(2, guard_in, stmt_idx, stmt, block)
        changed |= guard != guard_in

        if changed:
            return Store(
                stmt.idx,
                addr,
                data,
                stmt.size,
                stmt.endness,
                guard=guard,
                **stmt.tags,
            )
        return stmt

    def _handle_Jump(self, stmt_idx: int, stmt: Jump, block: Block | None) -> Statement:
        target_in = stmt.target
        target = self._handle_expr(0, target_in, stmt_idx, stmt, block)
        changed = target != target_in

        if changed:
            return Jump(
                stmt.idx,
                target,
                target_idx=stmt.target_idx,
                **stmt.tags,
            )
        return stmt

    def _handle_ConditionalJump(self, stmt_idx: int, stmt: ConditionalJump, block: Block | None) -> Statement:
        condition_in = stmt.condition
        condition = self._handle_expr(0, condition_in, stmt_idx, stmt, block)
        changed = condition != condition_in

        true_target = None
        true_target_in = stmt.true_target
        if true_target_in is not None:
            true_target = self._handle_expr(1, true_target_in, stmt_idx, stmt, block)
            changed |= true_target != true_target_in

        false_target = None
        false_target_in = stmt.false_target
        if false_target_in is not None:
            false_target = self._handle_expr(2, false_target_in, stmt_idx, stmt, block)
            changed |= false_target != false_target_in

        if changed:
            return ConditionalJump(
                stmt.idx,
                condition,
                true_target,
                false_target,
                true_target_idx=stmt.true_target_idx,
                false_target_idx=stmt.false_target_idx,
                **stmt.tags,
            )
        return stmt

    def _handle_Return(self, stmt_idx: int, stmt: Return, block: Block | None) -> Statement:
        if stmt.ret_exprs:
            new_ret_exprs = [
                self._handle_expr(idx, expr, stmt_idx, stmt, block) for idx, expr in enumerate(stmt.ret_exprs)
            ]
            changed = any(old is not new for new, old in zip(new_ret_exprs, stmt.ret_exprs))

            if changed:
                return Return(stmt.idx, new_ret_exprs, **stmt.tags)
        return stmt

    def _handle_DirtyStatement(self, stmt_idx: int, stmt: DirtyStatement, block: Block | None) -> Statement:
        dirty_in = stmt.dirty
        dirty = self._handle_expr(0, dirty_in, stmt_idx, stmt, block)
        assert isinstance(dirty, DirtyExpression)
        changed = dirty != dirty_in

        if changed:
            return DirtyStatement(stmt.idx, dirty, **stmt.tags)
        return stmt

    #
    # Expression handlers

    def _handle_expr(self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None):
        # Reach a fixed point. Handlers return the input ``expr`` Python
        # object when nothing changed (legacy convention), so ``is`` is
        # the right termination check. One wrinkle:
        # ``expr.X`` accessors mint fresh wrappers each time, so handlers
        # that compare ``new_X != expr.X`` for ``changed`` may produce
        # a structurally-equal-but-different-identity replacement even
        # when no rewrite happened. Cap the iteration at a few rounds and
        # fall back to a structural ``likes`` check to avoid infinite
        # loops in that corner case.
        for _ in range(8):
            result = super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
            if result is expr:
                return expr
            if isinstance(result, Expression) and isinstance(expr, Expression) and result.likes(expr):
                return result
            expr = result
        return expr

    def _handle_Load(
        self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        addr_in = expr.addr
        addr = self._handle_expr(0, addr_in, stmt_idx, stmt, block)
        changed = addr != addr_in

        if changed:
            new_expr = expr.copy()
            new_expr.addr = addr
            return new_expr
        return expr

    def _handle_ComboRegister(
        self, expr_idx: int, expr: ComboRegister, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        changed = False
        new_regs = []

        for idx, reg in enumerate(expr.registers):
            new_reg = self._handle_expr(idx, reg, stmt_idx, stmt, block)
            if new_reg and new_reg is not reg:
                changed = True
                new_regs.append(new_reg)
            else:
                new_regs.append(reg)

        if changed:
            new_expr = expr.copy()
            new_expr.registers = new_regs
            return new_expr

        return expr

    def _handle_Call(
        self, expr_idx: int, expr: Call, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        changed = False

        # Cache slot accessors -- ``expr.target`` and ``expr.args``
        # each mint fresh wrapper objects per call.
        target_in = expr.target
        if isinstance(target_in, str):
            new_target = target_in
        else:
            new_target = self._handle_expr(-1, target_in, stmt_idx, stmt, block)
            changed |= new_target != target_in

        args_in = expr.args
        new_args = None
        if args_in is not None:
            new_args = [self._handle_expr(idx, arg, stmt_idx, stmt, block) for idx, arg in enumerate(args_in)]
            changed |= any(old is not new for new, old in zip(new_args, args_in))

        if changed:
            expr = expr.copy()
            expr.target = new_target
            expr.args = new_args
            return expr
        return expr

    def _handle_BinaryOp(
        self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        # ``expr.operands`` mints a fresh 2-tuple of fresh wrappers
        # per access; cache once so the recurse + compare pair costs one
        # allocation instead of four.
        ops = expr.operands
        op0_in, op1_in = ops[0], ops[1]
        operand_0 = self._handle_expr(0, op0_in, stmt_idx, stmt, block)
        changed = operand_0 != op0_in

        operand_1 = self._handle_expr(1, op1_in, stmt_idx, stmt, block)
        changed |= operand_1 != op1_in

        if changed:
            new_expr = expr.copy()
            new_expr.operands = (operand_0, operand_1)
            assert operand_0 is not None
            new_expr.depth = max(operand_0.depth, operand_1.depth) + 1
            return new_expr
        return expr

    def _handle_UnaryOp(
        self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        operand_in = expr.operand
        new_operand = self._handle_expr(0, operand_in, stmt_idx, stmt, block)
        changed = new_operand != operand_in

        if changed:
            new_expr = expr.copy()
            new_expr.operand = new_operand
            return new_expr
        return expr

    def _handle_Convert(
        self, expr_idx: int, expr: Convert, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        operand_in = expr.operand
        new_operand = self._handle_expr(expr_idx, operand_in, stmt_idx, stmt, block)
        changed = new_operand != operand_in

        if changed:
            return Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed, new_operand, **expr.tags)
        return expr

    def _handle_Reinterpret(
        self, expr_idx: int, expr: Reinterpret, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        operand_in = expr.operand
        new_operand = self._handle_expr(expr_idx, operand_in, stmt_idx, stmt, block)
        changed = new_operand != operand_in

        if changed:
            return Reinterpret(
                expr.idx, expr.from_bits, expr.from_type, expr.to_bits, expr.to_type, new_operand, **expr.tags
            )
        return expr

    def _handle_ITE(
        self, expr_idx: int, expr: ITE, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        cond_in = expr.cond
        cond = self._handle_expr(0, cond_in, stmt_idx, stmt, block)
        changed = cond != cond_in

        iftrue_in = expr.iftrue
        iftrue = self._handle_expr(1, iftrue_in, stmt_idx, stmt, block)
        changed |= iftrue != iftrue_in

        iffalse_in = expr.iffalse
        iffalse = self._handle_expr(2, iffalse_in, stmt_idx, stmt, block)
        changed |= iffalse != iffalse_in

        if changed:
            new_expr = expr.copy()
            new_expr.cond = cond
            new_expr.iftrue = iftrue
            new_expr.iffalse = iffalse
            return new_expr
        return expr

    def _handle_Phi(
        self, expr_idx: int, expr: Phi, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        if not self._replace_phi_stmt:
            # fallback to the read-only version
            super()._handle_Phi(expr_idx, expr, stmt_idx, stmt, block)
            return expr

        changed = False

        src_and_vvars = [
            (src, self._handle_expr(idx, vvar, stmt_idx, stmt, block) if vvar is not None else None)
            for idx, (src, vvar) in enumerate(expr.src_and_vvars)
        ]
        changed = any(new is not old for (_, new), (_, old) in zip(src_and_vvars, expr.src_and_vvars))

        if changed:
            assert all(vvar is None or isinstance(vvar, VirtualVariable) for _, vvar in src_and_vvars)
            return Phi(
                expr.idx,
                expr.bits,
                cast(list[tuple[tuple[int, int | None], VirtualVariable | None]], src_and_vvars),
                **expr.tags,
            )
        return expr

    def _handle_DirtyExpression(
        self, expr_idx: int, expr: DirtyExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        operands_in = expr.operands
        new_operands = [self._handle_expr(0, operand, stmt_idx, stmt, block) for operand in operands_in]
        changed = any(new is not old for new, old in zip(new_operands, operands_in))

        new_guard = None
        guard_in = expr.guard
        if guard_in is not None:
            new_guard = self._handle_expr(2, guard_in, stmt_idx, stmt, block)
            changed |= new_guard != guard_in

        if changed:
            return DirtyExpression(
                expr.idx,
                expr.callee,
                new_operands,
                guard=new_guard,
                mfx=expr.mfx,
                maddr=expr.maddr,
                msize=expr.msize,
                bits=expr.bits,
                **expr.tags,
            )
        return expr

    def _handle_VEXCCallExpression(
        self, expr_idx: int, expr: VEXCCallExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        operands_in = expr.operands
        new_operands = [
            self._handle_expr(idx, operand, stmt_idx, stmt, block) for idx, operand in enumerate(operands_in)
        ]
        changed = any(new is not old for new, old in zip(new_operands, operands_in))

        if changed:
            new_expr = expr.copy()
            new_expr.operands = tuple(new_operands)
            return new_expr
        return expr

    def _handle_MultiStatementExpression(
        self, expr_idx, expr: MultiStatementExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        stmts_in = expr.stmts
        new_statements = [self._handle_stmt(idx, stmt_, None) for idx, stmt_ in enumerate(stmts_in)]
        changed = any(new is not old for new, old in zip(new_statements, stmts_in))

        expr_in = expr.expr
        new_expr = self._handle_expr(0, expr_in, stmt_idx, stmt, block)
        changed |= new_expr != expr_in

        if changed:
            expr_ = expr.copy()
            expr_.expr = new_expr
            expr_.stmts = new_statements
            return expr_
        return expr

    def _handle_Extract(
        self, expr_idx: int, expr: Extract, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        base_in = expr.base
        offset_in = expr.offset
        new_base = self._handle_expr(0, base_in, stmt_idx, stmt, block)
        new_offset = self._handle_expr(1, offset_in, stmt_idx, stmt, block)

        if new_base != base_in or new_offset != offset_in:
            result = expr.copy()
            result.base = new_base
            result.offset = new_offset
            return result
        return expr

    def _handle_Insert(
        self, expr_idx: int, expr: Insert, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        base_in = expr.base
        offset_in = expr.offset
        value_in = expr.value
        new_base = self._handle_expr(0, base_in, stmt_idx, stmt, block)
        new_offset = self._handle_expr(1, offset_in, stmt_idx, stmt, block)
        new_value = self._handle_expr(2, value_in, stmt_idx, stmt, block)

        if new_base != base_in or new_offset != offset_in or new_value != value_in:
            result = expr.copy()
            result.base = new_base
            result.offset = new_offset
            result.value = new_value
            return result
        return expr

    def _handle_RustEnum(
        self, expr_idx: int, expr: RustEnum, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        changed = False
        new_fields = []
        for idx, field in enumerate(expr.fields):
            new_field = self._handle_expr(idx, field, stmt_idx, stmt, block)
            if new_field is not None and new_field is not field:
                changed = True
                new_fields.append(new_field)
            else:
                new_fields.append(field)

        if changed:
            new_expr = expr.copy()
            new_expr.fields = tuple(new_fields)
            return new_expr
        return expr

    def _handle_StringLiteral(
        self, expr_idx: int, expr: StringLiteral, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        return expr

    def _handle_Struct(self, expr_idx: int, expr: Struct, stmt_idx: int, stmt: Statement | None, block: Block | None):
        changed = False
        new_fields = OrderedDict()
        for idx, (offset, field) in enumerate(expr.fields.items()):
            new_field = self._handle_expr(idx, field, stmt_idx, stmt, block)
            if new_field is not None and new_field is not field:
                changed = True
                new_fields[offset] = new_field
            else:
                new_fields[offset] = field

        if changed:
            new_expr = expr.copy()
            new_expr.fields = new_fields
            return new_expr
        return expr

    def _handle_Array(self, expr_idx: int, expr: Array, stmt_idx: int, stmt: Statement | None, block: Block | None):
        changed = False
        new_elements = []
        for idx, ele in enumerate(expr.elements):
            new_ele = self._handle_expr(idx, ele, stmt_idx, stmt, block)
            if new_ele is not None and new_ele is not ele:
                changed = True
                new_elements.append(new_ele)
            else:
                new_elements.append(ele)

        if changed:
            new_expr = expr.copy()
            new_expr.elements = tuple(new_elements)
            return new_expr
        return expr

    def _handle_FunctionLikeMacro(
        self, expr_idx: int, expr: FunctionLikeMacro, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        changed = False

        new_args = None
        if expr.args is not None:
            i = 0
            new_args = []
            while i < len(expr.args):
                arg = expr.args[i]
                new_arg = self._handle_expr(i, arg, stmt_idx, stmt, block)
                if new_arg is not None and new_arg is not arg:
                    if not changed:
                        # initialize new_args
                        new_args = list(expr.args[:i])
                    new_args.append(new_arg)
                    changed = True
                else:
                    if changed:
                        new_args.append(arg)
                i += 1

        if changed:
            expr = expr.copy()
            expr.args = new_args
            return expr
        return expr
