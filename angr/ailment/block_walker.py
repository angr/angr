# pylint:disable=unused-argument,no-self-use
from __future__ import annotations

from abc import abstractmethod
from collections import OrderedDict
from collections.abc import Callable
from typing import Any, NamedTuple, cast

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
    IRegister,
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
    IRegister,
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
    """Resolve a handler-dict key for ``obj``."""
    # Fast path: fat-enum instances are the overwhelming majority of dispatches (e.g., ~4M on ``doit``).
    # Dispatch on the cached ``pykind`` instead of ``kind`` to avoid extra Rust-to-C conversion.
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


_EXPR_MARKERS = (
    Const,
    Tmp,
    Register,
    ComboRegister,
    IRegister,
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


class _ExprContinue(NamedTuple):
    prepared: Expression
    state: Any = None


class _ExprHandled(NamedTuple):
    result: Any


_EXPR_WORKLIST_MIN_DEPTH = 64


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

    def _uses_expr_handler(self, expr: Expression, handler: Callable) -> bool:
        handlers = self._expr_handlers
        if handlers is None:
            if type(expr) is _RustExpression:
                registered = self._default_expr_funcs_by_pykind.get(expr.pykind)
            else:
                registered = self._default_expr_funcs.get(_dispatch_key(expr))
            return registered is handler
        if type(expr) is _RustExpression:
            key = _EXPR_KIND_TO_MARKER.get(expr.pykind, _RustExpression)
        else:
            key = _dispatch_key(expr)
        registered = handlers.get(key)
        return getattr(registered, "__self__", None) is self and getattr(registered, "__func__", None) is handler

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
        # Inline the stmt-side dispatch: a Rust statement (the common case, ~1M/decompile) skips the ``_dispatch_key``
        # frame and the redundant expr-side check, dispatching on the cached ``pykind`` int directly.
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
        action = self._enter_expr(expr_idx, expr, stmt_idx, stmt, block)
        if isinstance(action, _ExprHandled):
            return action.result
        result = self._handle_prepared_expr(expr_idx, action.prepared, stmt_idx, stmt, block)
        return self._leave_expr(expr_idx, expr, action.prepared, result, action.state, stmt_idx, stmt, block)

    def _uses_default_expr_entry(self) -> bool:
        return "_handle_expr" not in self.__dict__ and type(self)._handle_expr is AILBlockWalker._handle_expr

    @staticmethod
    def _requires_expr_worklist(expr: Expression) -> bool:
        # Recursive expression dispatch uses several Python frames per tree level. Keep ordinary shallow trees on the
        # faster recursive path while switching well before they can approach the interpreter's recursion limit.
        return expr.depth >= _EXPR_WORKLIST_MIN_DEPTH

    def _handle_prepared_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        return self._dispatch_expr(expr_idx, expr, stmt_idx, stmt, block)

    def _dispatch_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        # Inline the expr-side dispatch: a Rust expression (the common case) dispatches on the cached ``pykind`` int
        # with no ``_dispatch_key`` frame and no redundant stmt-side check.
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

    def _enter_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> _ExprContinue | _ExprHandled:
        return _ExprContinue(expr)

    def _leave_expr(
        self,
        expr_idx: int,
        original: Expression,
        prepared: Expression,
        result: ExprType,
        state: Any,
        stmt_idx: int,
        stmt: Statement | None,
        block: Block | None,
    ) -> ExprType:
        return result

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
        if (
            self._requires_expr_worklist(expr)
            and self._uses_default_expr_entry()
            and self._uses_expr_handler(expr, AILBlockWalker._handle_BinaryOp)
        ):
            return self._handle_binary_iteratively(
                expr_idx,
                expr,
                stmt_idx,
                stmt,
                block,
                AILBlockWalker._handle_BinaryOp,
                AILBlockWalker._handle_MultiStatementExpression,
                binary_uses_top=True,
                mse_uses_top=True,
            )

        ops = expr.operands
        self._handle_expr(0, ops[0], stmt_idx, stmt, block)
        self._handle_expr(1, ops[1], stmt_idx, stmt, block)
        return self._top(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_binary_iteratively(
        self,
        expr_idx: int,
        expr: BinaryOp | MultiStatementExpression,
        stmt_idx: int,
        stmt: Statement | None,
        block: Block | None,
        binary_handler: Callable,
        mse_handler: Callable,
        *,
        binary_uses_top: bool,
        mse_uses_top: bool,
    ) -> ExprType:
        """Walk a connected BinaryOp/MultiStatementExpression subtree without using the Python call stack."""

        def iterative_handler(current_expr: Expression) -> Callable | None:
            if isinstance(current_expr, BinaryOp) and self._uses_expr_handler(current_expr, binary_handler):
                return binary_handler
            if isinstance(current_expr, MultiStatementExpression) and self._uses_expr_handler(
                current_expr, mse_handler
            ):
                return mse_handler
            return None

        root_handler = iterative_handler(expr)
        assert root_handler is not None
        stack: list[dict[str, Any]] = [
            {"expr_idx": expr_idx, "prepared": expr, "original": None, "state": None, "handler": root_handler}
        ]

        def descend(child_idx: int, child: Expression) -> None:
            action = self._enter_expr(child_idx, child, stmt_idx, stmt, block)
            if isinstance(action, _ExprHandled):
                return
            prepared = action.prepared
            handler = iterative_handler(prepared)
            if handler is not None:
                stack.append(
                    {
                        "expr_idx": child_idx,
                        "prepared": prepared,
                        "original": child,
                        "state": action.state,
                        "handler": handler,
                    }
                )
                return
            child_result = self._handle_prepared_expr(child_idx, prepared, stmt_idx, stmt, block)
            self._leave_expr(
                child_idx,
                child,
                prepared,
                child_result,
                action.state,
                stmt_idx,
                stmt,
                block,
            )

        result: ExprType | None = None
        while stack:
            frame = stack[-1]
            current_expr = frame["prepared"]
            handler = frame["handler"]
            if handler is binary_handler:
                assert isinstance(current_expr, BinaryOp)
                next_operand = frame.setdefault("next_operand", 0)
                if next_operand < 2:
                    frame["next_operand"] = next_operand + 1
                    descend(next_operand, current_expr.operands[next_operand])
                    continue
                result = self._top(frame["expr_idx"], current_expr, stmt_idx, stmt, block) if binary_uses_top else None
            else:
                assert handler is mse_handler
                assert isinstance(current_expr, MultiStatementExpression)
                next_statement = frame.setdefault("next_statement", 0)
                if next_statement < len(current_expr.stmts):
                    frame["next_statement"] = next_statement + 1
                    self._handle_stmt(next_statement, current_expr.stmts[next_statement], None)
                    continue
                if not frame.get("handled_expr", False):
                    frame["handled_expr"] = True
                    descend(0, current_expr.expr)
                    continue
                result = self._top(frame["expr_idx"], current_expr, stmt_idx, stmt, block) if mse_uses_top else None

            stack.pop()
            if frame["original"] is not None:
                result = self._leave_expr(
                    frame["expr_idx"],
                    frame["original"],
                    cast(Expression, current_expr),
                    cast(ExprType, result),
                    frame["state"],
                    stmt_idx,
                    stmt,
                    block,
                )
        return cast(ExprType, result)

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

    def _handle_IRegister(
        self, expr_idx: int, expr: IRegister, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> ExprType:
        self._handle_expr(0, expr.reg_offset, stmt_idx, stmt, block)
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
        if (
            self._requires_expr_worklist(expr)
            and self._uses_default_expr_entry()
            and self._uses_expr_handler(expr, AILBlockWalker._handle_MultiStatementExpression)
        ):
            return self._handle_binary_iteratively(
                expr_idx,
                expr,
                stmt_idx,
                stmt,
                block,
                AILBlockWalker._handle_BinaryOp,
                AILBlockWalker._handle_MultiStatementExpression,
                binary_uses_top=True,
                mse_uses_top=True,
            )

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
        if (
            self._requires_expr_worklist(expr)
            and self._uses_default_expr_entry()
            and self._uses_expr_handler(expr, AILBlockViewer._handle_BinaryOp)
        ):
            return self._handle_binary_iteratively(
                expr_idx,
                expr,
                stmt_idx,
                stmt,
                block,
                AILBlockViewer._handle_BinaryOp,
                AILBlockViewer._handle_MultiStatementExpression,
                binary_uses_top=False,
                mse_uses_top=False,
            )

        ops = expr.operands
        self._handle_expr(0, ops[0], stmt_idx, stmt, block)
        self._handle_expr(1, ops[1], stmt_idx, stmt, block)
        return None

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

    def _handle_IRegister(
        self, expr_idx: int, expr: IRegister, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        self._handle_expr(0, expr.reg_offset, stmt_idx, stmt, block)

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
        if (
            self._requires_expr_worklist(expr)
            and self._uses_default_expr_entry()
            and self._uses_expr_handler(expr, AILBlockViewer._handle_MultiStatementExpression)
        ):
            return self._handle_binary_iteratively(
                expr_idx,
                expr,
                stmt_idx,
                stmt,
                block,
                AILBlockViewer._handle_BinaryOp,
                AILBlockViewer._handle_MultiStatementExpression,
                binary_uses_top=False,
                mse_uses_top=False,
            )

        for idx, stmt_ in enumerate(expr.stmts):
            self._handle_stmt(idx, stmt_, None)
        self._handle_expr(0, expr.expr, stmt_idx, stmt, block)
        return None

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
            # ``FunctionLikeMacro`` is included because it is a Call-shaped expression that may legitimately replace a
            # Call inside a SideEffectStatement (e.g. format_macro_simplifier rewrites ``stmt.expr`` from a Call to
            # ``format!(...)``). Before the ailment Rust flatten, FunctionLikeMacro inherited from Call via the pyclass
            # hierarchy and matched ``isinstance(_, Call)`` automatically; after the flatten the union must be explicit.
            side_effect_expr: Call | FunctionLikeMacro = (
                new_expr if isinstance(new_expr, (Call, FunctionLikeMacro)) else cast(Call | FunctionLikeMacro, expr_in)
            )
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
        ret_exprs_in = stmt.ret_exprs
        if ret_exprs_in:
            new_ret_exprs = [
                self._handle_expr(idx, expr, stmt_idx, stmt, block) for idx, expr in enumerate(ret_exprs_in)
            ]
            changed = any(old != new for new, old in zip(new_ret_exprs, ret_exprs_in))

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

    def _enter_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> _ExprContinue | _ExprHandled:
        return _ExprContinue(self._pre_handle_expr(expr_idx, expr, stmt_idx, stmt, block))

    def _leave_expr(
        self,
        expr_idx: int,
        original: Expression,
        prepared: Expression,
        result: Expression,
        state: Any,
        stmt_idx: int,
        stmt: Statement | None,
        block: Block | None,
    ) -> Expression:
        return self._post_handle_expr(expr_idx, result, stmt_idx, stmt, block)

    def _handle_prepared_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        if (
            self._requires_expr_worklist(expr)
            and self._uses_default_expr_entry()
            and self._iterative_expr_handler(expr) is not None
        ):
            return self._handle_binary_mse_iteratively(
                expr_idx, cast(BinaryOp | Load | MultiStatementExpression, expr), stmt_idx, stmt, block
            )

        for iteration in range(16):  # limit the number of iterations to avoid infinite loops
            result = self._dispatch_expr(expr_idx, expr, stmt_idx, stmt, block)
            if result is expr:
                return expr
            if isinstance(result, Expression) and isinstance(expr, Expression) and result.likes(expr):
                return result
            expr = result
            if (
                iteration < 15
                and self._requires_expr_worklist(expr)
                and self._uses_default_expr_entry()
                and self._iterative_expr_handler(expr) is not None
            ):
                return self._handle_binary_mse_iteratively(
                    expr_idx,
                    cast(BinaryOp | Load | MultiStatementExpression, expr),
                    stmt_idx,
                    stmt,
                    block,
                    initial_iterations=iteration + 1,
                )
        return expr

    def _pre_handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        return expr

    def _post_handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        return expr

    def _iterative_expr_handler(self, expr: Expression) -> Callable | None:
        for expr_type, handler in (
            (BinaryOp, AILBlockRewriter._handle_BinaryOp),
            (Load, AILBlockRewriter._handle_Load),
            (MultiStatementExpression, AILBlockRewriter._handle_MultiStatementExpression),
        ):
            if isinstance(expr, expr_type) and self._uses_expr_handler(expr, handler):
                return handler
        return None

    def _handle_binary_mse_iteratively(
        self,
        expr_idx: int,
        expr: BinaryOp | Load | MultiStatementExpression,
        stmt_idx: int,
        stmt: Statement | None,
        block: Block | None,
        initial_iterations: int = 0,
    ) -> Expression:
        """Rewrite a connected BinaryOp/Load/MultiStatementExpression subtree without using the Python call stack."""

        stack: list[dict[str, Any]] = [
            {
                "expr_idx": expr_idx,
                "prepared": expr,
                "current": expr,
                "original": None,
                "state": None,
                "iterations": initial_iterations,
            }
        ]
        result: Expression = expr
        while stack:
            frame = stack[-1]
            current_expr = frame["current"]
            starting_dispatch = not frame.get("dispatching", False)
            if starting_dispatch:
                frame["dispatching"] = True
                frame["iterations"] += 1
            iterative_handler = self._iterative_expr_handler(current_expr)
            if iterative_handler is AILBlockRewriter._handle_BinaryOp:
                assert isinstance(current_expr, BinaryOp)
                next_operand = frame.setdefault("next_operand", 0)
                rewritten = frame.setdefault("rewritten", [None, None])
                if next_operand < 2:
                    frame["next_operand"] = next_operand + 1
                    operand = current_expr.operands[next_operand]
                    action = self._enter_expr(next_operand, operand, stmt_idx, stmt, block)
                    if isinstance(action, _ExprHandled):
                        rewritten[next_operand] = action.result
                    elif self._uses_default_expr_entry() and self._iterative_expr_handler(action.prepared) is not None:
                        stack.append(
                            {
                                "expr_idx": next_operand,
                                "prepared": action.prepared,
                                "current": action.prepared,
                                "original": operand,
                                "state": action.state,
                                "iterations": 0,
                            }
                        )
                    else:
                        child_result = self._handle_prepared_expr(next_operand, action.prepared, stmt_idx, stmt, block)
                        rewritten[next_operand] = self._leave_expr(
                            next_operand,
                            operand,
                            action.prepared,
                            child_result,
                            action.state,
                            stmt_idx,
                            stmt,
                            block,
                        )
                    continue

                operand_0, operand_1 = rewritten
                assert operand_0 is not None
                assert operand_1 is not None
                op0_in, op1_in = current_expr.operands
                if operand_0 != op0_in or operand_1 != op1_in:
                    result = cast(BinaryOp, current_expr.copy())
                    result.operands = (operand_0, operand_1)
                    result.depth = max(operand_0.depth, operand_1.depth) + 1
                else:
                    result = current_expr
                result = self._post_handle_BinaryOp(result, stmt_idx, stmt, block)
            elif iterative_handler is AILBlockRewriter._handle_Load:
                assert isinstance(current_expr, Load)
                if starting_dispatch:
                    self._pre_handle_Load(current_expr, stmt_idx, stmt, block)
                if "new_addr" not in frame:
                    addr = current_expr.addr
                    action = self._enter_expr(0, addr, stmt_idx, stmt, block)
                    if isinstance(action, _ExprHandled):
                        frame["new_addr"] = action.result
                    elif self._uses_default_expr_entry() and self._iterative_expr_handler(action.prepared) is not None:
                        stack.append(
                            {
                                "expr_idx": 0,
                                "prepared": action.prepared,
                                "current": action.prepared,
                                "original": addr,
                                "state": action.state,
                                "iterations": 0,
                            }
                        )
                    else:
                        child_result = self._handle_prepared_expr(0, action.prepared, stmt_idx, stmt, block)
                        frame["new_addr"] = self._leave_expr(
                            0,
                            addr,
                            action.prepared,
                            child_result,
                            action.state,
                            stmt_idx,
                            stmt,
                            block,
                        )
                    continue

                new_addr = frame["new_addr"]
                if new_addr != current_expr.addr:
                    result = cast(Load, current_expr.copy())
                    result.addr = new_addr
                else:
                    result = current_expr
            elif iterative_handler is AILBlockRewriter._handle_MultiStatementExpression:
                assert isinstance(current_expr, MultiStatementExpression)
                if starting_dispatch:
                    self._pre_handle_MultiStatementExpression(current_expr, stmt_idx, stmt, block)
                    frame["new_statements"] = self._handle_MultiStatementExpression_statements(current_expr, block)

                if "new_expr" not in frame:
                    nested_expr = current_expr.expr
                    action = self._enter_expr(0, nested_expr, stmt_idx, stmt, block)
                    if isinstance(action, _ExprHandled):
                        frame["new_expr"] = action.result
                    elif self._uses_default_expr_entry() and self._iterative_expr_handler(action.prepared) is not None:
                        stack.append(
                            {
                                "expr_idx": 0,
                                "prepared": action.prepared,
                                "current": action.prepared,
                                "original": nested_expr,
                                "state": action.state,
                                "iterations": 0,
                            }
                        )
                    else:
                        child_result = self._handle_prepared_expr(0, action.prepared, stmt_idx, stmt, block)
                        frame["new_expr"] = self._leave_expr(
                            0,
                            nested_expr,
                            action.prepared,
                            child_result,
                            action.state,
                            stmt_idx,
                            stmt,
                            block,
                        )
                    continue

                result = self._post_handle_MultiStatementExpression(
                    current_expr, frame["new_statements"], frame["new_expr"]
                )
            else:
                result = self._dispatch_expr(frame["expr_idx"], current_expr, stmt_idx, stmt, block)

            if result is not current_expr and not (
                isinstance(result, Expression) and isinstance(current_expr, Expression) and result.likes(current_expr)
            ):
                frame["current"] = result
                if frame["iterations"] < 16:
                    frame["dispatching"] = False
                    frame.pop("next_operand", None)
                    frame.pop("rewritten", None)
                    frame.pop("new_addr", None)
                    frame.pop("new_statements", None)
                    frame.pop("new_expr", None)
                    continue

            completed_expr_idx = frame["expr_idx"]
            stack.pop()
            if not stack:
                return result

            result = self._leave_expr(
                completed_expr_idx,
                frame["original"],
                frame["prepared"],
                result,
                frame["state"],
                stmt_idx,
                stmt,
                block,
            )
            parent = stack[-1]
            if isinstance(parent["current"], BinaryOp):
                parent["rewritten"][parent["next_operand"] - 1] = result
            elif isinstance(parent["current"], Load):
                parent["new_addr"] = result
            else:
                parent["new_expr"] = result

        raise AssertionError("iterative expression stack unexpectedly became empty")

    def _handle_Load(
        self, expr_idx: int, expr: Load, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        self._pre_handle_Load(expr, stmt_idx, stmt, block)
        addr_in = expr.addr
        addr = self._handle_expr(0, addr_in, stmt_idx, stmt, block)
        changed = addr != addr_in

        if changed:
            new_expr = expr.copy()
            new_expr.addr = addr
            return new_expr
        return expr

    def _pre_handle_Load(self, expr: Load, stmt_idx: int, stmt: Statement | None, block: Block | None) -> None:
        pass

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
            expr = new_expr
        return self._post_handle_BinaryOp(expr, stmt_idx, stmt, block)

    def _post_handle_BinaryOp(
        self, expr: BinaryOp, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
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

    def _handle_IRegister(
        self, expr_idx: int, expr: IRegister, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        reg_offset_in = expr.reg_offset
        new_reg_offset = self._handle_expr(0, reg_offset_in, stmt_idx, stmt, block)
        if new_reg_offset != reg_offset_in:
            new_expr = expr.copy()
            new_expr.reg_offset = new_reg_offset
            return new_expr
        return expr

    def _handle_Convert(
        self, expr_idx: int, expr: Convert, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> Expression:
        operand_in = expr.operand
        new_operand = self._handle_expr(expr_idx, operand_in, stmt_idx, stmt, block)
        changed = new_operand != operand_in

        if changed:
            return Convert(
                expr.idx,
                expr.from_bits,
                expr.to_bits,
                expr.is_signed,
                new_operand,
                from_type=expr.from_type,
                to_type=expr.to_type,
                rounding_mode=expr.rounding_mode,
                vector_count=expr.vector_count,
                **expr.tags,
            )
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

        src_and_vvars_in = expr.src_and_vvars
        src_and_vvars = [
            (src, self._handle_expr(idx, vvar, stmt_idx, stmt, block) if vvar is not None else None)
            for idx, (src, vvar) in enumerate(src_and_vvars_in)
        ]
        changed = any(new != old for (_, new), (_, old) in zip(src_and_vvars, src_and_vvars_in))

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
        changed = any(new != old for new, old in zip(new_operands, operands_in))

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
        self._pre_handle_MultiStatementExpression(expr, stmt_idx, stmt, block)
        new_statements = self._handle_MultiStatementExpression_statements(expr, block)
        new_expr = self._handle_expr(0, expr.expr, stmt_idx, stmt, block)
        return self._post_handle_MultiStatementExpression(expr, new_statements, new_expr)

    def _pre_handle_MultiStatementExpression(
        self, expr: MultiStatementExpression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> None:
        pass

    def _handle_MultiStatementExpression_statements(
        self, expr: MultiStatementExpression, block: Block | None
    ) -> list[Statement]:
        return [self._handle_stmt(idx, stmt, None) for idx, stmt in enumerate(expr.stmts)]

    def _post_handle_MultiStatementExpression(
        self, expr: MultiStatementExpression, new_statements: list[Statement], new_expr: Expression
    ) -> Expression:
        if (
            len(new_statements) != len(expr.stmts)
            or any(new is not old for new, old in zip(new_statements, expr.stmts))
            or new_expr != expr.expr
        ):
            result = expr.copy()
            result.expr = new_expr
            result.stmts = new_statements
            return result
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
