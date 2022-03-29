from typing import Optional, Any, TYPE_CHECKING

from ailment import Block, Stmt, Expr

from ..decompiler.ailblock_walker import AILBlockWalker

if TYPE_CHECKING:
    from .propagator import PropagatorAILState


class OutdatedDefinitionWalker(AILBlockWalker):
    """
    Walks an AIL expression to find outdated definitions.
    """
    def __init__(self, expr, state: 'PropagatorAILState', avoid: Optional[Expr.Expression]=None):
        super().__init__()
        self.expr = expr
        self.state = state
        self.avoid = avoid
        self.expr_handlers[Expr.Register] = self._handle_Register
        self.expr_handlers[Expr.Load] = self._handle_Load
        self.expr_handlers[Expr.Tmp] = self._handle_Tmp
        self.expr_handlers[Expr.VEXCCallExpression] = self._handle_VEXCCallExpression
        self.out_dated = False

    # pylint:disable=unused-argument
    def _handle_Tmp(self, expr_idx: int, tmp_expr: Expr.Tmp, stmt_idx: int, stmt: Stmt.Assignment,
                    block: Optional[Block]):
        if self.avoid is not None and tmp_expr.likes(self.avoid):
            self.out_dated = True

    # pylint:disable=unused-argument
    def _handle_Register(self, expr_idx: int, reg_expr: Expr.Register, stmt_idx: int, stmt: Stmt.Assignment,
                         block: Optional[Block]):
        if self.avoid is not None and reg_expr.likes(self.avoid):
            self.out_dated = True
        else:
            v = self.state.load_register(reg_expr)
            if v is not None:
                if not self.expr.likes(v):
                    self.out_dated = True
                elif isinstance(v, Expr.TaggedObject) \
                        and v.tags.get('def_at', None) != self.expr.tags.get('def_at', None):
                    self.out_dated = True

    @staticmethod
    def _check_store_precedes_load(store: Stmt.Store, load: Expr.Load) -> bool:
        """
        Check if store precedes load based on VEX tags.
        """
        tags = ('vex_block_addr', 'vex_stmt_idx')
        if all((t in load.tags and t in store.tags) for t in tags):
            return (store.tags['vex_block_addr'] == load.tags['vex_block_addr'] and
                    store.tags['vex_stmt_idx'] <= load.tags['vex_stmt_idx'])
        return False

    @staticmethod
    def _check_global_store_conflicts_load(addr: Any, store: Stmt.Store, load: Expr.Load) -> bool:
        """
        Check if the load may conflict with any existing stores that happened in the past.

        :param addr:
        :param size:
        :param store:
        :param load:
        :return:
        """
        tags = ('vex_block_addr', 'vex_stmt_idx')
        if all((t in load.tags and t in store.tags) for t in tags):
            if store.tags['vex_block_addr'] == load.tags['vex_block_addr'] and \
                    store.tags['vex_stmt_idx'] < load.tags['vex_stmt_idx']:
                written = set()
                if isinstance(addr, Expr.Const) and isinstance(store.size, int):
                    written |= { addr.value + i for i in range(store.size) }
                else:
                    return False  # FIXME: This is unsafe
                if isinstance(load.addr, Expr.Const) and isinstance(load.size, int):
                    read = { load.addr.value + i for i in range(load.size) }
                    return bool(written.intersection(read))
                return True
        return False

    def _handle_Load(self, expr_idx: int, expr: Expr.Load, stmt_idx: int, stmt: Stmt.Statement, block: Optional[Block]):
        if self.avoid is not None and (expr == self.avoid or expr.addr == self.avoid):  # pylint:disable=consider-using-in
            self.out_dated = True
        elif isinstance(expr.addr, Expr.StackBaseOffset) \
                and self.state.last_stack_store is not None \
                and not self._check_store_precedes_load(self.state.last_stack_store, expr):
            self.out_dated = True
        elif isinstance(expr.addr, Expr.Const) \
                and self.state.global_stores \
                and any(self._check_global_store_conflicts_load(addr, store, expr)
                        for addr, store in self.state.global_stores):
            self.out_dated = True
        elif not isinstance(expr.addr, (Expr.StackBaseOffset, Expr.Const)) \
                and (
                self.state.global_stores and
                not any(self._check_store_precedes_load(global_store, expr)
                        for _, global_store in self.state.global_stores) or
                self.state.last_stack_store is not None and
                not self._check_store_precedes_load(self.state.last_stack_store, expr)
        ):
            # check both stack and global stores if the load address is unknown
            self.out_dated = True
        else:
            super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VEXCCallExpression(self, expr_idx: int, expr: Expr.VEXCCallExpression, stmt_idx: int,
                                   stmt: Stmt.Statement, block: Optional[Block]):
        if self.avoid is not None:
            if any(op == self.avoid for op in expr.operands):
                self.out_dated = True

        if not self.out_dated:
            super()._handle_VEXCCallExpression(expr_idx, expr, stmt_idx, stmt, block)
