from typing import Optional, Any, TYPE_CHECKING

from ailment import Block, Stmt, Expr

from ..decompiler.ailblock_walker import AILBlockWalker

if TYPE_CHECKING:
    from .propagator import PropagatorAILState
    from angr.code_location import CodeLocation


class OutdatedDefinitionWalker(AILBlockWalker):
    """
    Walks an AIL expression to find outdated definitions.
    """
    def __init__(self, expr, expr_defat: 'CodeLocation', state: 'PropagatorAILState',
                 avoid: Optional[Expr.Expression]=None):
        super().__init__()
        self.expr = expr
        self.expr_defat = expr_defat
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
                for detail in v.offset_and_details.values():
                    if detail.expr is None:
                        self.out_dated = True
                        break
                    if isinstance(detail.expr, Expr.Expression) and detail.expr.has_atom(reg_expr, identity=False):
                        self.out_dated = True
                        break
                    if isinstance(detail.expr, Expr.TaggedObject) and detail.def_at != self.expr_defat:
                        self.out_dated = True
                        break

    @staticmethod
    def _check_store_precedes_load(store_block_addr: int, store_stmt_idx: int, store: Stmt.Store,
                                   load_block_addr: int, load_stmt_idx: int, load: Expr.Load) -> bool:
        """
        Check if store precedes load based on their AIL statement IDs.
        """
        return store_block_addr == load_block_addr and store_stmt_idx <= load_stmt_idx

    @staticmethod
    def _check_global_store_conflicts_load(store_block_addr: int, store_stmt_idx: int, addr: Any, store: Stmt.Store,
                                           load_block_addr: int, load_stmt_idx: int, load: Expr.Load) -> bool:
        """
        Check if the load may conflict with any existing stores that happened in the past.

        :param addr:
        :param size:
        :param store:
        :param load:
        :return:
        """
        if store_block_addr == load_block_addr and store_stmt_idx >= load_stmt_idx:
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
                and not self._check_store_precedes_load(*self.state.last_stack_store,
                                                        self.expr_defat.block_addr, self.expr_defat.stmt_idx, expr):
            self.out_dated = True
        elif isinstance(expr.addr, Expr.Const) \
                and self.state.global_stores \
                and any(self._check_global_store_conflicts_load(store_block_addr, store_stmt_idx, addr, store,
                                                            self.expr_defat.block_addr, self.expr_defat.stmt_idx, expr)
                        for store_block_addr, store_stmt_idx, addr, store in self.state.global_stores):
            self.out_dated = True
        elif not isinstance(expr.addr, (Expr.StackBaseOffset, Expr.Const)) \
                and (
                self.state.global_stores and
                not all(self._check_store_precedes_load(store_block_addr, store_stmt_idx, store,
                                                        self.expr_defat.block_addr, self.expr_defat.stmt_idx, expr)
                        for store_block_addr, store_stmt_idx, addr, store in self.state.global_stores) or
                self.state.last_stack_store is not None and
                not self._check_store_precedes_load(*self.state.last_stack_store,
                                                    self.expr_defat.block_addr, self.expr_defat.stmt_idx, expr)
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
