from typing import Optional, Any, Callable, TYPE_CHECKING

from ailment import Block, Stmt, Expr

from ...code_location import CodeLocation
from ..decompiler.ailblock_walker import AILBlockWalker

if TYPE_CHECKING:
    from .propagator import PropagatorAILState


class OutdatedDefinitionWalker(AILBlockWalker):
    """
    Walks an AIL expression to find outdated definitions.
    """
    def __init__(self, expr, expr_defat: CodeLocation, state: 'PropagatorAILState',
                 avoid: Optional[Expr.Expression]=None, extract_offset_to_sp: Callable=None):
        super().__init__()
        self.expr = expr
        self.expr_defat = expr_defat
        self.state = state
        self.avoid = avoid
        self.extract_offset_to_sp = extract_offset_to_sp
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
        if self.avoid is not None and isinstance(self.avoid, Expr.Register) and (
                reg_expr.likes(self.avoid) or self._reg_overlap(reg_expr, self.avoid)):
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
                    if isinstance(detail.expr, Expr.TaggedObject):
                        if not (detail.def_at == self.expr_defat or
                                self._check_store_precedes_load(detail.def_at, self.expr_defat)):
                            self.out_dated = True
                            break

    @staticmethod
    def _check_store_precedes_load(store_defat: Optional[CodeLocation], load_defat: Optional[CodeLocation]) -> bool:
        """
        Check if store precedes load based on their AIL statement IDs.
        """
        if store_defat is None or load_defat is None:
            return True
        return store_defat.block_addr == load_defat.block_addr and store_defat.stmt_idx <= load_defat.stmt_idx

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
        elif isinstance(expr.addr, Expr.StackBaseOffset):
            sp_offset = self.extract_offset_to_sp(expr.addr)
            if sp_offset is not None:
                # if expr.addr can be resolved to a concrete stack offset, perform the read and detect if the variables
                # on the stack are updated after their values are loaded into self.expr
                curr_stackvar = self.state.load_stack_variable(sp_offset, expr.size, endness=expr.endness)
                if curr_stackvar is None:
                    # the variable does not exist!
                    pass
                else:
                    for details in curr_stackvar.offset_and_details.values():
                        if details.def_at is None or not self._check_store_precedes_load(
                                details.def_at, self.expr_defat):
                            self.out_dated = True
                            break
                    if not self.out_dated:
                        # if there has been a stack store whose address cannot be resolved or concretized, we see if
                        # this store happens after the current definition. if so, we mark it as out-dated
                        if self.state.last_stack_store is not None \
                                and not self._check_store_precedes_load(CodeLocation(*self.state.last_stack_store[:2]),
                                                                        self.expr_defat):
                            self.out_dated = True
            else:
                # in cases where expr.addr cannot be resolved to a concrete stack offset, we play safe and assume
                # it's outdated
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
                not all(self._check_store_precedes_load(CodeLocation(store_block_addr, store_stmt_idx), self.expr_defat)
                        for store_block_addr, store_stmt_idx, addr, store in self.state.global_stores) or
                self.state.last_stack_store is not None and
                not self._check_store_precedes_load(CodeLocation(*self.state.last_stack_store[:2]),
                                                    self.expr_defat)
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

    @staticmethod
    def _reg_overlap(reg0: Expr.Register, reg1: Expr.Register) -> bool:
        if reg0.reg_offset <= reg1.reg_offset < reg0.reg_offset + reg0.size:
            return True
        if reg1.reg_offset <= reg0.reg_offset < reg1.reg_offset + reg1.size:
            return True
        return False
