from typing import Optional, Callable, TYPE_CHECKING

from ailment import Block, Stmt, Expr, AILBlockWalker

from ...errors import SimMemoryMissingError
from ...code_location import CodeLocation

if TYPE_CHECKING:
    from archinfo import Arch
    from .propagator import PropagatorAILState
    from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
    from angr.knowledge_plugins.key_definitions import LiveDefinitions


class OutdatedDefinitionWalker(AILBlockWalker):
    """
    Walks an AIL expression to find outdated definitions.
    """

    def __init__(
        self,
        expr,
        expr_defat: CodeLocation,
        livedefs_defat: "LiveDefinitions",
        current_loc: CodeLocation,
        livedefs_currentloc: "LiveDefinitions",
        state: "PropagatorAILState",
        arch: "Arch",
        avoid: Optional[Expr.Expression] = None,
        extract_offset_to_sp: Callable = None,
    ):
        super().__init__()
        self.expr = expr
        self.expr_defat = expr_defat
        self.livedefs_defat = livedefs_defat
        self.current_loc = current_loc
        self.livedefs_currentloc = livedefs_currentloc
        self.state = state
        self.avoid = avoid
        self.arch = arch
        self.extract_offset_to_sp = extract_offset_to_sp
        self.expr_handlers[Expr.Register] = self._handle_Register
        self.expr_handlers[Expr.Load] = self._handle_Load
        self.expr_handlers[Expr.Tmp] = self._handle_Tmp
        self.expr_handlers[Expr.VEXCCallExpression] = self._handle_VEXCCallExpression
        self.out_dated = False
        self.has_avoid = False

    # pylint:disable=unused-argument
    def _handle_Tmp(self, expr_idx: int, expr: Expr.Tmp, stmt_idx: int, stmt: Stmt.Assignment, block: Optional[Block]):
        if self.avoid is not None and expr.likes(self.avoid):
            self.has_avoid = True

    # pylint:disable=unused-argument
    def _handle_Register(
        self, expr_idx: int, expr: Expr.Register, stmt_idx: int, stmt: Stmt.Assignment, block: Optional[Block]
    ):
        if (
            self.avoid is not None
            and isinstance(self.avoid, Expr.Register)
            and (expr.likes(self.avoid) or self._reg_overlap(expr, self.avoid))
        ):
            self.has_avoid = True

        # is the used register still alive at this point?
        try:
            reg_vals: "MultiValues" = self.livedefs_defat.register_definitions.load(expr.reg_offset, size=expr.size)
            defs_defat = list(self.livedefs_defat.extract_defs_from_mv(reg_vals))
        except SimMemoryMissingError:
            defs_defat = []

        try:
            reg_vals: "MultiValues" = self.livedefs_currentloc.register_definitions.load(
                expr.reg_offset, size=expr.size
            )
            defs_currentloc = list(self.livedefs_currentloc.extract_defs_from_mv(reg_vals))
        except SimMemoryMissingError:
            defs_currentloc = []

        codelocs_defat = {def_.codeloc for def_ in defs_defat}
        codelocs_currentloc = {def_.codeloc for def_ in defs_currentloc}
        if not (codelocs_defat and codelocs_currentloc and codelocs_defat == codelocs_currentloc):
            self.out_dated = True

    def _handle_Load(self, expr_idx: int, expr: Expr.Load, stmt_idx: int, stmt: Stmt.Statement, block: Optional[Block]):
        if self.avoid is not None and (  # pylint:disable=consider-using-in
            expr == self.avoid or expr.addr == self.avoid
        ):
            self.has_avoid = True

        if isinstance(expr.addr, Expr.StackBaseOffset):
            sp_offset = self.extract_offset_to_sp(expr.addr)

            if sp_offset is not None:
                stack_addr = self.livedefs_defat.stack_offset_to_stack_addr(sp_offset)
                try:
                    mem_vals: "MultiValues" = self.livedefs_defat.stack_definitions.load(
                        stack_addr, size=expr.size, endness=expr.endness
                    )
                    defs_defat = list(self.livedefs_defat.extract_defs_from_mv(mem_vals))
                except SimMemoryMissingError:
                    defs_defat = []

                try:
                    mem_vals: "MultiValues" = self.livedefs_currentloc.stack_definitions.load(
                        stack_addr, size=expr.size, endness=expr.endness
                    )
                    defs_currentloc = list(self.livedefs_defat.extract_defs_from_mv(mem_vals))
                except SimMemoryMissingError:
                    defs_currentloc = []

                codelocs_defat = {def_.codeloc for def_ in defs_defat}
                codelocs_currentloc = {def_.codeloc for def_ in defs_currentloc}

                if not codelocs_defat and not codelocs_currentloc:
                    # fallback
                    if not self._check_store_precedes_load(self.expr_defat, self.current_loc):
                        self.out_dated = True
                elif not (codelocs_defat and codelocs_currentloc and codelocs_defat == codelocs_currentloc):
                    self.out_dated = True

            else:
                # in cases where expr.addr cannot be resolved to a concrete stack offset, we play safe and assume
                # it's outdated
                self.out_dated = True

        elif isinstance(expr.addr, Expr.Const):
            mem_addr = expr.addr.value
            try:
                mem_vals: "MultiValues" = self.livedefs_defat.memory_definitions.load(
                    mem_addr, size=expr.size, endness=expr.endness
                )
                defs_defat = list(self.livedefs_defat.extract_defs_from_mv(mem_vals))
            except SimMemoryMissingError:
                defs_defat = []

            try:
                mem_vals: "MultiValues" = self.livedefs_currentloc.memory_definitions.load(
                    mem_addr, size=expr.size, endness=expr.endness
                )
                defs_currentloc = list(self.livedefs_defat.extract_defs_from_mv(mem_vals))
            except SimMemoryMissingError:
                defs_currentloc = []

            codelocs_defat = {def_.codeloc for def_ in defs_defat}
            codelocs_currentloc = {def_.codeloc for def_ in defs_currentloc}

            if codelocs_defat != codelocs_currentloc:
                self.out_dated = True

        else:
            # the address is not concrete - we check the address first
            super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)
            # then if the address expression is up-to-date, we check the global store
            if not self.out_dated:
                if (
                    self.state.global_stores
                    and not all(
                        self._check_store_precedes_load(CodeLocation(store_block_addr, store_stmt_idx), self.expr_defat)
                        for store_block_addr, store_stmt_idx, addr, store in self.state.global_stores
                    )
                    or self.state.last_stack_store is not None
                    and not self._check_store_precedes_load(
                        CodeLocation(*self.state.last_stack_store[:2]), self.expr_defat
                    )
                ):
                    self.out_dated = True

    def _handle_VEXCCallExpression(
        self, expr_idx: int, expr: Expr.VEXCCallExpression, stmt_idx: int, stmt: Stmt.Statement, block: Optional[Block]
    ):
        if self.avoid is not None:
            if any(op == self.avoid for op in expr.operands):
                self.has_avoid = True

        super()._handle_VEXCCallExpression(expr_idx, expr, stmt_idx, stmt, block)

    @staticmethod
    def _reg_overlap(reg0: Expr.Register, reg1: Expr.Register) -> bool:
        if reg0.reg_offset <= reg1.reg_offset < reg0.reg_offset + reg0.size:
            return True
        if reg1.reg_offset <= reg0.reg_offset < reg1.reg_offset + reg1.size:
            return True
        return False

    @staticmethod
    def _check_store_precedes_load(store_defat: Optional[CodeLocation], load_defat: Optional[CodeLocation]) -> bool:
        """
        Check if store precedes load based on their AIL statement IDs.
        """
        if store_defat is None or load_defat is None:
            return True
        return store_defat.block_addr == load_defat.block_addr and store_defat.stmt_idx <= load_defat.stmt_idx
