# pylint:disable=consider-using-in
from typing import TYPE_CHECKING
from collections.abc import Callable

from ailment import Block, Stmt, Expr, AILBlockWalker

from ...code_location import CodeLocation
from ...knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from ...knowledge_plugins.key_definitions import atoms

if TYPE_CHECKING:
    from archinfo import Arch
    from .propagator import PropagatorAILState
    from angr.analyses.reaching_definitions import ReachingDefinitionsModel


class OutdatedDefinitionWalker(AILBlockWalker):
    """
    Walks an AIL expression to find outdated definitions.
    """

    def __init__(
        self,
        expr,
        expr_defat: CodeLocation,
        current_loc: CodeLocation,
        state: "PropagatorAILState",
        arch: "Arch",
        avoid: Expr.Expression | None = None,
        extract_offset_to_sp: Callable = None,
        rda: "ReachingDefinitionsModel" = None,
    ):
        super().__init__()
        self.expr = expr
        self.expr_defat = expr_defat
        self.current_loc = current_loc
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
        self.rda = rda

    # pylint:disable=unused-argument
    def _handle_Tmp(self, expr_idx: int, expr: Expr.Tmp, stmt_idx: int, stmt: Stmt.Assignment, block: Block | None):
        if self.avoid is not None and expr.likes(self.avoid):
            self.has_avoid = True

    # pylint:disable=unused-argument
    def _handle_Register(
        self, expr_idx: int, expr: Expr.Register, stmt_idx: int, stmt: Stmt.Assignment, block: Block | None
    ):
        if (
            self.avoid is not None
            and isinstance(self.avoid, Expr.Register)
            and (expr.likes(self.avoid) or self._reg_overlap(expr, self.avoid))
        ):
            self.has_avoid = True

        # is the used register still alive at this point?
        defs_defat = self.rda.get_defs(atoms.Register(expr.reg_offset, expr.size), self.expr_defat, OP_AFTER)
        defs_currentloc = self.rda.get_defs(atoms.Register(expr.reg_offset, expr.size), self.current_loc, OP_BEFORE)

        codelocs_defat = {def_.codeloc for def_ in defs_defat}
        codelocs_currentloc = {def_.codeloc for def_ in defs_currentloc}
        if not (codelocs_defat and codelocs_currentloc and codelocs_defat == codelocs_currentloc):
            self.out_dated = True

    def _handle_Load(self, expr_idx: int, expr: Expr.Load, stmt_idx: int, stmt: Stmt.Statement, block: Block | None):
        if self.avoid is not None and (expr == self.avoid or expr.addr == self.avoid):
            self.has_avoid = True

        if isinstance(expr.addr, Expr.StackBaseOffset):
            sp_offset = self.extract_offset_to_sp(expr.addr)

            if sp_offset is not None:
                defs_defat = self.rda.get_defs(
                    atoms.MemoryLocation(atoms.SpOffset(expr.bits, sp_offset), expr.size), self.expr_defat, OP_AFTER
                )
                defs_currentloc = self.rda.get_defs(
                    atoms.MemoryLocation(atoms.SpOffset(expr.bits, sp_offset), expr.size), self.current_loc, OP_BEFORE
                )

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

            defs_defat = self.rda.get_defs(atoms.MemoryLocation(mem_addr, expr.size), self.expr_defat, OP_AFTER)
            defs_currentloc = self.rda.get_defs(atoms.MemoryLocation(mem_addr, expr.size), self.current_loc, OP_BEFORE)

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
        self, expr_idx: int, expr: Expr.VEXCCallExpression, stmt_idx: int, stmt: Stmt.Statement, block: Block | None
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
    def _check_store_precedes_load(store_defat: CodeLocation | None, load_defat: CodeLocation | None) -> bool:
        """
        Check if store precedes load based on their AIL statement IDs.
        """
        if store_defat is None or load_defat is None:
            return True
        return store_defat.block_addr == load_defat.block_addr and store_defat.stmt_idx <= load_defat.stmt_idx
