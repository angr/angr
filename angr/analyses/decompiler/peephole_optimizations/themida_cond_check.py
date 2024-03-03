from typing import Optional

from ailment.statement import ConditionalJump
from ailment.expression import ITE, Convert, DirtyExpression, VEXCCallExpression, Tmp, BinaryOp, Const

from ailment import AILBlockWalker, Expression
from ailment.statement import Statement
from .themida_cond_simpifier import ThemidaCondSimplify
from .base import PeepholeOptimizationStmtBase

class ThemidaCondCheck(PeepholeOptimizationStmtBase):
    __slots__ = ()

    NAME = "Themida inside flag check stmt"
    stmt_classes = (ConditionalJump,)

    def optimize(self, stmt: ConditionalJump, **kwargs):
        cond = stmt.condition
        if (
                isinstance(stmt.condition, Convert) and isinstance(stmt.condition.operands[0], DirtyExpression)
                and isinstance(stmt.condition.operands[0].dirty_expr, VEXCCallExpression)
                and stmt.condition.operand.dirty_expr.cee_name == "x86g_calculate_condition"
        ):
            calc_cond_dirty_expr = stmt.condition.operand
            if not isinstance(stmt.condition.operands[0].dirty_expr.operands[2], Tmp):
                if (
                        stmt.condition.operand.dirty_expr.operands[0].value == 4
                        and stmt.condition.operand.dirty_expr.operands[1].value == 0xf
                ):
                    # we set this to true if we are inside a "x86_calculate_condition" with the above conditions
                    # actual simplification in ThemidaCondSimplify
                    old_operands = stmt.condition.operand.dirty_expr.operands

                    simp_cls = ThemidaCondSimplify(self.project, self.kb, self.func_addr)

                    def _handle_expr(
                            expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement, block
                    ) -> Optional[Expression]:
                        old_expr = expr

                        redo = True
                        while redo:
                            redo = False
                            if isinstance(expr, simp_cls.expr_classes):
                                r = simp_cls.optimize(expr)
                                if r is not None and r is not expr:
                                    expr = r
                                    redo = True
                                    break

                        if expr is not old_expr:
                            # continue to process the expr
                            r = AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)
                            return expr if r is None else r

                        return AILBlockWalker._handle_expr(walker, expr_idx, expr, stmt_idx, stmt, block)

                    # run expression optimizers
                    walker = AILBlockWalker()
                    walker._handle_expr = _handle_expr
                    new_operand_calc_flag = walker.walk_expression(stmt.condition.operands[0].dirty_expr.operands[2])

                    if new_operand_calc_flag:
                        new_cacl_cond_operands = (old_operands[0], old_operands[1], new_operand_calc_flag, old_operands[3], old_operands[4])
                        new_calc_cond_ccall = VEXCCallExpression(calc_cond_dirty_expr.dirty_expr.idx,
                                                                 calc_cond_dirty_expr.dirty_expr.cee_name,
                                                                 new_cacl_cond_operands,
                                                                 bits=calc_cond_dirty_expr.bits)
                        new_dirty_ccall_calc_cond = DirtyExpression(calc_cond_dirty_expr.idx, new_calc_cond_ccall, calc_cond_dirty_expr.bits)
                        new_cond = Convert(cond.idx, cond.from_bits, cond.to_bits, cond.is_signed, new_dirty_ccall_calc_cond)
                        return ConditionalJump(stmt.idx, new_cond, stmt.true_target, stmt.false_target, **stmt.tags)

        return None
