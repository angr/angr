from __future__ import annotations

from angr.ailment import Block
from angr.ailment.expression import BinaryOp, Const, Convert, Expression, Extract, UnaryOp, VirtualVariable
from angr.ailment.statement import ConditionalJump, Jump
from angr.analyses.decompiler.x87_fsw import const_is_nan

from .optimization_pass import OptimizationPass, OptimizationPassStage

# float comparisons that are false when the operands are unordered
_ORDERED_CMPS = frozenset({"CmpEQ", "CmpLT", "CmpLE", "CmpGT", "CmpGE"})


class NaNGuardRemover(OptimizationPass):
    """
    Removes a NaN test that every predecessor has already ruled out. x86 float branches test the parity flag after
    the comparison, e.g., ``if (a == b) { if (isunordered(a, b)) goto X; ... } else goto X``: the second jump is
    never taken. Left alone, return duplication splits the two jumps to X into an extra ``else if`` branch.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Remove NaN tests that dominating float comparisons rule out"
    DESCRIPTION = (__doc__ or "").strip()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.analyze()

    def _check(self):
        return True, None

    def _analyze(self, cache=None):
        for block in list(self._graph):
            if not block.statements or not isinstance(block.statements[-1], ConditionalJump):
                continue
            jump = block.statements[-1]
            nan_test = self._nan_test(jump.condition)
            if nan_test is None:
                continue
            terms, negated = nan_test
            # the NaN test is false here
            if negated:
                target, target_idx = jump.true_target, jump.true_target_idx
                nan_target = (jump.false_target, jump.false_target_idx)
            else:
                target, target_idx = jump.false_target, jump.false_target_idx
                nan_target = (jump.true_target, jump.true_target_idx)
            if not isinstance(target, Const) or not isinstance(nan_target[0], Const):
                continue
            preds = list(self._graph.predecessors(block))
            if not preds or not all(self._rules_out_nan(pred, block, terms, nan_target) for pred in preds):
                continue
            new_block = block.copy(statements=[*block.statements[:-1], Jump(jump.idx, target, target_idx, **jump.tags)])
            self._update_block(block, new_block)
            assert self.out_graph is not None
            for succ in list(self.out_graph.successors(new_block)):
                if not self._is_target(succ, target.value, target_idx):
                    self.out_graph.remove_edge(new_block, succ)

    @staticmethod
    def _nan_test(cond: Expression) -> tuple[list[Expression], bool] | None:
        """(the values whose NaN-ness is tested, negated) for isnan(x), isunordered(a, b), x != x, or a negation."""
        negated = False
        while isinstance(cond, UnaryOp) and cond.op == "Not":
            cond = cond.operand
            negated = not negated
        if isinstance(cond, UnaryOp) and cond.op == "IsNaN":
            terms = [cond.operand]
        elif isinstance(cond, BinaryOp) and cond.floating_point and cond.op == "CmpUN":
            terms = list(cond.operands)
        elif (
            isinstance(cond, BinaryOp)
            and cond.floating_point
            and cond.op in {"CmpEQ", "CmpNE"}
            and cond.operands[0].likes(cond.operands[1])
        ):
            terms = [cond.operands[0]]
            if cond.op == "CmpEQ":
                negated = not negated
        else:
            return None
        terms = [t for t in terms if not (isinstance(t, Const) and not const_is_nan(t))]
        # a load or call may read a different value than the predecessor compared
        if not all(NaNGuardRemover._is_pure(t) for t in terms):
            return None
        return terms, negated

    @staticmethod
    def _is_pure(expr: Expression) -> bool:
        if isinstance(expr, (VirtualVariable, Const)):
            return True
        if isinstance(expr, (Convert, UnaryOp)):
            return NaNGuardRemover._is_pure(expr.operand)
        if isinstance(expr, Extract):
            return NaNGuardRemover._is_pure(expr.base) and NaNGuardRemover._is_pure(expr.offset)
        if isinstance(expr, BinaryOp):
            return all(NaNGuardRemover._is_pure(o) for o in expr.operands)
        return False

    def _rules_out_nan(self, pred: Block, block: Block, terms: list[Expression], nan_target: tuple) -> bool:
        """
        Whether taking the edge pred -> block implies that no term is NaN. pred's other edge must go where the NaN
        test goes: AIL float comparisons drop the unordered outcome, so that is where pred really sends NaNs.
        """
        if pred is block or not pred.statements or not isinstance(pred.statements[-1], ConditionalJump):
            return False
        jump = pred.statements[-1]
        on_true = self._is_target(block, jump.true_target, jump.true_target_idx)
        on_false = self._is_target(block, jump.false_target, jump.false_target_idx)
        if on_true == on_false:
            return False
        other, other_idx = (
            (jump.false_target, jump.false_target_idx) if on_true else (jump.true_target, jump.true_target_idx)
        )
        if not (isinstance(other, Const) and other.value == nan_target[0].value and other_idx == nan_target[1]):
            return False
        cond = jump.condition
        while isinstance(cond, UnaryOp) and cond.op == "Not":
            cond = cond.operand
            on_true = not on_true
        if not (isinstance(cond, BinaryOp) and cond.floating_point):
            return False
        if cond.op in _ORDERED_CMPS:
            ordered = on_true
        elif cond.op == "CmpNE":
            ordered = not on_true
        else:
            return False
        if not ordered:
            return False
        a, b = cond.operands
        return all(t.likes(a) or t.likes(b) for t in terms)

    @staticmethod
    def _is_target(block: Block, target, target_idx: int | None) -> bool:
        if isinstance(target, Const):
            target = target.value
        return isinstance(target, int) and block.addr == target and (target_idx is None or block.idx == target_idx)
