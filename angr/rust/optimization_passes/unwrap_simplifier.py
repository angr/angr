import logging
from collections import defaultdict

from ailment.expression import BinaryOp, Load, VirtualVariable, Const
from ailment.statement import ConditionalJump, Call, Assignment

from ..sim_type import RustSimTypeOption
from ..mixins.cfg_transformation_mixin import CFGTransformationMixin
from ..mixins.dfa_mixin import DFAMixin
from ..mixins.srda_mixin import SRDAMixin
from ..mixins.cfa_mixin import CFAMixin
from ... import SIM_LIBRARIES
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass

UNWRAP_FAILED_FUNCTIONS = ("core::result::unwrap_failed", "core::option::unwrap_failed")
UNWRAP_FUNCTIONS = {
    "core::result::unwrap_failed": "core::result::unwrap",
    "core::option::unwrap_failed": "core::option::unwrap",
}


l = logging.getLogger(name=__name__)


class UnwrapSimplifierState:
    def __init__(
        self, conditional_jump_block, unwrap_failed_block, ownership_move_block, cmp_expr, unwrap_failed_func_name
    ):
        self.conditional_jump_block = conditional_jump_block
        self.unwrap_failed_block = unwrap_failed_block
        self.ownership_move_block = ownership_move_block
        self.cmp_expr = cmp_expr
        self.unwrap_failed_func_name = unwrap_failed_func_name

        self.err_or_none_discriminant = self._decide_err_or_none_discriminant()

        self.replacement = None
        self.stmt_to_replace = (None, None, None)
        self.stmts_to_remove = defaultdict(list)

    def _decide_err_or_none_discriminant(self):
        jump: ConditionalJump = self.conditional_jump_block.statements[-1]
        if isinstance(jump.condition.operands[1], Const):
            op = jump.condition.op
            if (
                op == "CmpEQ"
                and isinstance(jump.true_target, Const)
                and (jump.true_target.value, jump.true_target_idx)
                == (
                    self.unwrap_failed_block.addr,
                    self.unwrap_failed_block.idx,
                )
            ):
                return jump.condition.operands[1].value
            elif (
                op == "CmpNE"
                and isinstance(jump.false_target, Const)
                and (jump.false_target.value, jump.false_target_idx)
                == (
                    self.unwrap_failed_block.addr,
                    self.unwrap_failed_block.idx,
                )
            ):
                return jump.condition.operands[1].value
        return None


class UnwrapSimplifier(OptimizationPass, CFAMixin, SRDAMixin, DFAMixin, CFGTransformationMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Simplify unwrap-like operations"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        CFAMixin.__init__(self, self._graph, self.project)
        SRDAMixin.__init__(self, func, self._graph, self.project)
        DFAMixin.__init__(self)
        CFGTransformationMixin.__init__(self, self._graph)
        self.librust = SIM_LIBRARIES["librust"]
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _extract_expr_from_condition(self, cond: BinaryOp):
        for op in cond.operands:
            if isinstance(op, VirtualVariable):
                return op
        return None

    def simplify(self, state: UnwrapSimplifierState):
        if isinstance(state.cmp_expr, VirtualVariable) and state.cmp_expr.was_reg:
            call = self.get_terminal_vvar_value(state.cmp_expr)
            if isinstance(call, Call):
                dst_vvar, src_vvar, offset, stmt_to_remove = self.find_reg_ptr_to_reg_data_flow(
                    state.ownership_move_block, state.cmp_expr
                )
                if dst_vvar:
                    last_stmt = self.last_stmt(state.ownership_move_block)
                    unwrap_func_name = UNWRAP_FUNCTIONS[state.unwrap_failed_func_name]
                    replacement = Call(
                        idx=last_stmt.idx,
                        target=unwrap_func_name,
                        prototype=self.librust.get_prototype(unwrap_func_name).with_arch(self.project.arch),
                        args=[src_vvar],
                        ret_expr=None,
                        **last_stmt.tags,
                    )
                    replacement.bits = dst_vvar.bits
                    state.replacement = Assignment(None, dst_vvar, replacement, **last_stmt.tags)
                    state.stmt_to_replace = (state.ownership_move_block, stmt_to_remove, state.replacement)
        if state.replacement:
            # Simplification succeeded
            block, old_stmt, new_stmt = state.stmt_to_replace
            stmt_idx = block.statements.index(old_stmt)
            block.statements[stmt_idx] = new_stmt
            for block, stmts in state.stmts_to_remove:
                for stmt in stmts:
                    block.statements.remove(stmt)
            self.remove_block(state.unwrap_failed_block)

    def _analyze(self, cache=None):
        for block in list(self._graph.nodes):
            if (unwrap_failed_func_name := self.match_call(block, UNWRAP_FAILED_FUNCTIONS)) and self.num_predecessors(
                block
            ) == 1:
                pred = self.get_one_predecessor(block)
                last_stmt = self.last_stmt(pred)
                if (
                    isinstance(last_stmt, ConditionalJump)
                    and isinstance(last_stmt.condition, BinaryOp)
                    and self.num_successors(pred) == 2
                ):
                    expr = self._extract_expr_from_condition(last_stmt.condition)
                    successors = [succ for succ in self._graph.successors(pred) if succ.addr != block.addr]
                    if len(successors) == 1:
                        succ = successors[0]
                        state = UnwrapSimplifierState(
                            unwrap_failed_block=block,
                            conditional_jump_block=pred,
                            ownership_move_block=succ,
                            cmp_expr=expr,
                            unwrap_failed_func_name=unwrap_failed_func_name,
                        )
                        self.simplify(state)

        self.out_graph = self._graph
