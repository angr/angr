from collections import defaultdict

from angr.ailment.expression import Const, BinaryOp, VirtualVariable, Load, StringLiteral
from angr.ailment.statement import Assignment, Call, ConditionalJump
from angr.rust.utils.ail import unwrap_stack_vvar_reference
from angr.rust.sim_type import RustSimTypeResult, RustSimTypeOption
from angr.rust.mixins import CFAMixin, SRDAMixin, DFAMixin, CFGTransformationMixin, SSAVariableMixin
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass


RESULT_UNWRAP_FAILED_FUNCTION = "core::result::unwrap_failed"
OPTION_UNWRAP_FAILED_FUNCTION = "core::option::unwrap_failed"
UNWRAP_FAILED_FUNCTIONS = (RESULT_UNWRAP_FAILED_FUNCTION, OPTION_UNWRAP_FAILED_FUNCTION)
UNWRAP_FUNCTIONS = {
    "core::result::unwrap_failed": "core::result::unwrap",
    "core::option::unwrap_failed": "core::option::unwrap",
}


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


class UnwrapOutliner(OptimizationPass, CFAMixin, SRDAMixin, DFAMixin, CFGTransformationMixin, SSAVariableMixin):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Outline unwrap function calls"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        CFAMixin.__init__(self, self._graph, self.project)
        SRDAMixin.__init__(self, func, self._graph, self.project)
        DFAMixin.__init__(self)
        CFGTransformationMixin.__init__(self, self._graph)
        SSAVariableMixin.__init__(self, self)
        self.librust = self.project.kb.librust
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def simplify(self, state: UnwrapSimplifierState):
        import ipdb

        ipdb.set_trace()
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

    def _extract_vvar_from_cond(self, cond: BinaryOp):
        op0 = cond.operands[0]
        if isinstance(op0, Load):
            return unwrap_stack_vvar_reference(op0.addr)
        return None

    def _find_pred_and_succ(self, unwrap_failed_block):
        if self.num_predecessors(unwrap_failed_block) == 1:
            pred = self.get_one_predecessor(unwrap_failed_block)
            succs = [succ for succ in self._graph.successors(pred) if succ.addr != unwrap_failed_block.addr]
            if len(succs) == 1:
                return pred, succs[0]
        return None, None

    def _try_outline(self, unwrap_failed_block, unwrap_failed_func_name):
        pred, succ = self._find_pred_and_succ(unwrap_failed_block)
        if pred and succ:
            last_stmt = self.last_stmt(pred)
            if (
                isinstance(last_stmt, ConditionalJump)
                and isinstance(last_stmt.condition, BinaryOp)
                and ((cmp_vvar := self._extract_vvar_from_cond(last_stmt.condition)) and cmp_vvar.was_stack)
            ):
                call = self.get_terminal_vvar_value(cmp_vvar)
                if isinstance(call, Call) and isinstance(
                    call.prototype.returnty, (RustSimTypeResult, RustSimTypeOption)
                ):
                    enum_ty = call.prototype.returnty
                    variant = None
                    if (
                        isinstance(enum_ty, RustSimTypeResult)
                        and unwrap_failed_func_name == RESULT_UNWRAP_FAILED_FUNCTION
                    ):
                        variant = enum_ty.get_variant_by_name("Ok")
                    elif (
                        isinstance(enum_ty, RustSimTypeOption)
                        and unwrap_failed_func_name == OPTION_UNWRAP_FAILED_FUNCTION
                    ):
                        variant = enum_ty.get_variant_by_name("Some")
                    if variant:
                        offset = cmp_vvar.stack_offset + variant.first_field_offset
                        size = variant.size - variant.first_field_offset
                        dst_vvar = self.new_stack_vvar(offset, size * 8, cmp_vvar.tags)
                        unwrap_func_name = UNWRAP_FUNCTIONS[unwrap_failed_func_name]
                        first_block, second_block = self.split_block(pred, last_stmt)
                        assert self.remove_block(unwrap_failed_block)
                        replacement = Call(
                            idx=last_stmt.idx,
                            target=StringLiteral(None, unwrap_func_name, self.project.arch.bits),
                            prototype=self.librust.get_prototype(unwrap_func_name)
                            .with_arch(self.project.arch)
                            .normalize(),
                            args=[cmp_vvar],
                            ret_expr=None,
                            **last_stmt.tags,
                        )
                        replacement.prototype.returnty = variant.type.with_arch(self.project.arch)
                        replacement.bits = dst_vvar.bits
                        second_block.statements[-1] = Assignment(None, dst_vvar, replacement, **last_stmt.tags)

    def _analyze(self, cache=None):
        for block in list(self._graph.nodes):
            # if block.addr == 0x40B2DE:
            #     import ipdb
            #
            #     ipdb.set_trace()
            if block in self._graph and (unwrap_failed_func_name := self.match_call(block, UNWRAP_FAILED_FUNCTIONS)):
                self._try_outline(block, unwrap_failed_func_name)

        self.out_graph = self._graph
