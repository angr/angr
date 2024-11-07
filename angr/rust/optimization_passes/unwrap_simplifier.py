import logging
from enum import Enum
from typing import Optional

from ailment.expression import BinaryOp, Load, Expression, Const, VirtualVariable, VirtualVariableCategory
from ailment.statement import Call, ConditionalJump, Assignment

from .base import TransformationPass
from ..sim_type import RustSimTypeOption
from ..utils.library import normalize
from ... import SIM_LIBRARIES
from ...analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage
from ...analyses.s_reaching_definitions import SRDAView
from ...knowledge_plugins.key_definitions.constants import OP_BEFORE

UNWRAP_FUNCTIONS = ("core::result::unwrap_failed",)
UNWRAP_FAILED_FUNCTIONS = ("core::result::unwrap_failed", "core::option::unwrap_failed")


l = logging.getLogger(name=__name__)


class OptionEnum(Enum):
    SOME = 0
    NONE = 1

    @staticmethod
    def from_discriminant(discriminant):
        if discriminant == 0:
            return OptionEnum.SOME
        return OptionEnum.NONE


class UnwrapSimplifier(TransformationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify unwrap-like operations"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.librust = SIM_LIBRARIES["librust"]
        self.srda = self.project.analyses.SReachingDefinitions(subject=self._func, func_graph=self._graph)
        self.srda_view = SRDAView(self.srda.model)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _extract_expr_from_condition(self, cond: BinaryOp):
        for op in cond.operands:
            if isinstance(op, Load):
                return op.addr
        return None

    def _get_stack_vvar_by_insn(
        self, stack_offset: int, addr: int, block_idx: int | None = None
    ) -> VirtualVariable | None:
        vvars = set()

        def _predicate(stmt) -> bool:
            if (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_stack
                and stmt.dst.stack_offset == stack_offset
            ):
                vvars.add(stmt.dst)
                return True
            return False

        self.srda_view._get_vvar_by_insn(addr, OP_BEFORE, _predicate, block_idx=block_idx)

        assert len(vvars) <= 1
        return next(iter(vvars), None)

    def _simplify_non_returning_calls(self):
        removed = set()
        for block in self._graph.nodes:
            if (
                block.statements
                and isinstance(block.statements[-1], ConditionalJump)
                and self.num_successors(block) == 2
            ):
                should_update = False
                cond = block.statements[-1].condition
                block0, block1 = self.get_two_successors(block)
                if self.match_call(block0, UNWRAP_FUNCTIONS):
                    self.replace_jump_target(block, block0, block1)
                    removed.add(block0)
                    should_update = True
                elif self.match_call(block1, UNWRAP_FUNCTIONS):
                    self.replace_jump_target(block, block1, block0)
                    removed.add(block1)
                    should_update = True
                if should_update:
                    expr = self._extract_expr_from_condition(cond)
                    if expr:
                        last_stmt = block.statements[-1]
                        new_stmt = Call(
                            idx=last_stmt.idx,
                            target="core::result::unwrap",
                            prototype=self.librust.get_prototype("core::result::unwrap").with_arch(self.project.arch),
                            args=[expr],
                            ret_expr=None,
                            **last_stmt.tags,
                        )
                        block.statements[-1] = new_stmt

        for block in removed:
            self._graph.remove_node(block)

    def _extract_expr_and_enum_type(self, cond) -> (Expression | None, OptionEnum | None):
        if isinstance(cond, BinaryOp):
            op0 = cond.operands[0]
            op1 = cond.operands[1]
            if isinstance(op0, Load) and isinstance(op1, Const):
                return op0.addr, OptionEnum.from_discriminant(op1.value)
        return None

    def _simplify_unwrap(self):
        blocks_to_remove = set()
        jump_to_replace = set()
        for block in self._graph.nodes:
            if (
                block.statements
                and isinstance(block.statements[-1], ConditionalJump)
                and self.num_successors(block) == 2
            ):
                jump: ConditionalJump = block.statements[-1]
                expr, enum_type = self._extract_expr_and_enum_type(jump.condition)
                vvar = self._get_stack_vvar_by_insn(expr.offset, jump.ins_addr, block.idx)
                vvar_value = self.srda_view.get_vvar_value(vvar)
                if (
                    isinstance(vvar_value, Call)
                    and vvar_value.prototype
                    and isinstance(vvar_value.prototype.returnty, RustSimTypeOption)
                ):
                    option_ty = vvar_value.prototype.returnty
                    if isinstance(jump.true_target, Const) and isinstance(jump.false_target, Const):
                        failed_addr, failed_idx = jump.true_target.value, jump.true_target_idx
                        successful_addr, successful_idx = jump.false_target.value, jump.false_target_idx
                        if enum_type == OptionEnum.SOME:
                            failed_addr, failed_idx = jump.false_target.value, jump.false_target_idx
                            successful_addr, successful_idx = jump.true_target.value, jump.true_target_idx
                        failed_block = self.blocks_by_addr_and_idx.get((failed_addr, failed_idx), None)
                        successful_block = self.blocks_by_addr_and_idx.get((successful_addr, successful_idx), None)
                        if failed_block and successful_block and self.match_call(failed_block, UNWRAP_FAILED_FUNCTIONS):
                            call = Call(
                                idx=jump.idx,
                                target="core::result::unwrap",
                                prototype=self.librust.get_prototype("core::result::unwrap").with_arch(
                                    self.project.arch
                                ),
                                args=[],
                                ret_expr=None,
                                **jump.tags,
                            )
                            call.tags["receiver"] = vvar
                            call.bits = option_ty.data_type.size
                            call.prototype.returnty = option_ty.data_type
                            vvar_id = self.vvar_id_start
                            self.vvar_id_start += 1
                            vvar_bits = option_ty.data_type.size
                            dst_vvar = VirtualVariable(
                                None,
                                vvar_id,
                                vvar_bits,
                                VirtualVariableCategory.STACK,
                                oident=expr.offset,
                                **jump.tags,
                            )
                            assignment = Assignment(None, dst_vvar, call, **jump.tags)
                            jump_to_replace.add((block, successful_block, assignment))
                            blocks_to_remove.add(failed_block)

        for block in blocks_to_remove:
            self._remove_block(block)
        for block, target_block, new_terminal in jump_to_replace:
            self.replace_jump_target(block, None, target_block)
            block.statements[-1] = new_terminal

    def _analyze(self, cache=None):
        if normalize(self._func.name) == "oxdizer_test::test_unwrap_simplifier::test_option_unwrap":
            self._simplify_unwrap()
        # if normalize(self._func.name) == "uu_fmt::uumain":
        #     removed = set()
        #     for block in self._graph.nodes:
        #         if (
        #             block.statements
        #             and isinstance(block.statements[-1], ConditionalJump)
        #             and self.num_successors(block) == 2
        #         ):
        #             jump: ConditionalJump = block.statements[-1]
        #             if isinstance(jump.condition, BinaryOp) and isinstance(jump.condition.operands[1], Const):
        #                 value = jump.condition.operands[1].value
        #                 if value == 0x8000000000000000 or value == 0x8000000000000001:
        #                     op = jump.condition.op
        #                     queue = []
        #                     try:
        #                         block = None
        #                         if op == "CmpEQ" and isinstance(jump.true_target, Const):
        #                             block = self.blocks_by_addr_and_idx[(jump.true_target.value, jump.true_target_idx)]
        #                         elif op == "CmpNE" and isinstance(jump.false_target, Const):
        #                             block = self.blocks_by_addr_and_idx[
        #                                 (jump.false_target.value, jump.false_target_idx)
        #                             ]
        #                         if block:
        #                             queue.append(block)
        #                     except:
        #                         import ipdb
        #
        #                         ipdb.set_trace()
        #                     while len(queue):
        #                         block = queue.pop(0)
        #                         if block not in removed:
        #                             removed.add(block)
        #                             queue.extend(self._graph.successors(block))
        #     import ipdb
        #
        #     ipdb.set_trace()

        self.out_graph = self._graph
