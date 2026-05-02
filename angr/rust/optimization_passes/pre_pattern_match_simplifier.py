from __future__ import annotations
import logging
from typing import Any


from angr.ailment import BinaryOp
from angr.ailment.expression import Call, Load, Const, Convert, UnaryOp, VirtualVariable, RustEnum
from angr.ailment.statement import ConditionalJump, Return
from angr.analyses.decompiler.utils import copy_graph
from angr.rust.mixins import DFAMixin
from angr.rust.sim_type import EnumVariant, RustSimTypeOption, RustSimTypeResult
from angr.rust.utils.ail import unwrap_stack_vvar_reference, unwrap_combo_reg_vvar_reference
from angr.analyses.decompiler.structuring import SAILRStructurer, DreamStructurer
from angr.analyses.decompiler.optimization_passes.return_duplicator_base import ReturnDuplicatorBase
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage

_l = logging.getLogger(name=__name__)


class PrePatternMatchSimplifier(OptimizationPass, ReturnDuplicatorBase, DFAMixin):
    """
    Duplicate return blocks for identified pattern matches to form if-else structures.
    For example the following code,
        ```
        if (...){
            ...
        } else {
            v6 = std::fs::File::open(a1, a2);
            if !v6 as i32 {
                ...
            }
        }
        return Err(struct8 {
            field_0: v11
        });
        ```
    should be converted to
        ```
        v6 = std::fs::File::open(a1, a2);
        if v6 as i32 {
            return Err(struct8 {
                field_0: v11
            });
        } else {
            ...
        }
        ```
    for recovering pattern match constructs in later stage
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Duplicate return blocks to prepare for pattern match simplification"
    DESCRIPTION = __doc__
    STRUCTURING = [SAILRStructurer.NAME, DreamStructurer.NAME]

    def __init__(
        self,
        func,
        manager,
        # settings
        *,
        vvar_id_start: int,
        max_calls_in_regions: int = 2,
        minimize_copies_for_regions: bool = True,
        scratch: dict[str, Any] | None = None,
        **kwargs,
    ):
        OptimizationPass.__init__(self, func, manager, vvar_id_start=vvar_id_start, scratch=scratch, **kwargs)
        ReturnDuplicatorBase.__init__(
            self,
            func,
            manager,
            max_calls_in_regions=max_calls_in_regions,
            minimize_copies_for_regions=minimize_copies_for_regions,
            vvar_id_start=vvar_id_start,
            scratch=scratch,
        )
        DFAMixin.__init__(self, self._graph)

        self.analyze()

    def _check(self):
        return bool(self._func.endpoints) and self.project.is_rust_binary, None

    def _should_duplicate_dst(self, src, dst, graph, dst_is_const_ret=False):
        return (
            dst.statements
            and isinstance(dst.statements[-1], Return)
            and dst.statements[-1].ret_exprs
            and isinstance(dst.statements[-1].ret_exprs[0], RustEnum)
        )
        # pred = next(graph.predecessors(src), None)
        # if pred and pred.statements and isinstance(pred.statements[-1], ConditionalJump):
        #     jump = pred.statements[-1]
        #     return "scrutinee" in jump.condition.tags or dst_is_const_ret
        # return dst_is_const_ret

    @staticmethod
    def _strip_conversions(expr):
        while isinstance(expr, Convert):
            expr = expr.operand
        return expr

    @staticmethod
    def _const_value(expr):
        expr = PrePatternMatchSimplifier._strip_conversions(expr)
        if isinstance(expr, Const):
            return expr.value
        return None

    @staticmethod
    def _is_zero(expr):
        return PrePatternMatchSimplifier._const_value(expr) == 0

    @staticmethod
    def _same_expr(expr0, expr1):
        try:
            return expr0.likes(expr1)
        except AttributeError:
            return expr0 == expr1

    @staticmethod
    def _unwrap_zero_xor(expr):
        expr = PrePatternMatchSimplifier._strip_conversions(expr)
        if isinstance(expr, BinaryOp) and expr.op == "Xor":
            op0, op1 = expr.operands
            if PrePatternMatchSimplifier._is_zero(op0):
                return PrePatternMatchSimplifier._strip_conversions(op1)
            if PrePatternMatchSimplifier._is_zero(op1):
                return PrePatternMatchSimplifier._strip_conversions(op0)
        return expr

    @staticmethod
    def _unwrap_neg(expr):
        expr = PrePatternMatchSimplifier._unwrap_zero_xor(expr)
        if isinstance(expr, UnaryOp) and expr.op == "Neg":
            return PrePatternMatchSimplifier._strip_conversions(expr.operand)
        if isinstance(expr, BinaryOp) and expr.op == "Sub" and PrePatternMatchSimplifier._is_zero(expr.operands[0]):
            return PrePatternMatchSimplifier._strip_conversions(expr.operands[1])
        return None

    @staticmethod
    def _match_scrutinee(expr):
        expr = PrePatternMatchSimplifier._strip_conversions(expr)
        if isinstance(expr, Load):
            return unwrap_stack_vvar_reference(expr.addr) or unwrap_combo_reg_vvar_reference(expr.addr)
        if isinstance(expr, (VirtualVariable, Call)):
            return expr
        return None

    @staticmethod
    def _extract_sign_bit_discriminant(condition):
        condition = PrePatternMatchSimplifier._strip_conversions(condition)
        if not isinstance(condition, BinaryOp) or condition.op not in {"Shr", "Sar"}:
            return None, None

        value, shift = condition.operands
        shift_value = PrePatternMatchSimplifier._const_value(shift)
        if not isinstance(shift_value, int) or shift_value < 0:
            return None, None

        value = PrePatternMatchSimplifier._strip_conversions(value)
        if not isinstance(value, BinaryOp) or value.op != "And":
            return None, None

        lhs = PrePatternMatchSimplifier._unwrap_zero_xor(value.operands[0])
        rhs = PrePatternMatchSimplifier._unwrap_zero_xor(value.operands[1])
        lhs_neg_base = PrePatternMatchSimplifier._unwrap_neg(lhs)
        rhs_neg_base = PrePatternMatchSimplifier._unwrap_neg(rhs)
        if lhs_neg_base is not None and PrePatternMatchSimplifier._same_expr(lhs_neg_base, rhs):
            scrutinee_expr = rhs
        elif rhs_neg_base is not None and PrePatternMatchSimplifier._same_expr(lhs, rhs_neg_base):
            scrutinee_expr = lhs
        else:
            return None, None

        bits = getattr(scrutinee_expr, "bits", None) or shift_value + 1
        if shift_value != bits - 1:
            return None, None

        scrutinee = PrePatternMatchSimplifier._match_scrutinee(scrutinee_expr)
        if scrutinee is None:
            return None, None

        discriminant = -(1 << shift_value)
        return scrutinee, discriminant

    @staticmethod
    def extract_scrutinee_and_discriminant(condition):
        leftover = None
        if isinstance(condition, BinaryOp) and condition.op == "LogicalAnd":
            leftover = condition.operands[1]
            condition = condition.operands[0]

        scrutinee, discriminant = PrePatternMatchSimplifier._extract_sign_bit_discriminant(condition)
        if scrutinee is not None and discriminant is not None:
            return scrutinee, discriminant, "CmpEQ", leftover

        scrutinee, discriminant, cmp_op = None, None, None
        if isinstance(condition, BinaryOp) and condition.op in ("CmpEQ", "CmpNE"):
            op0, op1 = condition.operands
            cmp_op = condition.op
            # CmpEQ((Load(addr=(Reference vvar_247{stack -216}), size=1, endness=Iend_LE) & 0x1<8>), 0x0<8>)
            if (
                isinstance(op1, Const)
                and op1.value == 0
                and isinstance(op0, BinaryOp)
                and op0.op == "And"
                and isinstance(op0.operands[1], Const)
            ):
                op1 = op1.copy()
                op1.value = op0.operands[1].value
                op0 = op0.operands[0]
                cmp_op = "CmpNE" if cmp_op == "CmpEQ" else "CmpEQ"
            scrutinee = PrePatternMatchSimplifier._match_scrutinee(op0)
            discriminant = PrePatternMatchSimplifier._const_value(op1)
        if scrutinee is not None and discriminant is not None and cmp_op:
            return scrutinee, discriminant, cmp_op, leftover
        return None, None, None, None

    @staticmethod
    def inverse_variant(enum_type, discriminant) -> EnumVariant | None:
        if enum_type.num_variants() == 2:
            for variant in enum_type.variants:
                if variant.discriminant != discriminant:
                    return variant
        return None

    def _group_move_stmts_for_block(self, block, scrutinee: VirtualVariable, variant: EnumVariant):
        stack_defs = self.collect_stack_defs_at(block)
        src_to_dst_and_stack_def = {}
        for dst, stack_def in stack_defs.items():
            src_vvar = None
            if isinstance(stack_def.data, Load):
                src_vvar = unwrap_stack_vvar_reference(stack_def.data.addr)
            elif isinstance(stack_def.data, VirtualVariable):
                src_vvar = stack_def.data
            if isinstance(src_vvar, VirtualVariable) and src_vvar.was_stack:
                src_to_dst_and_stack_def[src_vvar.stack_offset] = (dst, stack_def)
        expected_src_offset = scrutinee.stack_offset + variant.first_field_offset
        expected_dst_offset = None
        expected_size = variant.size - variant.first_field_offset
        cur_size = 0
        move_stmts = []
        while expected_src_offset in src_to_dst_and_stack_def and cur_size < expected_size:
            dst, stack_def = src_to_dst_and_stack_def[expected_src_offset]
            if expected_dst_offset is not None and expected_dst_offset != dst:
                break
            expected_dst_offset = dst + stack_def.data.size
            expected_src_offset += stack_def.data.size
            cur_size += stack_def.data.size
            move_stmts.append(stack_def.stmt)
        if cur_size == expected_size:
            move_stmt = None
            if len(move_stmts) >= 2:
                pass
                # dst_offset = move_stmts[0].dst.stack_offset
                # TODO: Group move stmts
            elif len(move_stmts) == 1:
                move_stmt = move_stmts[0]
            if move_stmt:
                self.project.kb.type_hints.add_type_hint(move_stmt.dst, variant.fields[0][0], self._func.addr)

    def _group_move_stmts(self):
        for block in self._graph.nodes:
            if block.statements and (
                (jmp := block.statements[-1])
                and isinstance(jmp, ConditionalJump)
                and isinstance(jmp.true_target, Const)
                and isinstance(jmp.false_target, Const)
            ):
                scrutinee, discriminant, cmp_op, _ = self.extract_scrutinee_and_discriminant(jmp.condition)
                if scrutinee and (
                    (enum_ty := scrutinee.tags.get("type", None))
                    and isinstance(enum_ty, (RustSimTypeOption, RustSimTypeResult))
                ):
                    true_block = self.blocks_by_addr_and_idx.get((jmp.true_target.value_int, jmp.true_target_idx), None)
                    false_block = self.blocks_by_addr_and_idx.get(
                        (jmp.false_target.value_int, jmp.false_target_idx), None
                    )
                    true_variant = enum_ty.get_variant(discriminant)
                    false_variant = self.inverse_variant(enum_ty, discriminant)
                    if cmp_op == "CmpNE":
                        true_variant, false_variant = false_variant, true_variant
                    if isinstance(scrutinee, VirtualVariable):
                        if true_block and true_variant:
                            self._group_move_stmts_for_block(true_block, scrutinee, true_variant)
                        if false_block and false_variant:
                            self._group_move_stmts_for_block(false_block, scrutinee, false_variant)

    def _analyze(self, cache=None):
        graph_copy = copy_graph(self._graph)
        # since we run before the RegionIdentification pass in the decompiler, we need to collect it early here
        self._ri = self._recover_regions(graph_copy)
        if self._analyze_core(graph_copy):
            self.out_graph = self._simplify_graph(graph_copy)
        self._group_move_stmts()
