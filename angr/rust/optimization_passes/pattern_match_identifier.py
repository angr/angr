from typing import Optional

from ailment import BinaryOp, Assignment
from ailment.expression import Const, Load, StackBaseOffset, VirtualVariable
from ailment.statement import ConditionalJump, Call

from angr.rust.utils.ail_util import unwrap_stack_vvar_reference
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.mixins.srda_mixin import SRDAMixin
from angr.rust.optimization_passes.base import SSAVariableHelper
from angr.rust.mixins.dfa_mixin import DFAMixin
from angr.rust.mixins.cfa_mixin import CFAMixin
from angr.rust.sim_type import RustSimEnum, EnumVariant


class PatternMatchIdentifier(OptimizationPass, CFAMixin, DFAMixin, SRDAMixin, SSAVariableHelper):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.RUST_SPECIFIC_SIMPLIFICATION
    NAME = "Simplify enum pattern match"

    def __init__(self, func, **kwargs):
        OptimizationPass.__init__(self, func, **kwargs)
        CFAMixin.__init__(self, self._graph)
        DFAMixin.__init__(self)
        SRDAMixin.__init__(self, self._func, self._graph, self.project)
        SSAVariableHelper.__init__(self, self)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _swap_jump_targets(self, jump: ConditionalJump):
        true_target, true_target_idx = jump.true_target, jump.true_target_idx
        jump.true_target = jump.false_target
        jump.true_target_idx = jump.false_target_idx
        jump.false_target = true_target
        jump.false_target_idx = true_target_idx

    def _inverse_variant(self, enum_type, discriminant) -> Optional[EnumVariant]:
        if enum_type.num_variants() == 2:
            for variant in enum_type.variants:
                if variant.discriminant != discriminant:
                    return variant
        return None

    def _find_associated_data_moves(self, block, variant: EnumVariant, enum_vvar):
        """
        Find the statements that move the associated data out of enum instance
        Unify the move statements and return a list of unified Assignment statements
        """
        if enum_vvar.was_reg:
            return ()
        moves = []
        src_offset = enum_vvar.stack_offset + variant.first_field_offset
        for ty in variant.associated_data.keys():
            ty_size = ty.size // self.project.arch.byte_width
            stmts, dst_offset = self.find_stack_data_flow(block, src_offset, ty_size)
            if stmts:
                dst = self.new_stack_vvar(dst_offset, ty.size, {})
                src = Load(
                    None,
                    StackBaseOffset(None, self.project.arch.bits, src_offset),
                    ty_size,
                    endness=self.project.arch.memory_endness,
                )
                move_stmt = Assignment(
                    None, dst, src, **sorted(stmts, key=lambda s: block.statements.index(s))[-1].tags
                )
                self.replace_stmt(block, stmts, move_stmt)
                moves.append(move_stmt)
            else:
                # If we can not find stack to stack data flow, fall back to finding stack to register data flow
                stmt, dst_vvar = self.find_stack_to_reg_data_flow(block, src_offset, ty_size)
                moves.append(stmt)
            src_offset += ty_size
        return tuple(moves)

    def _analyze(self, cache=None):
        for block in self._graph.nodes:
            if isinstance(last_stmt := self.last_stmt(block), ConditionalJump):
                cond = last_stmt.condition
                if (
                    isinstance(last_stmt.true_target, Const)
                    and isinstance(last_stmt.false_target, Const)
                    and isinstance(cond, BinaryOp)
                    and (cond.op == "CmpEQ" or cond.op == "CmpNE")
                    and isinstance(cond.operands[1], Const)
                ):
                    vvar, value = None, None
                    cond_op0 = cond.operands[0]
                    if isinstance(cond_op0, VirtualVariable):
                        vvar = cond_op0
                        cond_op0 = self.get_terminal_vvar_value(cond_op0)
                    if isinstance(cond_op0, Load) and (vvar := unwrap_stack_vvar_reference(cond_op0.addr)):
                        value = self.get_terminal_vvar_value(vvar) if vvar else None
                    elif isinstance(cond_op0, Call):
                        value = cond_op0
                    if (
                        isinstance(value, Call)
                        and value.prototype
                        and isinstance(value.prototype.returnty, RustSimEnum)
                        and value.prototype.returnty.num_variants() == 2
                    ):
                        enum_type = value.prototype.returnty
                        discriminant = cond.operands[1].value
                        true_variant, false_variant = None, None
                        true_block = self.blocks_by_addr_and_idx.get(
                            (last_stmt.true_target.value, last_stmt.true_target_idx), None
                        )
                        false_block = self.blocks_by_addr_and_idx.get(
                            (last_stmt.false_target.value, last_stmt.false_target_idx), None
                        )
                        # Find the variants associated with true branch and false branch
                        if cond.op == "CmpEQ":
                            true_variant = enum_type.get_variant(discriminant)
                            false_variant = self._inverse_variant(enum_type, discriminant)
                        if true_block and false_block and true_variant and false_variant:
                            true_moves = self._find_associated_data_moves(true_block, true_variant, vvar)
                            false_moves = self._find_associated_data_moves(false_block, false_variant, vvar)
                            match_arms = {
                                true_block.addr: (true_variant, true_moves),
                                false_block.addr: (false_variant, false_moves),
                            }
                            cond.tags["call"] = value
                            cond.tags["scrutinee"] = vvar
                            cond.tags["match_arms"] = match_arms
