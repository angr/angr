from typing import Optional

from ailment import BinaryOp
from ailment.expression import BasePointerOffset, Const, Load, StackBaseOffset
from ailment.statement import ConditionalJump, Call, Store

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.mixins.srda_mixin import SRDAMixin
from angr.rust.optimization_passes.base import SSAVariableHelper
from angr.rust.mixins.dfa_mixin import DFAMixin
from angr.rust.mixins.cfa_mixin import CFAMixin
from angr.rust.sim_type import RustSimEnum, EnumVariant


class PatternMatchIdentifier(OptimizationPass, CFAMixin, DFAMixin, SRDAMixin, SSAVariableHelper):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
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
        Unify the move statements and return a list of unified Store statements
        """
        moves = []
        src_offset = enum_vvar.stack_offset + variant.data_offset
        for ty in variant.associated_data.keys():
            ty_size = ty.size // self.project.arch.byte_width
            stmts, dst_offset = self.find_stack_data_flow(block, src_offset, ty_size)
            if stmts:
                addr = StackBaseOffset(None, self.project.arch.bits, dst_offset)
                data = Load(
                    None,
                    StackBaseOffset(None, self.project.arch.bits, src_offset),
                    ty_size,
                    endness=self.project.arch.memory_endness,
                )
                move_stmt = Store(
                    idx=None,
                    addr=addr,
                    data=data,
                    size=data.size,
                    endness=self.project.arch.memory_endness,
                    **sorted(stmts, key=lambda s: block.statements.index(s))[-1].tags,
                )
                self.replace_stmt(block, stmts, move_stmt)
                moves.append(move_stmt)
            else:
                moves.append(None)
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
                    and isinstance(cond.operands[0], Load)
                    and isinstance(cond.operands[0].addr, BasePointerOffset)
                    and isinstance(cond.operands[1], Const)
                ):
                    vvar = self.get_stack_vvar_by_insn(cond.operands[0].addr.offset, last_stmt.ins_addr, block.idx)
                    value = self.get_terminal_vvar_value(vvar) if vvar else None
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
                            cond.tags["scrutinee"] = vvar
                            cond.tags["match_arms"] = match_arms
                            # if variant:
                            #     import ipdb
                            #
                            #     ipdb.set_trace()
                            #     if not variant.has_associated_data and (
                            #         inverse_variant := self._inverse_variant(enum_type, discriminant)
                            #     ):
                            #         variant = inverse_variant
                            #         self._swap_jump_targets(last_stmt)
                            #     defs = self._find_associated_data_definitions(last_stmt, variant, vvar)
                            #     let_expr = Let(None, variant, defs, vvar)
                            #     last_stmt.condition = let_expr
