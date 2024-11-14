from typing import Optional

from ailment import BinaryOp
from ailment.expression import BasePointerOffset, Const, Load, StackBaseOffset
from ailment.statement import ConditionalJump, Call, Store

from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPassStage, OptimizationPass
from angr.rust.ailment.expression import Let
from angr.rust.optimization_passes.base import SSAVariableHelper
from angr.rust.mixins.dfa_mixin import DFAHelper
from angr.rust.mixins.cfa_mixin import CFAMixin
from angr.rust.sim_type import RustSimEnum, EnumVariant
from angr.rust.utils.srda_util import SRDAUtil


class EnumPatternMatchSimplifier(OptimizationPass, CFAMixin, DFAHelper, SSAVariableHelper):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify enum pattern match"

    def __init__(self, func, **kwargs):
        OptimizationPass.__init__(self, func, **kwargs)
        CFAMixin.__init__(self, self._graph)
        DFAHelper.__init__(self)
        SSAVariableHelper.__init__(self, self)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _inverse_variant(self, enum_type, discriminant) -> Optional[EnumVariant]:
        if enum_type.num_variants() == 2:
            for variant in enum_type.variants:
                if variant.discriminant != discriminant:
                    return variant
        return None

    def _swap_jump_targets(self, jump: ConditionalJump):
        true_target, true_target_idx = jump.true_target, jump.true_target_idx
        jump.true_target = jump.false_target
        jump.true_target_idx = jump.false_target_idx
        jump.false_target = true_target
        jump.false_target_idx = true_target_idx

    def _find_associated_data_definitions(self, jump, variant: EnumVariant, enum_vvar):
        defs = []
        if isinstance(jump.true_target, Const):
            block_addr = jump.true_target.value
            if (block_addr, jump.true_target_idx) in self.blocks_by_addr_and_idx:
                block = self.blocks_by_addr_and_idx[(block_addr, jump.true_target_idx)]
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
                        replacement = Store(
                            idx=None,
                            addr=addr,
                            data=data,
                            size=data.size,
                            endness=self.project.arch.memory_endness,
                            **sorted(stmts, key=lambda s: block.statements.index(s))[-1].tags,
                        )
                        replacement.tags["hidden"] = True
                        self.replace_stmt(block, stmts, replacement)
                        defs.append(replacement)
                    else:
                        defs.append(None)
                    src_offset += ty_size
        return defs

    def _analyze(self, cache=None):
        srda_util = SRDAUtil.from_function(self.project, self._func, self._graph)
        for block in self._graph.nodes:
            if isinstance(last_stmt := self.last_stmt(block), ConditionalJump):
                cond = last_stmt.condition
                if (
                    isinstance(cond, BinaryOp)
                    and (cond.op == "CmpEQ" or cond.op == "CmpNE")
                    and isinstance(cond.operands[0], Load)
                    and isinstance(cond.operands[0].addr, BasePointerOffset)
                    and isinstance(cond.operands[1], Const)
                ):
                    vvar = srda_util.get_stack_vvar_by_insn(cond.operands[0].addr.offset, last_stmt.ins_addr, block.idx)
                    value = srda_util.srda_view.get_vvar_value(vvar) if vvar else None
                    if (
                        isinstance(value, Call)
                        and value.prototype
                        and isinstance(value.prototype.returnty, RustSimEnum)
                    ):
                        enum_type = value.prototype.returnty
                        discriminant = cond.operands[1].value
                        if cond.op == "CmpEQ":
                            variant = enum_type.get_variant(discriminant)
                            if variant:
                                if not variant.has_associated_data and (
                                    inverse_variant := self._inverse_variant(enum_type, discriminant)
                                ):
                                    variant = inverse_variant
                                    self._swap_jump_targets(last_stmt)
                                defs = self._find_associated_data_definitions(last_stmt, variant, vvar)
                                let_expr = Let(None, variant, defs, vvar)
                                last_stmt.condition = let_expr
                                import ipdb

                                ipdb.set_trace()
