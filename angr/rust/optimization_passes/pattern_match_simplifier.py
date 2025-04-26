from collections import OrderedDict
from typing import Dict, Tuple, Union

import ailment
from ailment import Statement
from ailment.expression import VirtualVariable, Load
from ailment.statement import Label, Assignment, Call

from angr.rust.utils.ail_util import unwrap_stack_vvar_reference
from angr.rust.mixins import DFAMixin
from angr.rust.optimization_passes.pre_pattern_match_simplifier import PrePatternMatchSimplifier
from angr.analyses.decompiler.optimization_passes.optimization_pass import (
    OptimizationPassStage,
    SequenceOptimizationPass,
)
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.rust.sim_type import EnumVariant, RustSimTypeOption, RustSimTypeResult
from angr.rust.structuring.structurer_nodes import PatternMatchNode


class PatternMatchWalker(SequenceWalker, DFAMixin):
    def __init__(self, var_manager):
        super().__init__()
        self.var_manager = var_manager

    @staticmethod
    def _find_first_block(node):
        class BlockFinder(SequenceWalker):

            def __init__(self):
                super().__init__(
                    handlers={ailment.Block: self._handle_Block}, force_forward_scan=True, update_seqnode_in_place=False
                )
                self.block = None

            def _handle(self, node, **kwargs):
                if self.block:
                    return None
                return super()._handle(node, **kwargs)

            def _handle_Block(self, block, **kwargs):
                self.block = block
                return None

        finder = BlockFinder()
        finder.walk(node)
        return finder.block

    @staticmethod
    def _find_first_non_label_stmt(block):
        for stmt in block.statements or []:
            if isinstance(stmt, Label):
                continue
            return stmt
        return None

    def _collect_move_stmts(self, scrutinee: VirtualVariable, variant: EnumVariant, node):
        if not scrutinee.was_stack:
            return (None,) * len(variant.fields)
        block = self._find_first_block(node)
        if block:
            src_offset_to_stmt = {}
            for stmt in block.statements:
                if (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.dst, VirtualVariable)
                    and stmt.dst.was_stack
                    and isinstance(stmt.src, Load)
                    and (
                        (src_vvar := unwrap_stack_vvar_reference(stmt.src.addr))
                        and src_vvar.was_stack
                        and src_vvar.stack_offset not in src_offset_to_stmt
                    )
                ):
                    src_offset_to_stmt[src_vvar.stack_offset] = stmt
            field_offsets = variant.field_offsets
            move_stmts = []
            for field_offset in sorted(field_offsets.keys()):
                field_ty = field_offsets[field_offset]
                field_offset += scrutinee.stack_offset
                if (
                    field_offset in src_offset_to_stmt
                    and src_offset_to_stmt[field_offset].dst.size == field_ty.size // 8
                ):
                    move_stmts.append(src_offset_to_stmt[field_offset])
                else:
                    move_stmts.append(None)
            return tuple(move_stmts)
        return (None,) * len(variant.fields)

    def _build_pattern_match(
        self,
        true_node,
        false_node,
        true_variant,
        false_variant,
        scrutinee,
        addr,
    ):
        true_move_stmts = self._collect_move_stmts(scrutinee, true_variant, true_node)
        false_move_stmts = self._collect_move_stmts(scrutinee, false_variant, false_node)
        for stmt in true_move_stmts + false_move_stmts:
            if stmt:
                stmt.tags["hidden"] = True
        arms = OrderedDict(
            [
                ((true_variant, true_move_stmts), true_node),
                ((false_variant, false_move_stmts), false_node),
            ]
        )
        result = PatternMatchNode(scrutinee, arms, None, addr)
        return result

    def _handle_Condition(self, node, **kwargs):
        scrutinee, discriminant, cmp_op = PrePatternMatchSimplifier.extract_scrutinee_and_discriminant(node.condition)
        if node.true_node and node.false_node and scrutinee is not None and discriminant is not None:
            if isinstance(scrutinee, VirtualVariable) and isinstance(
                (enum_ty := scrutinee.tags.get("type", None) or self.var_manager.get_variable_type(scrutinee.variable)),
                (RustSimTypeOption, RustSimTypeResult),
            ):
                true_node = node.true_node
                false_node = node.false_node
                true_variant = enum_ty.get_variant(discriminant)
                false_variant = PrePatternMatchSimplifier.inverse_variant(enum_ty, discriminant)
                if cmp_op == "CmpNE":
                    true_variant, false_variant = false_variant, true_variant
                if true_variant and false_variant:
                    pattern_match = self._build_pattern_match(
                        true_node, false_node, true_variant, false_variant, scrutinee, node.addr
                    )
                    if pattern_match:
                        new_node = super()._handle_PatternMatch(pattern_match, **kwargs)
                        return new_node or pattern_match
            elif isinstance(scrutinee, Call):
                pass
        return super()._handle_Condition(node, **kwargs)


class PatternMatchSimplifier(SequenceOptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_STRUCTURING
    NAME = "Recover idiomatic Rust error handling code"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self._graph = kwargs.get("graph")
        self._variable_kb = kwargs.get("variable_kb")
        self.analyze()

    def _check(self):
        return bool(self.seq.nodes), None

    def _analyze(self, cache=None):
        walker = PatternMatchWalker(self._variable_kb.variables.get_function_manager(self._func.addr))
        walker.walk(self.seq)
        self.out_seq = self.seq
