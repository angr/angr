from collections import OrderedDict

import angr.ailment as ailment
from angr.ailment.expression import VirtualVariable, Load
from angr.ailment.statement import Label, Assignment, Call, Return
from angr.analyses.decompiler.structuring.structurer_nodes import ConditionNode

from angr.rust.utils.ail import unwrap_stack_vvar_reference
from angr.rust.mixins import DFAMixin
from angr.rust.optimization_passes.pre_pattern_match_simplifier import PrePatternMatchSimplifier
from angr.analyses.decompiler.optimization_passes.optimization_pass import (
    OptimizationPassStage,
    SequenceOptimizationPass,
)
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.rust.sim_type import EnumVariant, RustSimTypeOption, RustSimTypeResult
from angr.rust.structuring.structurer_nodes import PatternMatchNode, IfLetNode


class PatternMatchWalker(SequenceWalker, DFAMixin):
    def __init__(self, var_manager, graph):
        super().__init__()
        self.var_manager = var_manager
        self.graph = graph

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
        # if node.addr == 0x416C09:
        #     import ipdb
        #

        #     ipdb.set_trace()
        # TODO: Support the case when scrutinee.was_combo_reg
        if not scrutinee.was_stack:
            return (None,) * len(variant.fields)
        block = self._find_first_block(node)
        if block:
            src_offset_to_stmt = {}
            for stmt in block.statements:
                if (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.dst, VirtualVariable)
                    and (stmt.dst.was_stack or stmt.dst.was_reg)
                ):
                    src_vvar = None
                    if isinstance(stmt.src, Load):
                        src_vvar = unwrap_stack_vvar_reference(stmt.src.addr)
                    elif isinstance(stmt.src, VirtualVariable):
                        src_vvar = stmt.src
                    if (
                        isinstance(src_vvar, VirtualVariable)
                        and src_vvar.was_stack
                        and src_vvar.stack_offset not in src_offset_to_stmt
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
        leftover,
    ):
        true_move_stmts = self._collect_move_stmts(scrutinee, true_variant, true_node)
        false_move_stmts = self._collect_move_stmts(scrutinee, false_variant, false_node)
        for stmt in true_move_stmts + false_move_stmts:
            if stmt:
                stmt.tags["hidden"] = True
        if leftover:
            true_node = ConditionNode(addr, None, leftover, true_node, None)
        arms = OrderedDict(
            [
                ((true_variant, true_move_stmts), true_node),
                ((false_variant, false_move_stmts), false_node),
            ]
        )
        result = PatternMatchNode(scrutinee, arms, None, addr)
        return result

    def _build_if_let(self, true_node, true_variant, scrutinee, addr, leftover):
        true_move_stmts = self._collect_move_stmts(scrutinee, true_variant, true_node)
        for stmt in true_move_stmts:
            if stmt:
                stmt.tags["hidden"] = True
        pattern = (true_variant, true_move_stmts)
        if leftover:
            true_node = ConditionNode(addr, None, leftover, true_node, None)
        result = IfLetNode(pattern, scrutinee, true_node, None, addr)
        return result

    def _is_simple_return(self, node):
        if isinstance(node, ailment.Block):
            last_stmt = self._find_first_non_label_stmt(node)
            if isinstance(last_stmt, Return):
                return True
        return False

    def _try_build_if_let(self, body_node, variant, scrutinee, addr, leftover, **kwargs):
        """Helper to build an IfLetNode and handle it. Returns the new node or None."""
        if_let = self._build_if_let(body_node, variant, scrutinee, addr, leftover)
        if if_let:
            new_node = super()._handle_IfLet(if_let, **kwargs)
            return new_node or if_let
        return None

    def _try_build_pattern_match(
        self, true_node, false_node, true_variant, false_variant, scrutinee, addr, leftover, **kwargs
    ):
        """Helper to build a PatternMatchNode and handle it. Returns the new node or None."""
        pattern_match = self._build_pattern_match(
            true_node, false_node, true_variant, false_variant, scrutinee, addr, leftover
        )
        if pattern_match:
            new_node = super()._handle_PatternMatch(pattern_match, **kwargs)
            return new_node or pattern_match
        return None

    def _get_enum_type(self, scrutinee: VirtualVariable):
        """Get the enum type from scrutinee's tags or variable manager."""
        enum_ty = scrutinee.tags.get("type", None)
        if enum_ty is None:
            enum_ty = self.var_manager.get_variable_type(scrutinee.variable)
        if isinstance(enum_ty, (RustSimTypeOption, RustSimTypeResult)):
            return enum_ty
        return None

    def _handle_Condition(self, node, **kwargs):
        scrutinee, discriminant, cmp_op, leftover = PrePatternMatchSimplifier.extract_scrutinee_and_discriminant(
            node.condition
        )

        # Early return if basic preconditions are not met
        if not node.true_node or scrutinee is None or discriminant is None:
            return super()._handle_Condition(node, **kwargs)

        # Handle VirtualVariable scrutinee with Option/Result types
        if isinstance(scrutinee, VirtualVariable):
            enum_ty = self._get_enum_type(scrutinee)
            if enum_ty is not None:
                result = self._handle_enum_condition(node, scrutinee, enum_ty, discriminant, cmp_op, leftover, **kwargs)
                if result is not None:
                    return result

        # TODO: Handle Call scrutinee case
        # elif isinstance(scrutinee, Call):
        #     pass

        return super()._handle_Condition(node, **kwargs)

    def _handle_enum_condition(self, node, scrutinee, enum_ty, discriminant, cmp_op, leftover, **kwargs):
        """Handle condition nodes where the scrutinee is an Option or Result type."""
        true_node = node.true_node
        false_node = node.false_node

        true_variant = enum_ty.get_variant(discriminant)
        false_variant = PrePatternMatchSimplifier.inverse_variant(enum_ty, discriminant)

        # Swap variants if comparison is "not equal"
        if cmp_op == "CmpNE":
            true_variant, false_variant = false_variant, true_variant

        # Case 1: Both variants exist and we have a false node - can build PatternMatch or IfLet
        if true_variant and false_variant and false_node:
            # If false branch is a simple return, build IfLet for the true branch
            if self._is_simple_return(false_node):
                return self._try_build_if_let(true_node, true_variant, scrutinee, node.addr, leftover, **kwargs)
            # If true branch is a simple return, build IfLet for the false branch
            if self._is_simple_return(true_node):
                return self._try_build_if_let(false_node, false_variant, scrutinee, node.addr, leftover, **kwargs)
            # Otherwise, build a full PatternMatch with both arms
            return self._try_build_pattern_match(
                true_node, false_node, true_variant, false_variant, scrutinee, node.addr, leftover, **kwargs
            )

        # Case 2: Only true variant exists (no false node) - build IfLet
        if true_variant:
            return self._try_build_if_let(true_node, true_variant, scrutinee, node.addr, leftover, **kwargs)

        return None


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
        walker = PatternMatchWalker(self._variable_kb.variables.get_function_manager(self._func.addr), self._graph)
        walker.walk(self.seq)
        self.out_seq = self.seq
