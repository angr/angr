from ailment import Block, Const
from ailment.statement import Call

from angr.analyses.decompiler.optimization_passes.optimization_pass import (
    OptimizationPassStage,
    SequenceOptimizationPass,
)
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structuring.structurer_nodes import ConditionNode, SequenceNode, LoopNode, CodeNode
from angr.rust.utils.ail_util import get_terminal_call
from angr.rust.utils.library import normalize

DECONSTRUCTION_FUNCTIONS = ("__rust_dealloc", "close", "core::ptr::drop_in_place", "core::ops::drop::Drop::drop")


class DropWalker(SequenceWalker):
    def __init__(self, context: "DropSimplifier"):
        super().__init__()
        self.context = context

    def match_call(self, block_or_stmt, func_list):
        stmt = block_or_stmt
        if isinstance(stmt, Block):
            stmt = get_terminal_call(block_or_stmt)
        if isinstance(stmt, Call) and isinstance(stmt.target, str):
            name = normalize(stmt.target, monopolize=True, use_trait_name=True)
            return name in func_list
        if isinstance(stmt, Call) and isinstance(stmt.target, Const) and stmt.target.value in self.context.kb.functions:
            func = self.context.kb.functions[stmt.target.value]
            name = normalize(func.name, monopolize=True, use_trait_name=True)
            return name in func_list
        return False

    def _match_conditional_drop(self, node: ConditionNode):
        if isinstance(node.true_node, Block) and node.false_node is None:
            if self.match_call(node.true_node, DECONSTRUCTION_FUNCTIONS):
                return True
            # Treat unresolved indirect call as drop call too
            # FIXME
            call = get_terminal_call(node.true_node)
            if call and not isinstance(call.target, Const):
                return True
        return False

    def _match_for_loop_drop(self, node: ConditionNode):
        if isinstance(node.true_node, SequenceNode) and node.false_node is None:
            loop_node = node.true_node.nodes[-1]
            # FIXME: This should be a for loop but right now angr can't recover it
            if isinstance(loop_node, LoopNode) and loop_node.sort == "do-while":
                cond_node = loop_node.sequence_node.nodes[-1]
                if isinstance(cond_node, ConditionNode):
                    return self._match_conditional_drop(cond_node)
        return False

    def _handle_Sequence(self, seq_node: SequenceNode, **kwargs):
        nodes_to_remove = set()
        for node in seq_node.nodes:
            if isinstance(node, ConditionNode):
                if self._match_conditional_drop(node):
                    nodes_to_remove.add(node)
                elif self._match_for_loop_drop(node):
                    nodes_to_remove.add(node)
        for node in nodes_to_remove:
            seq_node.remove_node(node)
        return super()._handle_Sequence(seq_node, **kwargs)


class DropSimplifier(SequenceOptimizationPass):
    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_STRUCTURING
    NAME = "Simplify drop operations"

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        return self.project.is_rust_binary, None

    def _analyze(self, cache=None):
        DropWalker(self).walk(self.seq)
        self.out_seq = self.seq
