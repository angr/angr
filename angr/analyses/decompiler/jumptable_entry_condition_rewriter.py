from __future__ import annotations
import claripy

from .structuring.structurer_nodes import ConditionNode, CodeNode
from .sequence_walker import SequenceWalker


class JumpTableEntryConditionRewriter(SequenceWalker):
    """
    Remove artificial jump table entry conditions that ConditionProcessor introduced when dealing with jump tables.
    """

    def __init__(self, jumptable_entry_conds):
        super().__init__()
        self._jumptable_entry_conds = jumptable_entry_conds

    def _process_expr(self, expr):
        if expr in self._jumptable_entry_conds:
            return claripy.true

        new_args = []
        replaced = False
        if expr.op in {"Or", "And", "Not"}:
            for arg in expr.args:
                new_arg = self._process_expr(arg)
                if new_arg is not None:
                    replaced = True
                new_args.append(new_arg if new_arg is not None else arg)
        if replaced:
            return getattr(claripy, expr.op)(*new_args)
        return None

    def _handle_Code(self, node: CodeNode, **kwargs):
        new_node = super()._handle_Code(node, **kwargs)
        changed = False
        if new_node is not None:
            changed = True
        else:
            new_node = node

        new_cond = self._process_expr(new_node.reaching_condition) if new_node.reaching_condition is not None else None
        if new_cond is not None:
            changed = True
        else:
            new_cond = new_node.reaching_condition

        if changed:
            return CodeNode(new_node.node, new_cond)
        return None

    def _handle_Condition(self, node: ConditionNode, **kwargs):
        new_node = super()._handle_Condition(node, **kwargs)
        changed = False
        if new_node is None:
            new_node = node
        else:
            changed = True

        new_cond = self._process_expr(new_node.condition)
        if new_cond is not None:
            return ConditionNode(
                new_node.addr, node.reaching_condition, new_cond, new_node.true_node, false_node=new_node.false_node
            )

        if changed:
            return new_node
        return None
