# pylint:disable=unused-argument,useless-return
from __future__ import annotations
from collections import OrderedDict

import ailment

from ...errors import UnsupportedNodeTypeError
from .structuring.structurer_nodes import (
    MultiNode,
    CodeNode,
    SequenceNode,
    ConditionNode,
    SwitchCaseNode,
    LoopNode,
    CascadingConditionNode,
    ConditionalBreakNode,
    IncompleteSwitchCaseNode,
)


class SequenceWalker:
    """
    Walks a SequenceNode and all its nodes, recursively.
    """

    def __init__(
        self,
        handlers=None,
        exception_on_unsupported=False,
        update_seqnode_in_place=True,
        force_forward_scan: bool = False,
    ):
        self._update_seqnode_in_place = update_seqnode_in_place
        self._exception_on_unsupported = exception_on_unsupported
        self._force_forward_scan = force_forward_scan

        if self._force_forward_scan and self._update_seqnode_in_place:
            raise TypeError("force_forward_scan and update_seqnode_in_place cannot be enabled at the same time")

        default_handlers = {
            # Structurer nodes
            CodeNode: self._handle_Code,
            SequenceNode: self._handle_Sequence,
            ConditionNode: self._handle_Condition,
            CascadingConditionNode: self._handle_CascadingCondition,
            SwitchCaseNode: self._handle_SwitchCase,
            IncompleteSwitchCaseNode: self._handle_IncompleteSwitchCase,
            LoopNode: self._handle_Loop,
            MultiNode: self._handle_MultiNode,
            ConditionalBreakNode: self._handle_ConditionalBreak,
            ailment.Block: self._handle_Noop,
        }

        self._handlers = default_handlers
        if handlers:
            self._handlers.update(handlers)

    def walk(self, sequence):
        return self._handle(sequence)

    #
    # Handlers
    #

    def _handle(self, node, **kwargs):
        handler = self._handlers.get(node.__class__, None)
        if handler is not None:
            return handler(node, **kwargs)
        if self._exception_on_unsupported:
            raise UnsupportedNodeTypeError(f"Node type {type(node)} is not supported yet.")
        return None

    def _handle_Code(self, node: CodeNode, **kwargs):
        new_inner_node = self._handle(node.node, parent=node, index=0)
        if new_inner_node is None:
            return None
        return CodeNode(new_inner_node, node.reaching_condition)

    def _handle_Sequence(self, node, **kwargs):
        nodes_copy = list(node.nodes)
        changed = False

        if self._force_forward_scan:
            for i, node_ in enumerate(nodes_copy):
                new_node = self._handle(node_, parent=node, index=i)
                if new_node is not None:
                    changed = True
                    nodes_copy[i] = new_node
        else:
            # we iterate backwards because users of this function may invoke insert_node() directly to insert nodes
            # to the parent node, either before the current node or after the current node. iterating backwards allows
            # us to ensure `i` always points to the right index in node.nodes, even after custom insertions.
            i = len(nodes_copy) - 1
            while i > -1:
                node_ = nodes_copy[i]
                new_node = self._handle(node_, parent=node, index=i)
                if new_node is not None:
                    changed = True
                    if self._update_seqnode_in_place:
                        node.nodes[i] = new_node
                    else:
                        nodes_copy[i] = new_node
                i -= 1

        if not changed:
            return None
        if self._update_seqnode_in_place:
            return node
        return SequenceNode(node.addr, nodes=nodes_copy)

    def _handle_MultiNode(self, node, **kwargs):
        changed = False
        nodes_copy = list(node.nodes)

        if self._force_forward_scan:
            for i, node_ in enumerate(nodes_copy):
                new_node = self._handle(node_, parent=node, index=i)
                if new_node is not None:
                    changed = True
                    node.nodes[i] = new_node
        else:
            i = len(nodes_copy) - 1
            while i > -1:
                node_ = nodes_copy[i]
                new_node = self._handle(node_, parent=node, index=i)
                if new_node is not None:
                    changed = True
                    node.nodes[i] = new_node
                i -= 1
        return None if not changed else node

    def _handle_SwitchCase(self, node, **kwargs):
        self._handle(node.switch_expr, parent=node, label="switch_expr")

        changed = False
        new_cases = OrderedDict()
        for idx in list(node.cases.keys()):
            case = node.cases[idx]
            new_case = self._handle(case, parent=node, index=idx, label="case")
            if new_case is not None:
                changed = True
                new_cases[idx] = new_case
            else:
                new_cases[idx] = case

        new_default_node = None
        if node.default_node is not None:
            new_default_node = self._handle(node.default_node, parent=node, index=0, label="default")
            if new_default_node is not None:
                changed = True
            else:
                new_default_node = node.default_node

        if changed:
            return SwitchCaseNode(node.switch_expr, new_cases, new_default_node, addr=node.addr)

        return None

    def _handle_IncompleteSwitchCase(self, node: IncompleteSwitchCaseNode, **kwargs):
        changed = False
        new_cases = []
        for idx, case in enumerate(node.cases):
            new_case = self._handle(case, parent=node, index=idx, label="case")
            if new_case is not None:
                changed = True
                new_cases.append(new_case)
            else:
                new_cases.append(case)

        new_head = None
        if node.head is not None:
            new_head = self._handle(node.head, parent=node, index=0, label="default")
            if new_head is not None:
                changed = True
            else:
                new_head = node.head

        if changed:
            return IncompleteSwitchCaseNode(node.addr, new_head, new_cases)

        return None

    def _handle_Loop(self, node: LoopNode, **kwargs):
        if node.initializer is not None:
            self._handle(node.initializer)
        if node.iterator is not None:
            self._handle(node.iterator)
        if node.condition is not None:
            self._handle(node.condition, parent=node, label="condition")
        seq_node = self._handle(node.sequence_node, parent=node, label="body", index=0)
        if seq_node is not None:
            return LoopNode(
                node.sort,
                node.condition,
                seq_node,
                addr=node.addr,
                continue_addr=node.continue_addr,
                initializer=node.initializer,
                iterator=node.iterator,
            )
        return None

    def _handle_Condition(self, node, **kwargs):
        new_true_node = self._handle(node.true_node, parent=node, index=0) if node.true_node is not None else None

        new_false_node = self._handle(node.false_node, parent=node, index=1) if node.false_node is not None else None

        if new_true_node is None and new_false_node is None:
            return None

        return ConditionNode(
            node.addr,
            node.reaching_condition,
            node.condition,
            node.true_node if new_true_node is None else new_true_node,
            false_node=node.false_node if new_false_node is None else new_false_node,
        )

    def _handle_CascadingCondition(self, node: CascadingConditionNode, **kwargs):
        for index, (_, child_node) in enumerate(node.condition_and_nodes):
            self._handle(child_node, parent=node, index=index)
        if node.else_node is not None:
            self._handle(node.else_node, parent=node, index=-1)
        return

    def _handle_ConditionalBreak(self, node: ConditionalBreakNode, **kwargs):  # pylint:disable=no-self-use
        return None

    def _handle_Noop(self, *args, **kwargs):  # pylint:disable=no-self-use
        return None
