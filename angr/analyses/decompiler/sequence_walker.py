# pylint:disable=unused-argument,useless-return,no-self-use
from __future__ import annotations

from collections import OrderedDict
from inspect import isgeneratorfunction

from angr import ailment
from angr.errors import UnsupportedNodeTypeError
from angr.rust.structuring.structurer_nodes import IfLetNode, PatternMatchNode

from .structurer_nodes import (
    CascadingConditionNode,
    CodeNode,
    ConditionalBreakNode,
    ConditionNode,
    IncompleteSwitchCaseNode,
    LoopNode,
    MultiNode,
    SequenceNode,
    SwitchCaseNode,
)


class SequenceWalker:
    """
    Walks a SequenceNode and all its nodes.
    """

    # A subclass that replaces _handle keeps the recursive walk, because only that walk passes every node through
    # _handle. Set this to False on a subclass whose _handle only adds node types this class does not walk itself,
    # such as AIL expressions and statements: those already reach it, and its children stay on the stack.
    HANDLE_SEES_EVERY_NODE = True

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
            PatternMatchNode: self._handle_PatternMatch,
            IfLetNode: self._handle_IfLet,
            IncompleteSwitchCaseNode: self._handle_IncompleteSwitchCase,
            LoopNode: self._handle_Loop,
            MultiNode: self._handle_MultiNode,
            ConditionalBreakNode: self._handle_ConditionalBreak,
            ailment.Block: self._handle_Noop,
        }

        self._handlers = default_handlers
        if handlers:
            self._handlers.update(handlers)

        self._walk_children_through_handle = (
            type(self)._handle is not SequenceWalker._handle and self.HANDLE_SEES_EVERY_NODE
        )

        # A handler that is a generator yields the children it wants walked, and _drive runs it, and the generators
        # of everything it reaches, on one stack, so the depth of the tree costs no interpreter frames. Ours are
        # generators through the _walk_ method beside each one; a caller can pass its own. A plain handler is called
        # as before and recurses through _handle for its children.
        self._walkers = {
            node_cls: handler for node_cls, handler in self._handlers.items() if isgeneratorfunction(handler)
        }
        self._walkers.update(
            (node_cls, walker)
            for node_cls, default, walker in (
                (CodeNode, SequenceWalker._handle_Code, self._walk_Code),
                (SequenceNode, SequenceWalker._handle_Sequence, self._walk_Sequence),
                (ConditionNode, SequenceWalker._handle_Condition, self._walk_Condition),
                (
                    CascadingConditionNode,
                    SequenceWalker._handle_CascadingCondition,
                    self._walk_CascadingCondition,
                ),
                (SwitchCaseNode, SequenceWalker._handle_SwitchCase, self._walk_SwitchCase),
                (PatternMatchNode, SequenceWalker._handle_PatternMatch, self._walk_PatternMatch),
                (IfLetNode, SequenceWalker._handle_IfLet, self._walk_IfLet),
                (
                    IncompleteSwitchCaseNode,
                    SequenceWalker._handle_IncompleteSwitchCase,
                    self._walk_IncompleteSwitchCase,
                ),
                (LoopNode, SequenceWalker._handle_Loop, self._walk_Loop),
                (MultiNode, SequenceWalker._handle_MultiNode, self._walk_MultiNode),
            )
            if getattr(self._handlers.get(node_cls), "__func__", None) is default
        )

    def walk(self, sequence):
        return self._handle(sequence)

    #
    # Handlers
    #

    def _handle(self, node, **kwargs):
        walker = self._walkers.get(node.__class__, None)
        if walker is not None:
            return self._drive(walker(node, **kwargs))
        handler = self._handlers.get(node.__class__, None)
        if handler is not None:
            return handler(node, **kwargs)
        if self._exception_on_unsupported:
            raise UnsupportedNodeTypeError(f"Node type {type(node)} is not supported yet.")
        return None

    def _drive(self, walk):
        """
        Run one walker generator, and the generators of every node it reaches, on a single stack. A generator yields
        the child it wants walked and the keyword arguments to walk it with, and is resumed with that child's
        replacement.
        """
        stack = [walk]
        replacement = None
        while stack:
            try:
                child, child_kwargs = stack[-1].send(replacement)
            except StopIteration as walked:
                stack.pop()
                replacement = walked.value
                continue
            walker = None if self._walk_children_through_handle else self._walkers.get(child.__class__, None)
            if walker is None:
                replacement = self._handle(child, **child_kwargs)
            else:
                stack.append(walker(child, **child_kwargs))
                replacement = None
        return replacement

    def _handle_Code(self, node: CodeNode, **kwargs):
        return self._drive(self._walk_Code(node, **kwargs))

    def _walk_Code(self, node: CodeNode, **kwargs):
        new_inner_node = yield node.node, {"parent": node, "index": 0}
        if new_inner_node is None:
            return None
        return CodeNode(new_inner_node, node.reaching_condition)

    def _handle_Sequence(self, node, **kwargs):
        return self._drive(self._walk_Sequence(node, **kwargs))

    def _walk_Sequence(self, node, **kwargs):
        nodes_copy = list(node.nodes)
        changed = False

        if self._force_forward_scan:
            for i, node_ in enumerate(nodes_copy):
                new_node = yield node_, {"parent": node, "index": i}
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
                new_node = yield node_, {"parent": node, "index": i}
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
        return self._drive(self._walk_MultiNode(node, **kwargs))

    def _walk_MultiNode(self, node, **kwargs):
        changed = False
        nodes = node.nodes if self._update_seqnode_in_place else list(node.nodes)

        if self._force_forward_scan:
            for i, node_ in enumerate(nodes):
                new_node = yield node_, {"parent": node, "index": i}
                if new_node is not None:
                    changed = True
                    nodes[i] = new_node
        else:
            i = len(nodes) - 1
            while i > -1:
                node_ = nodes[i]
                new_node = yield node_, {"parent": node, "index": i}
                if new_node is not None:
                    changed = True
                    nodes[i] = new_node
                i -= 1
        if not changed:
            return None
        if self._update_seqnode_in_place:
            return node
        return MultiNode(nodes, addr=node.addr, idx=node.idx)

    def _handle_SwitchCase(self, node, **kwargs):
        return self._drive(self._walk_SwitchCase(node, **kwargs))

    def _walk_SwitchCase(self, node, **kwargs):
        yield node.switch_expr, {"parent": node, "label": "switch_expr"}

        changed = False
        new_cases = OrderedDict()
        for idx in list(node.cases.keys()):
            case = node.cases[idx]
            new_case = yield case, {"parent": node, "index": idx, "label": "case"}
            if new_case is not None:
                changed = True
                new_cases[idx] = new_case
            else:
                new_cases[idx] = case

        new_default_node = None
        if node.default_node is not None:
            new_default_node = yield node.default_node, {"parent": node, "index": 0, "label": "default"}
            if new_default_node is not None:
                changed = True
            else:
                new_default_node = node.default_node

        if changed:
            return SwitchCaseNode(node.switch_expr, new_cases, new_default_node, addr=node.addr)

        return None

    def _handle_PatternMatch(self, node: PatternMatchNode, **kwargs):
        return self._drive(self._walk_PatternMatch(node, **kwargs))

    def _walk_PatternMatch(self, node: PatternMatchNode, **kwargs):
        yield node.scrutinee, {"parent": node, "label": "scrutinee"}

        changed = False
        new_arms = OrderedDict()
        for key, arm in node.arms.items():
            new_arm = yield arm, {"parent": node, "label": "arm"}
            if new_arm is not None:
                changed = True
                new_arms[key] = new_arm
            else:
                new_arms[key] = arm

        new_default_node = None
        if node.default_node is not None:
            new_default_node = yield node.default_node, {"parent": node, "index": 0, "label": "default"}
            if new_default_node is not None:
                changed = True
            else:
                new_default_node = node.default_node

        if changed:
            return PatternMatchNode(node.scrutinee, new_arms, new_default_node, addr=node.addr)

        return None

    def _handle_IfLet(self, node: IfLetNode, **kwargs):
        return self._drive(self._walk_IfLet(node, **kwargs))

    def _walk_IfLet(self, node: IfLetNode, **kwargs):
        changed = False

        new_scrutinee = yield node.scrutinee, {"parent": node, "label": "scrutinee"}
        if new_scrutinee is not None:
            changed = True
        else:
            new_scrutinee = node.scrutinee

        variant, bound_vars = node.pattern
        new_bound_vars = []
        for bound_var in bound_vars:
            new_bound_var = yield bound_var, {"parent": node, "label": "bound_var"}
            new_bound_vars.append(new_bound_var if new_bound_var is not None else bound_var)
            if new_bound_var is not None:
                changed = True
        new_pattern = (variant, new_bound_vars)

        new_true_node = yield node.true_node, {"parent": node, "label": "true_node"}
        if new_true_node is not None:
            changed = True
        else:
            new_true_node = node.true_node

        new_false_node = None
        if node.false_node is not None:
            new_false_node = yield node.false_node, {"parent": node, "label": "false_node"}
            if new_false_node is not None:
                changed = True
            else:
                new_false_node = node.false_node

        if changed:
            return IfLetNode(new_pattern, new_scrutinee, new_true_node, new_false_node, addr=node.addr)

        return None

    def _handle_IncompleteSwitchCase(self, node: IncompleteSwitchCaseNode, **kwargs):
        return self._drive(self._walk_IncompleteSwitchCase(node, **kwargs))

    def _walk_IncompleteSwitchCase(self, node: IncompleteSwitchCaseNode, **kwargs):
        changed = False
        new_cases = []
        for idx, case in enumerate(node.cases):
            new_case = yield case, {"parent": node, "index": idx, "label": "case"}
            if new_case is not None:
                changed = True
                new_cases.append(new_case)
            else:
                new_cases.append(case)

        new_head = None
        if node.head is not None:
            new_head = yield node.head, {"parent": node, "index": 0, "label": "default"}
            if new_head is not None:
                changed = True
            else:
                new_head = node.head

        if changed:
            return IncompleteSwitchCaseNode(node.addr, new_head, new_cases)

        return None

    def _handle_Loop(self, node: LoopNode, **kwargs) -> LoopNode | None:
        return self._drive(self._walk_Loop(node, **kwargs))

    def _walk_Loop(self, node: LoopNode, **kwargs):
        new_initializer = (yield node.initializer, {}) if node.initializer is not None else None
        new_iterator = (yield node.iterator, {}) if node.iterator is not None else None
        new_condition = (
            (yield node.condition, {"parent": node, "label": "condition"}) if node.condition is not None else None
        )

        # note that initializer and iterator are both statements, so they can return empty tuples
        # TODO: Handle the case where multiple statements are returned
        if new_initializer == ():
            new_initializer = None
        if new_iterator == ():
            new_iterator = None

        seq_node = yield node.sequence_node, {"parent": node, "label": "body", "index": 0}
        if seq_node is not None or new_initializer is not None or new_iterator is not None or new_condition is not None:
            return LoopNode(
                node.sort,
                new_condition if new_condition is not None else node.condition,
                seq_node if seq_node is not None else node.sequence_node,
                addr=node.addr,
                continue_addr=node.continue_addr,
                initializer=new_initializer if new_initializer is not None else node.initializer,
                iterator=new_iterator if new_iterator is not None else node.iterator,
            )
        return None

    def _handle_Condition(self, node, **kwargs):
        return self._drive(self._walk_Condition(node, **kwargs))

    def _walk_Condition(self, node, **kwargs):
        new_true_node = (yield node.true_node, {"parent": node, "index": 0}) if node.true_node is not None else None

        new_false_node = (yield node.false_node, {"parent": node, "index": 1}) if node.false_node is not None else None

        new_condition = (
            (yield node.condition, {"parent": node, "label": "condition"}) if node.condition is not None else None
        )

        if new_true_node is None and new_false_node is None and new_condition is None:
            return None

        return ConditionNode(
            node.addr,
            node.reaching_condition,
            node.condition if new_condition is None else new_condition,
            node.true_node if new_true_node is None else new_true_node,
            false_node=node.false_node if new_false_node is None else new_false_node,
        )

    def _handle_CascadingCondition(self, node: CascadingConditionNode, **kwargs):
        return self._drive(self._walk_CascadingCondition(node, **kwargs))

    def _walk_CascadingCondition(self, node: CascadingConditionNode, **kwargs):
        cond_nodes_changed = False
        new_condition_and_nodes = []
        for index, (cond, child_node) in enumerate(node.condition_and_nodes):
            new_child = yield child_node, {"parent": node, "index": index}
            if new_child is not None:
                cond_nodes_changed = True
                new_condition_and_nodes.append((cond, new_child))
            else:
                new_condition_and_nodes.append((cond, child_node))

        new_else = None
        if node.else_node is not None:
            new_else = yield node.else_node, {"parent": node, "index": -1}

        if cond_nodes_changed or new_else is not None:
            return CascadingConditionNode(
                node.addr,
                new_condition_and_nodes if cond_nodes_changed else node.condition_and_nodes,
                else_node=new_else if new_else is not None else node.else_node,
            )
        return None

    def _handle_ConditionalBreak(self, node: ConditionalBreakNode, **kwargs):
        return None

    def _handle_Noop(self, *args, **kwargs):
        return None
