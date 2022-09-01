# pylint:disable=unused-argument,useless-return
import ailment

from ...errors import UnsupportedNodeTypeError
from .region_identifier import MultiNode
from .structurer_nodes import CodeNode, SequenceNode, ConditionNode, SwitchCaseNode, LoopNode, CascadingConditionNode, \
    ConditionalBreakNode


class SequenceWalker:
    """
    Walks a SequenceNode and all its nodes, recursively.
    """
    def __init__(self, handlers=None, exception_on_unsupported=False, update_seqnode_in_place=True):
        self._update_seqnode_in_place = update_seqnode_in_place
        self._exception_on_unsupported = exception_on_unsupported

        default_handlers = {
            # Structurer nodes
            CodeNode: self._handle_Code,
            SequenceNode: self._handle_Sequence,
            ConditionNode: self._handle_Condition,
            CascadingConditionNode: self._handle_CascadingCondition,
            SwitchCaseNode: self._handle_SwitchCase,
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
            raise UnsupportedNodeTypeError("Node type %s is not supported yet." % type(node))
        return None

    def _handle_Code(self, node: CodeNode, **kwargs):
        new_inner_node = self._handle(node.node, parent=node, index=0)
        if new_inner_node is None:
            return None
        return CodeNode(new_inner_node, node.reaching_condition)

    def _handle_Sequence(self, node, **kwargs):
        i = 0
        nodes_copy = list(node.nodes)
        changed = False
        while i < len(nodes_copy):
            node_ = nodes_copy[i]
            new_node = self._handle(node_, parent=node, index=i)
            if new_node is not None:
                changed = True
                if self._update_seqnode_in_place:
                    node.nodes[i] = new_node
                else:
                    nodes_copy[i] = new_node
            i += 1

        if not changed:
            return None
        if self._update_seqnode_in_place:
            return node
        return SequenceNode(node.addr, nodes=nodes_copy)

    def _handle_MultiNode(self, node, **kwargs):
        i = 0
        changed = False
        nodes_copy = list(node.nodes)
        while i < len(nodes_copy):
            node_ = nodes_copy[i]
            new_node = self._handle(node_, parent=node, index=i)
            if new_node is not None:
                changed = True
                node.nodes[i] = new_node
            i += 1
        return None if not changed else node

    def _handle_SwitchCase(self, node, **kwargs):
        self._handle(node.switch_expr, parent=node, label='switch_expr')

        changed = False
        new_cases = { }
        for idx in list(node.cases.keys()):
            case = node.cases[idx]
            new_case = self._handle(case, parent=node, index=idx, label='case')
            if new_case is not None:
                changed = True
                new_cases[idx] = new_case
            else:
                new_cases[idx] = case

        new_default_node = None
        if node.default_node is not None:
            new_default_node = self._handle(node.default_node, parent=node, label='default')
            if new_default_node is not None:
                changed = True
            else:
                new_default_node = node.default_node

        if changed:
            return SwitchCaseNode(node.switch_expr, new_cases, new_default_node, addr=node.addr)

        return None

    def _handle_Loop(self, node: LoopNode, **kwargs):
        if node.initializer is not None:
            self._handle(node.initializer)
        if node.iterator is not None:
            self._handle(node.iterator)
        if node.condition is not None:
            self._handle(node.condition, parent=node, label="condition")
        seq_node = self._handle(node.sequence_node, **kwargs)
        if seq_node is not None:
            return LoopNode(node.sort, node.condition, seq_node, addr=node.addr, continue_addr=node.continue_addr,
                            initializer=node.initializer, iterator=node.iterator)
        return None

    def _handle_Condition(self, node, **kwargs):
        if node.true_node is not None:
            new_true_node = self._handle(node.true_node, parent=node, index=0)
        else:
            new_true_node = None

        if node.false_node is not None:
            new_false_node = self._handle(node.false_node, parent=node, index=1)
        else:
            new_false_node = None

        if new_true_node is None and new_false_node is None:
            return None

        return ConditionNode(node.addr, node.reaching_condition, node.condition,
                             node.true_node if new_true_node is None else new_true_node,
                             false_node=node.false_node if new_false_node is None else new_false_node)

    def _handle_CascadingCondition(self, node: CascadingConditionNode, **kwargs):
        for index, (_, child_node) in enumerate(node.condition_and_nodes):
            self._handle(child_node, parent=node, index=index)
        if node.else_node is not None:
            self._handle(node.else_node, parent=node, index=-1)
        return None

    def _handle_ConditionalBreak(self, node: ConditionalBreakNode, **kwargs):  # pylint:disable=no-self-use
        return None

    def _handle_Noop(self, *args, **kwargs):  # pylint:disable=no-self-use
        return None
