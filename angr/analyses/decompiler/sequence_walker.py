# pylint:disable=unused-argument,useless-return
import ailment

from ...errors import UnsupportedNodeTypeError
from .region_identifier import MultiNode
from .structurer_nodes import CodeNode, SequenceNode, ConditionNode, SwitchCaseNode, LoopNode


class SequenceWalker:
    """
    Walks a SequenceNode and all its nodes, recursively.
    """
    def __init__(self, handlers=None, exception_on_unsupported=False):
        self._exception_on_unsupported = exception_on_unsupported

        default_handlers = {
            # Structurer nodes
            CodeNode: self._handle_Code,
            SequenceNode: self._handle_Sequence,
            ConditionNode: self._handle_Condition,
            SwitchCaseNode: self._handle_SwitchCase,
            LoopNode: self._handle_Loop,
            MultiNode: self._handle_MultiNode,
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

    def _handle_Code(self, node, **kwargs):
        return self._handle(node.node, parent=node, index=0)

    def _handle_Sequence(self, node, **kwargs):
        i = 0
        while i < len(node.nodes):
            node_ = node.nodes[i]
            self._handle(node_, parent=node, index=i)
            i += 1
        return None

    def _handle_MultiNode(self, node, **kwargs):
        i = 0
        while i < len(node.nodes):
            node_ = node.nodes[i]
            self._handle(node_, parent=node, index=i)
            i += 1
        return None

    def _handle_SwitchCase(self, node, **kwargs):
        self._handle(node.switch_expr, parent=node, label='switch_expr')
        for idx, case in node.cases.items():
            self._handle(case, parent=node, index=idx, label='case')
        if node.default_node is not None:
            self._handle(node.default_node, parent=node, label='default')
        return None

    def _handle_Loop(self, node, **kwargs):
        return self._handle(node.sequence_node, **kwargs)

    def _handle_Condition(self, node, **kwargs):
        self._handle(node.true_node, parent=node, index=0)
        self._handle(node.false_node, parent=node, index=1)
        return None

    @staticmethod
    def _handle_Noop(*args, **kwargs):
        return None
