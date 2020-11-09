# pylint:disable=unused-argument
import claripy
import ailment

from .sequence_walker import SequenceWalker
from .region_identifier import MultiNode
from .structurer_nodes import SequenceNode, CodeNode, ConditionNode, SwitchCaseNode, ConditionalBreakNode, \
    BreakNode, LoopNode
from .condition_processor import ConditionProcessor


class EmptyNodeRemover:
    """
    Rewrites a node and its children to remove empty nodes.

    The following optimizations are performed at the same time:
    - Convert if (A) { } else { ... } to if(!A) { ... } else { }
    """
    def __init__(self, node):
        self.root = node

        handlers = {
            SequenceNode: self._handle_Sequence,
            CodeNode: self._handle_Code,
            ConditionNode: self._handle_Condition,
            SwitchCaseNode: self._handle_SwitchCase,
            LoopNode: self._handle_Loop,

            MultiNode: self._handle_Default,
            BreakNode: self._handle_Default,
            ConditionalBreakNode: self._handle_Default,

            ailment.Block: self._handle_Block,
        }
        self._walker = SequenceWalker(handlers=handlers)
        r = self._walker.walk(self.root)
        if r is None:
            self.result = SequenceNode(nodes=[])
        else:
            self.result = r

    #
    # Handlers
    #

    def _handle_Sequence(self, node, **kwargs):

        new_nodes = [ ]
        for node_ in node.nodes:
            new_node = self._walker._handle(node_)
            if new_node is not None:
                if isinstance(new_node, SequenceNode):
                    new_nodes.extend(new_node.nodes)
                else:
                    new_nodes.append(new_node)

        if not new_nodes:
            return None
        return SequenceNode(nodes=new_nodes)

    def _handle_Code(self, node, **kwargs):
        inner_node = self._walker._handle(node.node)
        if inner_node is None:
            return None
        return CodeNode(inner_node, node.reaching_condition)

    def _handle_Condition(self, node, **kwargs):

        true_node = self._walker._handle(node.true_node)
        false_node = self._walker._handle(node.false_node)

        if true_node is None and false_node is None:
            # empty node
            return None
        if true_node is None and false_node is not None:
            # swap them
            return ConditionNode(node.addr,
                                 node.reaching_condition,
                                 ConditionProcessor.simplify_condition(claripy.Not(node.condition)),
                                 false_node,
                                 false_node=None)
        return ConditionNode(node.addr, node.reaching_condition, node.condition, true_node, false_node=false_node)

    def _handle_Loop(self, node, **kwargs):
        new_seq = self._walker._handle(node.sequence_node)

        if new_seq is None:
            return None

        return LoopNode(node.sort,
                        node.condition,
                        new_seq,
                        addr=node.addr
                        )

    def _handle_SwitchCase(self, node, **kwargs):

        new_cases = { }

        for idx, case in node.cases.items():
            new_case = self._walker._handle(case)
            if new_case is not None:
                new_cases[idx] = new_case

        new_default_node = self._walker._handle(node.default_node)

        if not new_cases and new_default_node is None:
            return None

        return SwitchCaseNode(node.switch_expr,
                              new_cases,
                              new_default_node,
                              addr=node.addr
                              )

    @staticmethod
    def _handle_Default(node, **kwargs):
        return node

    @staticmethod
    def _handle_Block(block, **kwargs):
        if not block.statements:
            return None
        return block
