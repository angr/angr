# pylint:disable=unused-argument,arguments-differ
from __future__ import annotations
from collections import defaultdict

import ailment

from ..condition_processor import ConditionProcessor, EmptyBlockNotice
from ..sequence_walker import SequenceWalker
from ..structuring.structurer_nodes import (
    SequenceNode,
    CodeNode,
    MultiNode,
    LoopNode,
    ConditionNode,
    ContinueNode,
    CascadingConditionNode,
)
from ..utils import is_statement_terminating, has_nonlabel_nonphi_statements


class LoopSimplifier(SequenceWalker):
    """
    Simplifies loops.
    """

    def __init__(self, node, functions):
        handlers = {
            SequenceNode: self._handle_sequencenode,
            CodeNode: self._handle_codenode,
            MultiNode: self._handle_multinode,
            LoopNode: self._handle_loopnode,
            ConditionNode: self._handle_conditionnode,
            CascadingConditionNode: self._handle_cascadingconditionnode,
            ailment.Block: self._handle_block,
        }

        super().__init__(handlers)
        self.functions = functions
        self.continue_preludes: dict[LoopNode, list[ailment.Block]] = defaultdict(list)
        self.walk(node)

    @staticmethod
    def _control_transferring_statement(stmt: ailment.Stmt.Statement) -> bool:
        return isinstance(
            stmt, (ailment.Stmt.Call, ailment.Stmt.Return, ailment.Stmt.Jump, ailment.Stmt.ConditionalJump)
        )

    def _handle_sequencenode(self, node, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs):
        for n0, n1, n2 in zip(node.nodes, node.nodes[1:] + [successor], [predecessor] + node.nodes[:-1]):
            self._handle(n0, predecessor=n2, successor=n1, loop=loop, loop_successor=loop_successor)

    def _handle_codenode(self, node, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs):
        self._handle(node.node, predecessor=predecessor, successor=successor, loop=loop, loop_successor=loop_successor)

    def _handle_conditionnode(self, node, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs):
        if node.true_node is not None:
            self._handle(
                node.true_node, predecessor=predecessor, successor=successor, loop=loop, loop_successor=loop_successor
            )
        if node.false_node is not None:
            self._handle(
                node.false_node, predecessor=predecessor, successor=successor, loop=loop, loop_successor=loop_successor
            )

    def _handle_cascadingconditionnode(
        self, node: CascadingConditionNode, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs
    ):
        for _, child_node in node.condition_and_nodes:
            self._handle(
                child_node, predecessor=predecessor, successor=successor, loop=loop, loop_successor=loop_successor
            )
        if node.else_node is not None:
            self._handle(
                node.else_node, predecessor=predecessor, successor=successor, loop=loop, loop_successor=loop_successor
            )

    def _handle_loopnode(
        self, node: LoopNode, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs
    ):
        self._handle(
            node.sequence_node, predecessor=predecessor, successor=successor, loop=node, loop_successor=successor
        )

        # find for-loop iterators
        if (
            (
                node.sort == "while"
                and self.continue_preludes[node]
                and (
                    (node.condition is not None and not isinstance(node.condition, ailment.Expr.Const))
                    or len(self.continue_preludes[node]) > 1
                )
            )
            and (
                all(block.statements for block in self.continue_preludes[node])
                and all(
                    not self._control_transferring_statement(block.statements[-1])
                    for block in self.continue_preludes[node]
                )
                and all(
                    block.statements[-1] == self.continue_preludes[node][0].statements[-1]
                    for block in self.continue_preludes[node]
                )
            )
            and (
                all(has_nonlabel_nonphi_statements(block) for block in self.continue_preludes[node])
                and all(
                    not self._control_transferring_statement(block.statements[-1])
                    for block in self.continue_preludes[node]
                )
                and all(
                    block.statements[-1] == self.continue_preludes[node][0].statements[-1]
                    for block in self.continue_preludes[node]
                )
            )
        ):
            node.sort = "for"
            node.iterator = self.continue_preludes[node][0].statements[-1]
            for block in self.continue_preludes[node]:
                block.statements = block.statements[:-1]

        # find for-loop initializers
        if isinstance(predecessor, MultiNode):
            predecessor = predecessor.nodes[-1]
        if (
            node.sort == "for"
            and isinstance(predecessor, ailment.Block)
            and predecessor.statements
            and isinstance(predecessor.statements[-1], (ailment.Stmt.Assignment, ailment.Stmt.Store))
        ):
            node.initializer = predecessor.statements[-1]
            predecessor.statements = predecessor.statements[:-1]

    def _handle_multinode(self, node, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs):
        for n0, n1, n2 in zip(node.nodes, node.nodes[1:] + [successor], [predecessor] + node.nodes[:-1]):
            self._handle(n0, predecessor=n2, successor=n1, loop=loop, loop_successor=loop_successor)

    def _handle_block(
        self, block, predecessor=None, successor=None, loop=None, loop_successor=None, **kwargs
    ):  # pylint:disable=no-self-use
        if isinstance(successor, ContinueNode) or successor is loop_successor:
            # ensure this block is not returning or exiting
            try:
                last_stmt = ConditionProcessor.get_last_statement(block)
            except EmptyBlockNotice:
                last_stmt = None
            if last_stmt is not None and is_statement_terminating(last_stmt, self.functions):
                return
            self.continue_preludes[loop].append(block)
