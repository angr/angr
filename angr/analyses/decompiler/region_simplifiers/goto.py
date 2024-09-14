# pylint:disable=unused-argument,arguments-differ
from __future__ import annotations
import logging

import ailment

from ..sequence_walker import SequenceWalker
from ..structuring.structurer_nodes import (
    SequenceNode,
    CodeNode,
    MultiNode,
    LoopNode,
    ConditionNode,
    CascadingConditionNode,
)
from .node_address_finder import NodeAddressFinder
from ..goto_manager import Goto


l = logging.getLogger(name=__name__)


class GotoSimplifier(SequenceWalker):
    """
    Remove unnecessary Jump statements.
    This simplifier also has the side effect of detecting Gotos that can't be reduced in the
    structuring and eventual decompilation output. Because of this, when this analysis is run,
    gotos in decompilation will be detected and stored in the kb.gotos. See the
    _handle_irreducible_goto function below.

    TODO:
    Move the recording of Gotos outside this function
    """

    def __init__(self, node, function=None, kb=None):
        handlers = {
            SequenceNode: self._handle_sequencenode,
            CodeNode: self._handle_codenode,
            MultiNode: self._handle_multinode,
            LoopNode: self._handle_loopnode,
            ConditionNode: self._handle_conditionnode,
            CascadingConditionNode: self._handle_cascadingconditionnode,
            ailment.Block: self._handle_block,
        }
        self._function = function
        self._kb = kb
        self.irreducible_gotos = set()

        super().__init__(handlers)
        self._node_addrs: set[int] = NodeAddressFinder(node).addrs

        self.walk(node)

    def _handle_sequencenode(self, node, successor=None, **kwargs):
        """

        :param SequenceNode node:
        :return:
        """

        for n0, n1 in zip(node.nodes, node.nodes[1:] + [successor]):
            self._handle(n0, successor=n1)

    def _handle_codenode(self, node, successor=None, **kwargs):
        """

        :param CodeNode node:
        :return:
        """

        self._handle(node.node, successor=successor)

    def _handle_conditionnode(self, node, successor=None, **kwargs):
        """

        :param ConditionNode node:
        :param successor:
        :return:
        """

        if node.true_node is not None:
            self._handle(node.true_node, successor=successor)
        if node.false_node is not None:
            self._handle(node.false_node, successor=successor)

    def _handle_cascadingconditionnode(self, node: CascadingConditionNode, successor=None, **kwargs):
        for _, child_node in node.condition_and_nodes:
            self._handle(child_node, successor=successor)
        if node.else_node is not None:
            self._handle(node.else_node, successor=successor)

    def _handle_loopnode(self, node, successor=None, **kwargs):
        """

        :param LoopNode node:
        :param successor:
        :return:
        """

        self._handle(
            node.sequence_node,
            successor=node,  # the end of a loop always jumps to the beginning of its body
        )

    def _handle_multinode(self, node, successor=None, **kwargs):
        """

        :param MultiNode node:
        :return:
        """

        for n0, n1 in zip(node.nodes, node.nodes[1:] + [successor]):
            self._handle(n0, successor=n1)

    def _handle_block(self, block, successor=None, **kwargs):  # pylint:disable=no-self-use
        """
        This will also record irreducible gotos into the kb if found.

        :param ailment.Block block:
        :return:
        """
        if not block.statements:
            return

        last_stmt = block.statements[-1]
        # goto label;
        if isinstance(last_stmt, ailment.Stmt.Jump):
            if isinstance(last_stmt.target, ailment.Expr.Const):
                goto_target = last_stmt.target.value
                if successor and goto_target == successor.addr:
                    can_remove = True
                elif goto_target not in self._node_addrs:
                    # the target block has been removed and is no longer exist. we assume this goto is useless
                    can_remove = True
                else:
                    can_remove = False
                    self._handle_irreducible_goto(block, last_stmt)

                if can_remove:
                    # we can remove this statement
                    block.statements = block.statements[:-1]
        # if {goto label_1;} else {goto label_2;}
        elif isinstance(last_stmt, ailment.Stmt.ConditionalJump):
            if (
                last_stmt.true_target
                and isinstance(last_stmt.true_target, ailment.Expr.Const)
                and isinstance(last_stmt.true_target.value, int)
            ):
                self._handle_irreducible_goto(block, last_stmt, branch_target=True)

            if (
                last_stmt.false_target
                and isinstance(last_stmt.false_target, ailment.Expr.Const)
                and isinstance(last_stmt.false_target.value, int)
            ):
                self._handle_irreducible_goto(block, last_stmt, branch_target=False)

    def _handle_irreducible_goto(
        self, block, goto_stmt: ailment.Stmt.Jump | ailment.Stmt.ConditionalJump, branch_target=None
    ):
        if not self._function:
            l.debug("Unable to store a goto at %#x because simplifier is kb or functionless", block.addr)
            return

        # normal Goto Label
        if branch_target is None:
            dst_target = goto_stmt.target
        # true branch of a conditional jump
        elif branch_target:
            dst_target = goto_stmt.true_target
        # false branch of a conditional jump
        else:
            dst_target = goto_stmt.true_target

        src_ins_addr = goto_stmt.ins_addr if "ins_addr" in goto_stmt.tags else block.addr
        goto = Goto(block.addr, dst_target.value, src_idx=block.idx, dst_idx=None, src_ins_addr=src_ins_addr)
        l.debug("Storing %r goto", goto)
        self.irreducible_gotos.add(goto)
