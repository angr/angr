# pylint:disable=unused-argument
from __future__ import annotations

from typing import TYPE_CHECKING

from angr import ailment
from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structurer_nodes import (
    BreakNode,
    CascadingConditionNode,
    CodeNode,
    ConditionalBreakNode,
    ConditionNode,
    ContinueNode,
    LoopNode,
    MultiNode,
    SequenceNode,
    SwitchCaseNode,
)
from angr.analyses.decompiler.utils import first_nonlabel_statement, sequence_to_blocks

if TYPE_CHECKING:
    from angr.ailment import Manager


def _label_addrs(block: ailment.Block) -> set[int]:
    """
    Addresses a jump into block may name: its own address and those of its leading labels.
    """
    addrs = {block.addr}
    for stmt in block.statements:
        if not isinstance(stmt, ailment.Stmt.Label):
            break
        if "ins_addr" in stmt.tags:
            addrs.add(stmt.tags["ins_addr"])
    return addrs


def _entry_addrs(node) -> set[int] | None:
    """
    Addresses that may name where control arrives when it enters node, or None if node is unknown.
    """
    if node is None:
        return None
    addrs = {node.addr} if isinstance(node.addr, int) else set()
    if isinstance(node, LoopNode):
        if node.continue_addr is not None:
            addrs.add(node.continue_addr)
        if node.iterator is not None and "ins_addr" in node.iterator.tags:
            addrs.add(node.iterator.tags["ins_addr"])
    blocks = sequence_to_blocks(node)
    if blocks:
        addrs |= _label_addrs(blocks[0])
        # a goto-only block keeps the address it was split from, not the address it sends control to
        stmt = first_nonlabel_statement(blocks[0])
        if isinstance(stmt, ailment.Stmt.Jump) and isinstance(stmt.target, ailment.Expr.Const):
            addrs.add(stmt.target.value)
    return addrs


class BreakRebinder(SequenceWalker):
    """
    Rewrite Break and Continue nodes that no longer reach their targets into gotos.

    Structuring records in every Break and Continue node the address it must reach. A later phase can enclose such a
    node in a loop or a switch-case that did not exist when it was created, and in C it binds to that construct
    instead. A node whose target is not where its binding construct sends control becomes a goto to the target.
    """

    def __init__(self, node, manager: Manager, bits: int):
        handlers = {
            SequenceNode: self._handle_sequencenode,
            CodeNode: self._handle_codenode,
            MultiNode: self._handle_multinode,
            LoopNode: self._handle_loopnode,
            SwitchCaseNode: self._handle_switchcasenode,
            ConditionNode: self._handle_conditionnode,
            CascadingConditionNode: self._handle_cascadingconditionnode,
            BreakNode: self._handle_breaknode,
            ConditionalBreakNode: self._handle_conditionalbreaknode,
            ContinueNode: self._handle_continuenode,
        }

        super().__init__(handlers)
        self.manager = manager
        self.bits = bits
        self.blocks = sequence_to_blocks(node)

        self.walk(node)

    #
    # Handlers
    #

    def _handle_sequencenode(self, node, successor=None, **kwargs):
        for idx, (child, child_successor) in enumerate(zip(node.nodes, [*node.nodes[1:], successor])):
            new_node = self._handle(child, successor=child_successor, **kwargs)
            if new_node is not None:
                node.nodes[idx] = new_node

    def _handle_multinode(self, node, **kwargs):
        self._handle_sequencenode(node, **kwargs)

    def _handle_codenode(self, node, **kwargs):
        new_node = self._handle(node.node, **kwargs)
        if new_node is not None:
            node.node = new_node

    def _handle_conditionnode(self, node, **kwargs):
        if node.true_node is not None:
            new_node = self._handle(node.true_node, **kwargs)
            if new_node is not None:
                node.true_node = new_node
        if node.false_node is not None:
            new_node = self._handle(node.false_node, **kwargs)
            if new_node is not None:
                node.false_node = new_node

    def _handle_cascadingconditionnode(self, node: CascadingConditionNode, **kwargs):
        for idx, (cond, child) in enumerate(node.condition_and_nodes):
            new_node = self._handle(child, **kwargs)
            if new_node is not None:
                node.condition_and_nodes[idx] = cond, new_node
        if node.else_node is not None:
            new_node = self._handle(node.else_node, **kwargs)
            if new_node is not None:
                node.else_node = new_node

    def _handle_loopnode(self, node: LoopNode, successor=None, **kwargs):
        self._handle(
            node.sequence_node,
            successor=node,  # the end of a loop always jumps to the beginning of its body
            break_target=_entry_addrs(successor),
            continue_target=_entry_addrs(node),
        )

    def _handle_switchcasenode(self, node: SwitchCaseNode, successor=None, continue_target=None, **kwargs):
        break_target = _entry_addrs(successor)
        for case_idx in node.cases:
            new_node = self._handle(node.cases[case_idx], break_target=break_target, continue_target=continue_target)
            if new_node is not None:
                node.cases[case_idx] = new_node
        if node.default_node is not None:
            new_node = self._handle(node.default_node, break_target=break_target, continue_target=continue_target)
            if new_node is not None:
                node.default_node = new_node

    def _handle_breaknode(self, node: BreakNode, break_target=None, **kwargs):
        return self._rewrite_to_goto(node, break_target)

    def _handle_continuenode(self, node: ContinueNode, continue_target=None, **kwargs):
        return self._rewrite_to_goto(node, continue_target)

    def _handle_conditionalbreaknode(self, node: ConditionalBreakNode, break_target=None, **kwargs):
        goto = self._rewrite_to_goto(node, break_target)
        return None if goto is None else ConditionNode(node.addr, None, node.condition, goto)

    #
    # Utils
    #

    def _rewrite_to_goto(self, node: BreakNode | ContinueNode, target_addrs: set[int] | None) -> ailment.Block | None:
        if not isinstance(node.target, int) or not isinstance(node.addr, int):
            return None
        if target_addrs is None or node.target in target_addrs:
            return None
        target_block = next((block for block in self.blocks if node.target in _label_addrs(block)), None)
        if target_block is None:
            return None
        label = self._ensure_label(target_block, node.target)
        jump = ailment.Stmt.Jump(
            self.manager.next_atom(),
            ailment.Expr.Const(self.manager.next_atom(), node.target, self.bits),
            target_idx=label.tags.get("block_idx"),
            ins_addr=node.addr,
        )
        return ailment.Block(node.addr, 0, statements=[jump], idx=None)

    def _ensure_label(self, block: ailment.Block, target: int) -> ailment.Stmt.Label:
        for stmt in block.statements:
            if isinstance(stmt, ailment.Stmt.Label) and stmt.tags.get("ins_addr") == target:
                return stmt
        label = ailment.Stmt.Label(self.manager.next_atom(), f"LABEL_{target:x}", ins_addr=target, block_idx=block.idx)
        block.statements = [label, *block.statements]
        return label
