from typing import Optional, Tuple

from ailment import Const, Block, Expression
from ailment.statement import Jump, ConditionalJump, Call
from networkx import NetworkXError


class CFGTransformationMixin:
    def __init__(self, graph):
        self._graph = graph
        self._block_by_addr_and_idx = {}
        for block in self._graph.nodes:
            self._block_by_addr_and_idx[(block.addr, block.idx)] = block

    def _remove_some_branch(
        self, block: Block, jump: ConditionalJump, kept_target, kept_target_idx, removed_target, removed_target_idx
    ):
        new_stmt = Jump(
            jump.idx,
            kept_target,
            kept_target_idx,
            **jump.tags,
        )
        block.statements[-1] = new_stmt
        if isinstance(removed_target, Const):
            key = (removed_target.value, removed_target_idx)
            if key in self._block_by_addr_and_idx:
                removed_target_block = self._block_by_addr_and_idx[key]
                try:
                    self._graph.remove_edge(block, removed_target_block)
                except NetworkXError:
                    pass

    def remove_false_branch(self, block: Block):
        if block.statements and isinstance(block.statements[-1], ConditionalJump):
            jump = block.statements[-1]
            self._remove_some_branch(
                block, jump, jump.true_target, jump.true_target_idx, jump.false_target, jump.false_target_idx
            )

    def replace_jump_target(
        self,
        block,
        old_target: Optional[Tuple[Expression, Optional[int]]],
        new_target: Tuple[Expression, Optional[int]],
    ):
        if not block.statements:
            return

        old_target_addr, old_target_idx = None, None
        new_target_addr, new_target_idx = new_target
        if old_target:
            old_target_addr, old_target_idx = old_target

        terminal = block.statements[-1]
        if isinstance(terminal, Jump):
            if old_target is None or (isinstance(terminal.target, Const) and terminal.target.value == old_target_addr):
                target = Const(0, None, new_target_addr, terminal.target.bits)
                block.statements[-1] = Jump(
                    terminal.idx,
                    target,
                    new_target_idx,
                    **terminal.tags,
                )
            else:
                return
        elif isinstance(terminal, ConditionalJump):
            if old_target is None or (
                isinstance(terminal.true_target, Const)
                and isinstance(terminal.false_target, Const)
                and (
                    (
                        terminal.true_target.value == old_target_addr
                        and terminal.true_target_idx == old_target_idx
                        and terminal.false_target.value == new_target_addr
                        and terminal.false_target_idx == new_target_idx
                    )
                    or (
                        terminal.false_target.value == old_target_addr
                        and terminal.false_target_idx == old_target_idx
                        and terminal.true_target.value == new_target_addr
                        and terminal.true_target_idx == new_target_idx
                    )
                )
            ):
                target = Const(0, None, new_target_addr, terminal.true_target.bits)
                block.statements[-1] = Jump(
                    terminal.idx,
                    target,
                    new_target_idx,
                    ins_addr=terminal.ins_addr,
                )
            elif (
                isinstance(terminal.true_target, Const)
                and terminal.true_target.value == old_target_addr
                and terminal.true_target_idx == old_target_idx
            ):
                terminal.true_target.value = new_target_addr
                terminal.true_target_idx = new_target_idx
            elif (
                isinstance(terminal.false_target, Const)
                and terminal.false_target.value == old_target_addr
                and terminal.false_target_idx == old_target_idx
            ):
                terminal.false_target.value = new_target_addr
                terminal.false_target_idx = new_target_idx
            else:
                return
        elif isinstance(terminal, Call):
            pass
        else:
            return
        # Remove old edges
        old_target_block = self._get_block_by_addr_and_idx(old_target_addr, old_target_idx)
        if old_target_block:
            try:
                self._graph.remove_edge(block, old_target_block)
            except NetworkXError:
                pass
        else:
            for succ in list(self._graph.successors(block)):
                try:
                    self._graph.remove_edge(block, succ)
                except NetworkXError:
                    pass
        # Add new edge
        self._graph.add_edge(block, new_target)
