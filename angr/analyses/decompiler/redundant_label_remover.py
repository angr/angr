# pylint:disable=unused-argument
from typing import Set, Optional, Tuple, Dict

import ailment

from .sequence_walker import SequenceWalker
from .structuring.structurer_nodes import SequenceNode
from .utils import first_nonlabel_statement


class RedundantLabelRemover:
    """
    Remove redundant labels.

    This optimization pass contains two separate passes. The first pass (self._walker0) finds all redundant labels
    (e.g., two or more labels for the same location) and records the replacement label for redundant labels in
    self._new_jump_target. The second pass (self._walker1) removes all redundant labels that (a) are not referenced
    anywhere (determined by jump_targets), or (b) are deemed replaceable by the first pass.
    """

    def __init__(self, node, jump_targets: Set[Tuple[int, Optional[int]]]):
        self.root = node
        self._jump_targets = jump_targets

        self._labels_to_remove: Set[ailment.Stmt.Label] = set()
        self._new_jump_target: Dict[Tuple[int, Optional[int]], Tuple[int, Optional[int]]] = {}

        handlers0 = {
            SequenceNode: self._handle_Sequence,
        }
        self._walker0 = SequenceWalker(handlers=handlers0)
        self._walker0.walk(self.root)

        handlers1 = {
            ailment.Block: self._handle_Block,
        }
        self._walker1 = SequenceWalker(handlers=handlers1)
        self._walker1.walk(self.root)
        self.result = self.root

    #
    # Handlers
    #

    def _handle_Sequence(self, node: SequenceNode, **kwargs):
        # merge consecutive labels
        last_label_addr: Optional[Tuple[int, Optional[int]]] = None
        for node_ in node.nodes:
            if isinstance(node_, ailment.Block):
                if node_.statements:
                    for stmt in node_.statements:
                        if isinstance(stmt, ailment.Stmt.Label):
                            if last_label_addr is None:
                                # record the label address
                                last_label_addr = stmt.ins_addr, stmt.block_idx
                            else:
                                # this label is useless - we should replace this label with the last label
                                self._labels_to_remove.add(stmt)
                                self._new_jump_target[(stmt.ins_addr, stmt.block_idx)] = last_label_addr
                        else:
                            last_label_addr = None
                            break
            else:
                last_label_addr = None

        return self._walker0._handle_Sequence(node, **kwargs)

    def _handle_Block(self, block: ailment.Block, **kwargs):
        if block.statements:
            # fixed point remove all labels with no edges in
            while True:
                for idx, stmt in enumerate(block.statements):
                    if isinstance(stmt, ailment.Stmt.Label):
                        if (stmt.ins_addr, stmt.block_idx) not in self._jump_targets or stmt in self._labels_to_remove:
                            # useless label - update the block in-place
                            block.statements = block.statements[:idx] + block.statements[idx + 1 :]
                            break
                else:
                    break

            first_stmt = first_nonlabel_statement(block)
            if isinstance(first_stmt, ailment.Stmt.ConditionalJump):
                if isinstance(first_stmt.true_target, ailment.Expr.Const):
                    tpl = first_stmt.true_target.value, None
                    if tpl in self._new_jump_target:
                        first_stmt.true_target = ailment.Expr.Const(
                            first_stmt.true_target.idx,
                            first_stmt.true_target.variable,
                            self._new_jump_target[tpl][0],
                            first_stmt.true_target.bits,
                            **first_stmt.true_target.tags,
                        )
                if isinstance(first_stmt.false_target, ailment.Expr.Const):
                    tpl = first_stmt.false_target.value, None
                    if tpl in self._new_jump_target:
                        first_stmt.false_target = ailment.Expr.Const(
                            first_stmt.false_target.idx,
                            first_stmt.false_target.variable,
                            self._new_jump_target[tpl][0],
                            first_stmt.false_target.bits,
                            **first_stmt.false_target.tags,
                        )

            if block.statements:
                last_stmt = block.statements[-1]
                if isinstance(last_stmt, ailment.Stmt.Jump):
                    if isinstance(last_stmt.target, ailment.Expr.Const):
                        tpl = last_stmt.target.value, last_stmt.target_idx
                        if tpl in self._new_jump_target:
                            last_stmt.target = ailment.Expr.Const(
                                last_stmt.target.idx,
                                last_stmt.target.variable,
                                self._new_jump_target[tpl][0],
                                last_stmt.target.bits,
                                **last_stmt.target.tags,
                            )
                            last_stmt.target_idx = self._new_jump_target[tpl][1]
