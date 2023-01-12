# pylint:disable=unused-argument
from typing import Set, Tuple, Optional

import ailment

from .sequence_walker import SequenceWalker


class JumpTargetCollector:
    """
    Collect all jump targets.
    """

    def __init__(self, node):
        self.root = node
        self.jump_targets: Set[Tuple[int, Optional[int]]] = set()

        handlers = {
            ailment.Block: self._handle_Block,
        }
        self._walker = SequenceWalker(handlers=handlers)
        self._walker.walk(self.root)

    #
    # Handlers
    #

    def _handle_Block(self, block: ailment.Block, **kwargs):
        for stmt in block.statements:
            if isinstance(stmt, ailment.Stmt.Jump):
                if isinstance(stmt.target, ailment.Expr.Const):
                    self.jump_targets.add((stmt.target.value, stmt.target_idx))
            elif isinstance(stmt, ailment.Stmt.ConditionalJump):
                if isinstance(stmt.true_target, ailment.Expr.Const):
                    self.jump_targets.add((stmt.true_target.value, None))
                if isinstance(stmt.false_target, ailment.Expr.Const):
                    self.jump_targets.add((stmt.false_target.value, None))
