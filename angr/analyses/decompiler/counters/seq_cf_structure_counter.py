from __future__ import annotations
from collections import defaultdict

import ailment

from angr.analyses.decompiler.sequence_walker import SequenceWalker
from angr.analyses.decompiler.structuring.structurer_nodes import LoopNode


class ControlFlowStructureCounter(SequenceWalker):
    """
    Counts the number of different types of control flow structures found in a sequence of nodes.
    This should be used after the sequence has been simplified.
    """

    def __init__(self, node):
        handlers = {
            LoopNode: self._handle_Loop,
            ailment.Block: self._handle_Block,
        }
        super().__init__(handlers)

        self.while_loops = 0
        self.do_while_loops = 0
        self.for_loops = 0
        self.ordered_labels = []
        self.goto_targets = defaultdict(int)

        self.walk(node)

        # eliminate gotos without labels
        self.goto_targets = {k: v for k, v in self.goto_targets.items() if k in self.ordered_labels}
        # correct labels that are not used
        self.ordered_labels = [lbl for lbl in self.ordered_labels if lbl in self.goto_targets]

    # pylint: disable=unused-argument
    def _handle_Block(self, node: ailment.Block, **kwargs):
        if not node.statements:
            return

        for stmt in node.statements:
            # labels found in the block at this point will be labels in the output
            if isinstance(stmt, ailment.statement.Label):
                label_addr = stmt.ins_addr
                if label_addr is not None:
                    self.ordered_labels.append(label_addr)

            # goto targets found in the block at this point will be goto targets in the output
            if isinstance(stmt, ailment.statement.Jump):
                target = stmt.target
                target_value = target.value if target is not None and isinstance(target, ailment.Expr.Const) else None
                if target_value is not None:
                    self.goto_targets[target_value] += 1

    def _handle_Loop(self, node: LoopNode, **kwargs):
        if node.sort == "while":
            self.while_loops += 1
        elif node.sort == "do-while":
            self.do_while_loops += 1
        elif node.sort == "for":
            self.for_loops += 1

        return super()._handle_Loop(node, **kwargs)
