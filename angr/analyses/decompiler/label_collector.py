# pylint:disable=unused-argument
from __future__ import annotations
from collections import defaultdict

import angr.ailment as ailment

from .sequence_walker import SequenceWalker


class LabelCollector:
    """
    Collect all labels.
    """

    def __init__(self, node):
        self.root = node
        self.labels: defaultdict[str, list[tuple[int, int | None]]] = defaultdict(list)

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
            if isinstance(stmt, ailment.Stmt.Label):
                self.labels[stmt.name].append((block.addr, block.idx))
