# pylint:disable=unused-argument,arguments-differ

import ailment

from ..sequence_walker import SequenceWalker


class NodeAddressFinder(SequenceWalker):
    """
    Walk the entire node and collect all addresses of nodes.
    """

    def __init__(self, node):
        handlers = {
            ailment.Block: self._handle_Block,
        }
        super().__init__(handlers=handlers)
        self.addrs: set[int] = set()

        self.walk(node)

    def _handle_Block(self, node: ailment.Block, **kwargs):
        self.addrs.add(node.addr)
