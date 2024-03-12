from ailment import Block

from .sequence_walker import SequenceWalker


class SequenceToBlocks(SequenceWalker):
    """
    Helper class to count AIL calls and call expressions in a structuring node.
    """

    def __init__(self):
        handlers = {
            Block: self._handle_Block,
        }
        self.blocks = []
        super().__init__(handlers, force_forward_scan=True, update_seqnode_in_place=False)

    def _handle_Block(self, node: Block, **kwargs):  # pylint:disable=unused-argument
        self.blocks.append(node)
