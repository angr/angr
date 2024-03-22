from ailment import Block

from .sequence_walker import SequenceWalker


class SequenceToBlocks(SequenceWalker):
    """
    A helper class to convert a sequence node into a list of blocks.
    """

    def __init__(self):
        handlers = {
            Block: self._handle_Block,
        }
        self.blocks = []
        super().__init__(handlers, force_forward_scan=True, update_seqnode_in_place=False)

    def _handle_Block(self, node: Block, **kwargs):  # pylint:disable=unused-argument
        self.blocks.append(node)
