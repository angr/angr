from itertools import imap

from archinfo import ArchARM

from ..block import Block
from .view import KnowledgeView

import logging
l = logging.getLogger(name=__name__)


class BlocksView(KnowledgeView):
    """
    TODO: Update documentation.
    """
    _disallowed_opts = {'arch', 'size', 'thumb', 'byte_string'}

    def __init__(self, kb):
        super(BlocksView, self).__init__(kb)

    def __getitem__(self, item):
        size = self._kb.blocks.sizes[item]
        return self._make_block(item, size)

    def __iter__(self):
        return imap(self.get_block, self._kb.blocks)

    def __contains__(self, item):
        return item in self._kb.blocks

    def __len__(self):
        return len(self._kb.blocks)

    def get_block(self, addr, **block_opts):
        """Get the Block object that corresponds to the basic block at given address.

        :param addr:
        :param thumb:
        :param opt_level:
        :return:
        """
        try:
            size = self._kb.blocks.sizes[addr]
        except KeyError:
            return None
        else:
            return self._make_block(addr, size, **block_opts)

    def _make_block(self, addr, size, **block_opts):
        """
        TODO: Update documentation.

        :param addr:
        :param size:
        :param block_opts:
        :return:
        """
        if set(block_opts) & self._disallowed_opts:
            raise ValueError("The following block options are not allowed: %s" %
                             ', '.join(set(block_opts) & self._disallowed_opts))

        thumb = None
        if isinstance(self._kb.object.arch, ArchARM):
            addr, thumb = addr & ~1, bool(addr & 1)

        arch = self._kb.object.arch
        byte_string = bytes(bytearray(self._kb.object.loader.memory.read_bytes(addr, size)))
        return Block(addr, arch=arch, thumb=thumb, byte_string=byte_string, **block_opts)
