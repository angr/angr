from bintrees import RBTree

from ..errors import InconsistentSizes, InconsistentEndpoints
from .plugin import KnowledgeBasePlugin

import logging
l = logging.getLogger(name=__name__)


class BasicBlocksPlugin(KnowledgeBasePlugin):
    """
    Storage for information about the boundaries of basic blocks. Access as kb.basic_blocks.
    """

    def __init__(self):
        super(BasicBlocksPlugin, self).__init__()

        self._addrs = set()
        self._sizes = {}
        self._index = RBTree()

    def __getitem__(self, item):
        return BasicBlock(item, self._sizes[item])

    def __iter__(self):
        for addr in self._addrs:
            yield self[addr]

    def __contains__(self, item):
        return item in self._addrs

    def __len__(self):
        return len(self._addrs)

    @property
    def addrs(self):
        return self._addrs

    @property
    def sizes(self):
        return self._index

    def get_block(self, addr):
        """Get the basic block that starts at given address.

        :param addr:
        :param thumb:
        :param opt_level:
        :return:
        """
        try:
            return self[addr]
        except KeyError:
            return None

    def mark_block(self, addr, size):
        """Mark (addr, addr + size) range as belonging to some basic block.

        :param addr:
        :param size:
        :param thumb:
        :return:
        """
        if size <= 0:
            raise ValueError("Invalid block size", size)

        try:
            p_addr, p_size = addr, self._sizes.get(addr)
            if p_size is None:
                p_addr, p_size = self._index.floor_item(addr)
        except KeyError:
            pass
        else:
            if addr == p_addr and size != p_size:
                raise InconsistentSizes(addr, size, p_size)
            elif p_addr + p_size > addr and p_addr + p_size != addr + size:
                raise InconsistentEndpoints(p_addr, p_size, addr, size)

        self._sizes[addr] = self._index[addr] = size
        self._addrs.add(addr)


class BasicBlock(object):

    def __init__(self, addr, size):
        self.addr = addr
        self.size = size
