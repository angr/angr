from binascii import hexlify
from rangedict import RangeDict, RangeItem

from ..errors import AngrError
from .plugin import KnowledgeBasePlugin

import logging
l = logging.getLogger("angr.knowledge.basic_blocks")


class BasicBlocksPlugin(KnowledgeBasePlugin):
    """
    Storage for information about the boundaries of basic blocks. Access as kb.basic_blocks.
    """

    def __init__(self, kb=None):
        super(BasicBlocksPlugin, self).__init__(kb)
        self._blocks = BlockMapping()

    def __setitem__(self, key, value):
        if not isinstance(key, slice):
            raise TypeError(key)
        elif key.step is not None:
            raise ValueError(key)

        self.add_block(key.start, key.stop - key.start, value)

    def __getitem__(self, key):
        if isinstance(key, (int, long)):
            return self.get_block(key)
        elif isinstance(key, slice):
            if key.step is not None:
                raise ValueError(key)
            return list(self.iter_blocks(key.start, key.stop))
        else:
            raise TypeError(key)

    def __delitem__(self, key):
        raise NotImplementedError

    def __iter__(self):
        return self.iter_blocks()

    def __contains__(self, key):
        if not isinstance(key, (int, long)):
            raise TypeError(key)
        return key in self._blocks

    def copy(self):
        raise NotImplementedError

    #
    #   ...
    #

    def add_block(self, addr, size, thumb=False, overlap_mode='trim', overlap_handler=None, **handler_kwargs):
        """Add a new block to the block map.
        
        In case a new block has intersected with any existing one, handle the intersction in a way
        specified by the `overlap_mode` parameter value:
        
            - If `overlap_mode` is set to 'trim', use the internal trimming mechanism that is provided by RangeDict. 
            
            - If `overlap_mode` is set 'handle', use the provided `overlap_handler` function to trim the blocks.
              The `overlap_handler` function should accept (this_block, other_block) arguments, where `this_block`
              is the newly added block, and `other_block` is the block which is to be overlapped.
              
            - If `overlap_mode` is set to 'raise', raise an `OverlappedBlock` exception.
        
        :param addr:            The address of the new block.
        :param size:            The size of the new block.
        :param thumb:           True, if this block contains THUMB code.
        :param overlap_mode:    This specifies how to handle the intersections.  
        :param overlap_handler: Use this handler function in case the `overlap_mode` is set to `handle`.
        :param handler_kwargs:  Pass this keyword arguments to `overlap_handler` function.
        :return: 
        """
        if size == 0:
            raise ValueError("Do not know how to handle an empty block @ %#x" % addr)

        try:
            self._blocks[addr:addr + size] = thumb

        except OverlappedBlocks as overlapped:
            this_block, other_block = \
                overlapped.this_block, overlapped.other_block

            if overlap_mode == 'handle':
                if this_block.addr != addr:
                    this_block, other_block = other_block, this_block
                overlap_handler(this_block, other_block, **handler_kwargs)

            elif overlap_mode == 'trim':
                this_block.second_chance = True
                self._blocks[addr:addr + size] = thumb

            elif overlap_mode == 'raise':
                raise

            else:
                raise ValueError('Unknown overlapped blocks handling mode', overlap_mode)

    def get_block(self, addr):
        """Get block that occupies the given address.
        
        :param addr: 
        :return: 
        """
        return self._blocks.peekitem(addr)

    def del_block(self, addr):
        """Delete block that occupies the given address.
        
        :param addr: 
        :return: 
        """
        raise NotImplementedError

    def iter_blocks(self, start=None, stop=None):
        """Iterate over blocks that occupy the specified range of addresses.
        
        :param start: 
        :param stop: 
        :return: 
        """
        return self._blocks.islice(start, stop)


class BlockMapping(RangeDict):

    def _trim_left(self, this_item, left_item):
        if this_item.start < left_item.end and not this_item.second_chance:
            raise OverlappedBlocks(this_item, left_item)
        else:
            this_item.second_chance = False
            return super(BlockMapping, self)._trim_left(this_item, left_item)

    def _trim_right(self, this_item, right_item):
        if this_item.end > right_item.start and not this_item.second_chance:
            raise OverlappedBlocks(this_item, right_item)
        else:
            this_item.second_chance = False
            return super(BlockMapping, self)._trim_right(this_item, right_item)

    def _should_merge(self, this_item, other_item):
        return False

    def _make_item(self, start, end, value):
        return BasicBlock(start, end, value)


class BasicBlock(RangeItem):

    def __init__(self, *args, **kwargs):
        super(BasicBlock, self).__init__(*args, **kwargs)
        self.second_chance = False

    @property
    def thumb(self):
        return self.value

    def __repr__(self):
        return '<BasicBlock(%#x-%#x, %d bytes%s)>' % \
               (self.start, self.end, self.size, ', THUMB' if self.thumb else '')

    def copy(self):
        return BasicBlock(self.start, self.end, self.value)


class OverlappedBlocks(AngrError):

    def __init__(self, this_block, other_block):
        self.this_block = this_block
        self.other_block = other_block
