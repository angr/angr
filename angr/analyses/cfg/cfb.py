
import logging

from bintrees import AVLTree

import cle

from ..analysis import Analysis
from .. import register_analysis

l = logging.getLogger('angr.analyses.cfg.cfb')


class CFBlanketView(object):
    """
    A view into the control-flow blanket.
    """
    def __init__(self, cfb):
        self._cfb = cfb

    def __getitem__(self, item):

        if isinstance(item, slice):
            addr = item.start
            start_addr = self._cfb.floor_addr(addr)

            addr_ = start_addr
            while True:
                obj = self._cfb[addr_]
                yield obj

                addr_ += obj
                # Find gaps
                # TODO: finish it
                raise NotImplementedError()


#
# An address can be mapped to one of the following types of object
# - Block
# - MemoryData
# - Unmapped region
#


class Unmapped(object):
    def __init__(self, addr, size):
        self.addr = addr
        self.size = size

        if size == 0:
            raise Exception("You cannot create an unmapped region of size 0.")

    def __repr__(self):
        s = "<Unmapped %#x-%#x>" % (self.addr, self.addr + self.size)
        return s


class CFBlanket(Analysis):
    """
    A Control-Flow Blanket is a representation for storing all instructions, data entries, and bytes of a full program.
    """
    def __init__(self, cfg=None):
        self._blanket = AVLTree()

        if cfg is not None:
            self._from_cfg(cfg)
        else:
            l.debug("CFG is not specified. Initialize CFBlanket from the knowledge base.")
            for func in self.kb.functions.values():
                self.add_function(func)

    def floor_item(self, addr):
        return self._blanket.floor_item(addr)

    def floor_items(self, addr=None):

        if addr is None:
            addr = self._blanket.min_key()
        else:
            try:
                addr = self.floor_addr(addr)
            except KeyError:
                try:
                    addr = self.ceiling_addr(addr)
                except KeyError:
                    # Nothing to yield
                    raise StopIteration

        while True:
            try:
                item = self._blanket[addr]
                yield (addr, item)
                item_size = item.size if item.size > 0 else 1
                addr = self.ceiling_addr(addr + item_size)
            except KeyError:
                break

    def floor_addr(self, addr):
        return self._blanket.floor_key(addr)

    def ceiling_item(self, addr):
        return self._blanket.ceiling_item(addr)

    def ceiling_addr(self, addr):
        return self._blanket.ceiling_key(addr)

    def __getitem__(self, addr):
        return self._blanket[addr]

    def add_obj(self, addr, obj):
        """


        :param addr:
        :param obj:
        :return:
        """

        self._blanket[addr] = obj

    def add_function(self, func):
        """
        Add a function and all blocks of this function to the blanket.

        :param angr.Function func: The function to add.
        :return:
        """

        for block in func.blocks:
            self.add_obj(block.addr, block)

    def dbg_repr(self):
        """
        The debugging representation of this CFBlanket.

        :return:    The debugging representation of this CFBlanket.
        :rtype:     str
        """

        output = [ ]

        for obj in self.project.loader.all_objects:
            for section in obj.sections:
                if section.memsize == 0:
                    continue
                min_addr, max_addr = section.min_addr, section.max_addr
                output.append("### Object %s" % repr(section))
                output.append("### Range %#x-%#x" % (min_addr, max_addr))

                pos = min_addr
                while pos < max_addr:
                    addr, thing = self.floor_item(pos)
                    output.append("%#x: %s" % (addr, repr(thing)))

                    if thing.size == 0: pos += 1
                    else: pos += thing.size

                output.append("")

        return "\n".join(output)

    def _from_cfg(self, cfg):
        """
        Initialize CFBlanket from a CFG instance.

        :param cfg: A CFG instance.
        :return:    None
        """

        # Let's first add all functions first
        for func in cfg.kb.functions.values():
            self.add_function(func)

        # TODO: Scan through the entire memory space and find gaps

        self._mark_unmapped()

    def _mark_unmapped(self):
        """
        Mark all unmapped regions.

        :return: None
        """

        for obj in self.project.loader.all_objects:
            if isinstance(obj, cle.ELF):
                # sections?
                if obj.sections:
                    for section in obj.sections:
                        if not section.memsize:
                            continue
                        min_addr, max_addr = section.min_addr, section.max_addr
                        self._mark_unmapped_core(min_addr, max_addr)
                elif obj.segments:
                    for segment in obj.segments:
                        if not segment.memsize:
                            continue
                        min_addr, max_addr = segment.min_addr, segment.max_addr
                        self._mark_unmapped_core(min_addr, max_addr)
                else:
                    # is it empty?
                    l.warning("Empty ELF object %s.", repr(obj))
            elif isinstance(obj, cle.PE):
                if obj.sections:
                    for section in obj.sections:
                        if not section.memsize:
                            continue
                        min_addr, max_addr = section.min_addr, section.max_addr
                        self._mark_unmapped_core(min_addr, max_addr)
                else:
                    # is it empty?
                    l.warning("Empty PE object %s.", repr(obj))
            else:
                min_addr, max_addr = obj.min_addr, obj.max_addr
                self._mark_unmapped_core(min_addr, max_addr)

    def _mark_unmapped_core(self, min_addr, max_addr):

        try:
            addr, item = self.floor_item(min_addr)
            if addr < min_addr:
                raise KeyError
        except KeyError:
            # there is no other lower addresses
            try:
                next_addr = self.ceiling_addr(min_addr)
                if next_addr >= max_addr:
                    raise KeyError
            except KeyError:
                next_addr = max_addr

            self.add_obj(min_addr, Unmapped(min_addr, next_addr - min_addr))

        addr = min_addr
        while addr < max_addr:
            last_addr, last_item = self.floor_item(addr)
            if last_addr < min_addr:
                # impossible
                raise Exception('Impossible')

            if last_item.size == 0:
                # Make sure everything has a non-zero size
                last_item_size = 1
            else:
                last_item_size = last_item.size
            end_addr = last_addr + last_item_size
            if end_addr < max_addr:
                try:
                    next_addr = self.ceiling_addr(end_addr)
                except KeyError:
                    next_addr = max_addr
                if next_addr > end_addr:
                    # there is a gap
                    self.add_obj(end_addr, Unmapped(end_addr, next_addr - end_addr))
                addr = next_addr
            else:
                addr = max_addr


register_analysis(CFBlanket, 'CFB')
