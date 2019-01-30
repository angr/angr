import logging
import cffi
import cle

from sortedcontainers import SortedDict

from ..analysis import Analysis

_l = logging.getLogger(name=__name__)


class CFBlanketView:
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
# Memory region
#


class MemoryRegion:
    def __init__(self, addr, size, type_, object_, cle_region):
        self.addr = addr
        self.size = size
        self.type = type_
        self.object = object_
        self.cle_region = cle_region


#
# An address can be mapped to one of the following types of object
# - Block
# - MemoryData
# - Unknown
#


class Unknown:
    def __init__(self, addr, size, bytes_=None, object_=None, segment=None, section=None):
        self.addr = addr
        self.size = size

        # Optional
        self.bytes = bytes_
        self.object = object_
        self.segment = segment
        self.section = section

        if size == 0:
            raise Exception("You cannot create an unknown region of size 0.")

    def __repr__(self):
        s = "<Unknown %#x-%#x>" % (self.addr, self.addr + self.size)
        return s


class CFBlanket(Analysis):
    """
    A Control-Flow Blanket is a representation for storing all instructions, data entries, and bytes of a full program.
    """
    def __init__(self, cfg=None):
        self._blanket = SortedDict()

        self._regions = [ ]

        self._init_regions()

        if cfg is not None:
            self._from_cfg(cfg)
        else:
            _l.debug("CFG is not specified. Initialize CFBlanket from the knowledge base.")
            for func in self.kb.functions.values():
                self.add_function(func)

    def _init_regions(self):

        for obj in self.project.loader.all_objects:
            if isinstance(obj, cle.MetaELF):
                if obj.sections:
                    # Enumerate sections in an ELF file
                    for section in obj.sections:
                        mr = MemoryRegion(section.vaddr, section.memsize, 'TODO', obj, section)
                        self._regions.append(mr)
                else:
                    raise NotImplementedError()
            else:
                mr = MemoryRegion(obj.min_addr, obj.size if hasattr(obj, 'size') else 80, 'TODO', obj, None)
                self._regions.append(mr)

        # Sort them just in case
        self._regions = list(sorted(self._regions, key=lambda x: x.addr))

    @property
    def regions(self):
        """
        Return all memory regions.
        """

        return self._regions

    def floor_addr(self, addr):
        try:
            return next(self._blanket.irange(maximum=addr, reverse=True))
        except StopIteration:
            raise KeyError(addr)

    def floor_item(self, addr):
        key = self.floor_addr(addr)
        return key, self._blanket[key]

    def floor_items(self, addr=None, reverse=False):
        if addr is None:
            start_addr = None
        else:
            try:
                start_addr = next(self._blanket.irange(maximum=addr, reverse=True))
            except StopIteration:
                start_addr = addr

        for key in self._blanket.irange(minimum=start_addr, reverse=reverse):
            yield key, self._blanket[key]

    def ceiling_addr(self, addr):
        try:
            return next(self._blanket.irange(minimum=addr))
        except StopIteration:
            raise KeyError(addr)

    def ceiling_item(self, addr):
        key = self.ceiling_addr(addr)
        return key, self._blanket[key]

    def ceiling_items(self, addr=None, reverse=False, include_first=True):
        if addr is None:
            start_addr = None
        else:
            try:
                start_addr = next(self._blanket.irange(minimum=addr))
            except StopIteration:
                start_addr = addr

        for key in self._blanket.irange(maximum=start_addr if include_first else start_addr - 1, reverse=reverse):
            yield key, self._blanket[key]

    def __getitem__(self, addr):
        return self._blanket[addr]

    def add_obj(self, addr, obj):
        """
        Adds an object `obj` to the blanket at the specified address `addr`
        """
        self._blanket[addr] = obj

    def add_function(self, func):
        """
        Add a function `func` and all blocks of this function to the blanket.
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
                    try:
                        addr, thing = self.floor_item(pos)
                        output.append("%#x: %s" % (addr, repr(thing)))

                        if thing.size == 0: pos += 1
                        else: pos += thing.size
                    except KeyError:
                        pos += 1

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

        self._mark_unknowns()

    def _mark_unknowns(self):
        """
        Mark all unmapped regions.

        :return: None
        """

        for obj in self.project.loader.all_objects:
            if isinstance(obj, cle.ELF):
                # sections?
                if obj.sections:
                    for section in obj.sections:
                        if not section.memsize or not section.vaddr:
                            continue
                        min_addr, max_addr = section.min_addr, section.max_addr
                        self._mark_unknowns_core(min_addr, max_addr + 1, obj=obj, section=section)
                elif obj.segments:
                    for segment in obj.segments:
                        if not segment.memsize:
                            continue
                        min_addr, max_addr = segment.min_addr, segment.max_addr
                        self._mark_unknowns_core(min_addr, max_addr + 1, obj=obj, segment=segment)
                else:
                    # is it empty?
                    _l.warning("Empty ELF object %s.", repr(obj))
            elif isinstance(obj, cle.PE):
                if obj.sections:
                    for section in obj.sections:
                        if not section.memsize:
                            continue
                        min_addr, max_addr = section.min_addr, section.max_addr
                        self._mark_unknowns_core(min_addr, max_addr + 1, obj=obj, section=section)
                else:
                    # is it empty?
                    _l.warning("Empty PE object %s.", repr(obj))
            else:
                min_addr, max_addr = obj.min_addr, obj.max_addr
                self._mark_unknowns_core(min_addr, max_addr + 1, obj=obj)

    def _mark_unknowns_core(self, min_addr, max_addr, obj=None, segment=None, section=None):

        # The region should be [min_addr, max_addr)

        try:
            addr = self.floor_addr(min_addr)
            if addr < min_addr:
                raise KeyError
        except KeyError:
            # there is no other lower address
            try:
                next_addr = self.ceiling_addr(min_addr)
                if next_addr >= max_addr:
                    raise KeyError
            except KeyError:
                next_addr = max_addr

            size = next_addr - min_addr
            if obj is None or isinstance(obj, cle.ExternObject):
                bytes_ = None
            else:
                try:
                    _l.debug("Loading bytes from object %s, section %s, segmeng %s, addresss %#x.",
                             obj, section, segment, min_addr)
                    bytes_ = self.project.loader.memory.load(min_addr, size)
                except KeyError:
                    # The address does not exist
                    bytes_ = None
            self.add_obj(min_addr,
                         Unknown(min_addr, size, bytes_=bytes_, object_=obj, segment=segment, section=section)
                         )

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
                    size = next_addr - end_addr
                    if obj is None or isinstance(obj, cle.ExternObject):
                        bytes_ = None
                    else:
                        try:
                            _l.debug("Loading bytes from object %s, section %s, segmeng %s, addresss %#x.",
                                     obj, section, segment, next_addr)
                            bytes_ = self.project.loader.memory.load(next_addr, size)
                        except KeyError:
                            # The address does not exist
                            bytes_ = None
                    self.add_obj(end_addr,
                                 Unknown(end_addr, size, bytes_=bytes_, object_=obj, segment=segment, section=section)
                                 )
                addr = next_addr
            else:
                addr = max_addr


from angr.analyses import AnalysesHub
AnalysesHub.register_default('CFB', CFBlanket)
AnalysesHub.register_default('CFBlanket', CFBlanket)
