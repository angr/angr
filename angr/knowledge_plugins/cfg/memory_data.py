# pylint:disable=no-member
from ...protos import cfg_pb2
from ...serializable import Serializable


class MemoryDataSort:
    Unspecified = None
    Unknown = "unknown"
    Integer = "integer"
    PointerArray = "pointer-array"
    String = "string"
    UnicodeString = "unicode"
    SegmentBoundary = "segment-boundary"
    CodeReference = "code reference"
    GOTPLTEntry = "GOT PLT Entry"
    ELFHeader = 'elf-header'
    FloatingPoint = 'fp'  # the size is determined by the MemoryData itself


_SORT_TO_IDX = {
    MemoryDataSort.Unspecified: cfg_pb2.MemoryData.Unspecified,
    MemoryDataSort.Unknown: cfg_pb2.MemoryData.UnknownDataType,
    MemoryDataSort.Integer: cfg_pb2.MemoryData.Integer,
    MemoryDataSort.PointerArray: cfg_pb2.MemoryData.PointerArray,
    MemoryDataSort.String: cfg_pb2.MemoryData.String,
    MemoryDataSort.UnicodeString: cfg_pb2.MemoryData.UnicodeString,
    MemoryDataSort.SegmentBoundary: cfg_pb2.MemoryData.SegmentBoundary,
    MemoryDataSort.CodeReference: cfg_pb2.MemoryData.CodeReference,
    MemoryDataSort.GOTPLTEntry: cfg_pb2.MemoryData.GOTPLTEntry,
    MemoryDataSort.ELFHeader: cfg_pb2.MemoryData.ELFHeader,
    MemoryDataSort.FloatingPoint: cfg_pb2.MemoryData.FloatingPoint,
}

_IDX_TO_SORT = dict((v, k) for k, v in _SORT_TO_IDX.items())


class MemoryData(Serializable):
    """
    MemoryData describes the syntactic content of a single address of memory.
    """

    __slots__ = ('addr', 'size', 'sort', 'max_size', 'pointer_addr', 'content', )

    def __init__(self, address, size, sort, pointer_addr=None, max_size=None):
        self.addr = address
        self.size = size
        self.sort = sort

        self.max_size = max_size
        self.pointer_addr = pointer_addr

        self.content = None  # optional

    @property
    def address(self):
        return self.addr

    def __repr__(self):
        return "\\%#x, %s, %s/" % (self.address,
                                   "%d bytes" % self.size if self.size is not None else "size unknown",
                                   self.sort
                                   )

    def copy(self):
        """
        Make a copy of the MemoryData.

        :return: A copy of the MemoryData instance.
        :rtype: MemoryData
        """
        s = MemoryData(self.address, self.size, self.sort, pointer_addr=self.pointer_addr, max_size=self.max_size)
        s.content = self.content

        return s

    def fill_content(self, loader):
        """
        Load data to fill self.content.

        :param loader:  The project loader.
        :return:        None
        """

        if self.sort == MemoryDataSort.String:
            self.content = loader.memory.load(self.addr, self.size)
            if self.content.endswith(b"\x00"):
                self.content = self.content.strip(b"\x00")
        else:
            # FIXME: Other types are not supported yet
            return

    #
    # Serialization
    #

    @classmethod
    def _get_cmsg(cls):
        return cfg_pb2.MemoryData()

    def serialize_to_cmessage(self):
        cmsg = self._get_cmsg()
        cmsg.ea = self.addr
        cmsg.size = self.size if self.size is not None else 0
        cmsg.type = _SORT_TO_IDX[self.sort]
        return cmsg

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        md = cls(cmsg.ea, cmsg.size, _IDX_TO_SORT[cmsg.type])
        return md
