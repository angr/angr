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
    ELFHeader = "elf-header"
    FloatingPoint = "fp"  # the size is determined by the MemoryData itself


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

_IDX_TO_SORT = {v: k for k, v in _SORT_TO_IDX.items()}


class MemoryData(Serializable):
    """
    MemoryData describes the syntactic content of a single address of memory.

    `reference_size` reflects the size of `content`. It can be different from `size`, which is the actual size of the
    memory data item in memory. The intended way to get the actual content in memory is `self.content[:self.size]`.
    """

    __slots__ = (
        "addr",
        "size",
        "reference_size",
        "sort",
        "max_size",
        "pointer_addr",
        "content",
    )

    def __init__(
        self,
        address: int,
        size: int,
        sort: str | None,  # temporary type
        pointer_addr: int | None = None,
        max_size: int | None = None,
        reference_size: int | None = None,
    ):
        self.addr: int = address
        self.size: int = size
        self.reference_size: int = reference_size
        self.sort: str | None = sort

        self.max_size: int | None = max_size
        self.pointer_addr: int | None = pointer_addr

        self.content: bytes | None = None  # temporary annotation

    def __eq__(self, other: "MemoryData"):
        return (
            self.addr == other.addr
            and self.size == other.size
            and self.reference_size == other.reference_size
            and self.sort == other.sort
            and self.max_size == other.max_size
            and self.pointer_addr == other.pointer_addr
            and self.content == other.content
        )

    @property
    def address(self):
        return self.addr

    def __repr__(self):
        return "\\{:#x}, {}, {}/".format(
            self.address, "%d bytes" % self.size if self.size is not None else "size unknown", self.sort
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
            self.content = loader.memory.load(
                self.addr, self.reference_size if self.reference_size is not None else self.size
            )
            if self.content.endswith(b"\x00"):
                self.content = self.content.strip(b"\x00")
        elif self.sort == MemoryDataSort.UnicodeString:
            self.content = loader.memory.load(
                self.addr, self.reference_size if self.reference_size is not None else self.size
            )
            if self.content.endswith(b"\x00\x00"):
                self.content = self.content[:-2]
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
        if self.size is not None:
            cmsg.size = self.size
        if self.reference_size is not None:
            cmsg.reference_size = self.reference_size
        cmsg.type = _SORT_TO_IDX[self.sort]
        return cmsg

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        md = cls(
            cmsg.ea,
            cmsg.size if cmsg.HasField("size") else None,
            _IDX_TO_SORT[cmsg.type],
            reference_size=cmsg.reference_size if cmsg.HasField("reference_size") else None,
        )
        return md
