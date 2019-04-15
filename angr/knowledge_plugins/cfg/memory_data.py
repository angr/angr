# pylint:disable=no-member
from ...protos import primitives_pb2, cfg_pb2
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
}

_IDX_TO_SORT = dict((v, k) for k, v in _SORT_TO_IDX.items())


class CodeReference(Serializable):
    """
    CodeReference describes a reference to a MemoryData instance.
    """

    __slots__ = ('insn_addr', 'block_addr', 'stmt_idx', 'insn_op_idx', 'insn_op_type', 'memory_data')

    def __init__(self, insn_addr, block_addr, stmt_idx, insn_op_idx=None, memory_data=None):
        self.insn_addr = insn_addr
        self.insn_op_idx = insn_op_idx
        self.block_addr = block_addr
        self.stmt_idx = stmt_idx
        self.memory_data = memory_data

    def __repr__(self):
        return "Ref@%#x" % self.insn_addr

    @classmethod
    def _get_cmsg(cls):
        return primitives_pb2.CodeReference()

    def serialize_to_cmessage(self):
        cmsg = self._get_cmsg()
        if self.memory_data is not None:
            cmsg.target_type = primitives_pb2.CodeTarget if self.memory_data.sort == MemoryDataSort.CodeReference \
                else primitives_pb2.DataTarget
            cmsg.location = primitives_pb2.Internal
            cmsg.data_ea = self.memory_data.addr
        else:
            cmsg.data_ea = -1
        if self.insn_op_idx is None:
            cmsg.operand_idx = -1
        else:
            cmsg.operand_idx = self.insn_op_idx
        cmsg.ea = self.insn_addr
        cmsg.block_ea = self.block_addr
        cmsg.stmt_idx = self.stmt_idx
        return cmsg

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        # Note that we cannot recover _memory_data from cmsg
        cr = CodeReference(cmsg.ea, cmsg.block_ea, cmsg.stmt_idx,
                           insn_op_idx=None if cmsg.operand_idx == -1 else cmsg.opearnd_idx)
        return cr

    def copy(self):
        cr = CodeReference(self.insn_addr, self.block_addr, self.stmt_idx, insn_op_idx=self.insn_op_idx,
                           memory_data=self.memory_data)
        return cr


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

    #
    # Serialization
    #

    @classmethod
    def _get_cmsg(cls):
        return cfg_pb2.MemoryData()

    def serialize_to_cmessage(self):
        cmsg = self._get_cmsg()
        cmsg.ea = self.addr
        cmsg.size = self.size
        cmsg.type = _SORT_TO_IDX[self.sort]
        return cmsg

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        md = cls(cmsg.ea, cmsg.size, _IDX_TO_SORT[cmsg.type])
        return md
