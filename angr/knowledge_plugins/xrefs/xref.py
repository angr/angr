
from .xref_types import XRefType
from ...serializable import Serializable
from ...protos import primitives_pb2


class XRef(Serializable):
    """
    XRef describes a reference to a MemoryData instance (if a MemoryData instance is available) or just an address.
    """

    __slots__ = ('ins_addr', 'block_addr', 'stmt_idx', 'insn_op_idx', 'insn_op_type', 'memory_data', 'dst', 'type', )

    def __init__(self, ins_addr=None, block_addr=None, stmt_idx=None, insn_op_idx=None, memory_data=None, dst=None,
                 xref_type=None):

        # src
        self.ins_addr = ins_addr
        self.insn_op_idx = insn_op_idx
        self.block_addr = block_addr
        self.stmt_idx = stmt_idx

        # dst
        self.memory_data = memory_data  # optional
        self.dst = dst
        self.type = xref_type

        if memory_data is not None and dst is None:
            self.dst = memory_data.addr

    @property
    def type_string(self):
        return XRefType.to_string(self.type)

    def __repr__(self):
        return "<XRef %s: %s->%s>" % (
                XRefType.to_string(self.type),
                "%#x" % self.ins_addr if self.ins_addr is not None else "%#x[%d]" % (self.block_addr, self.stmt_idx),
                "%#x" % (self.dst if self.dst is not None else self.memory_data.addr)
        )

    def __eq__(self, other):
        return type(other) is XRef and \
               other.type == self.type and \
               other.ins_addr == self.ins_addr and \
               other.dst == self.dst

    def __hash__(self):
        return hash((XRef, self.type, self.ins_addr, self.dst))

    @classmethod
    def _get_cmsg(cls):
        return primitives_pb2.CodeReference()

    def serialize_to_cmessage(self):
        # pylint:disable=no-member
        cmsg = self._get_cmsg()
        if self.memory_data is not None:
            cmsg.target_type = primitives_pb2.CodeReference.CodeTarget \
                if self.memory_data.sort == MemoryDataSort.CodeReference else primitives_pb2.CodeReference.DataTarget
            cmsg.location = primitives_pb2.CodeReference.Internal
            cmsg.data_ea = self.memory_data.addr
        elif self.dst is not None:
            cmsg.data_ea = self.dst
        else:
            # Unknown... why?
            cmsg.data_ea = -1
        if self.insn_op_idx is None:
            cmsg.operand_idx = -1
        else:
            cmsg.operand_idx = self.insn_op_idx
        cmsg.ea = self.ins_addr
        cmsg.block_ea = self.block_addr
        cmsg.stmt_idx = self.stmt_idx
        cmsg.ref_type = self.type
        return cmsg

    @classmethod
    def parse_from_cmessage(cls, cmsg, **kwargs):
        # Note that we cannot recover _memory_data from cmsg
        cr = XRef(ins_addr=cmsg.ea, block_addr=cmsg.block_ea, stmt_idx=cmsg.stmt_idx,
                  insn_op_idx=None if cmsg.operand_idx == -1 else cmsg.opearnd_idx,
                  dst=cmsg.data_ea, xref_type=cmsg.ref_type)
        return cr

    def copy(self):
        cr = XRef(ins_addr=self.ins_addr, block_addr=self.block_addr, stmt_idx=self.stmt_idx,
                  insn_op_idx=self.insn_op_idx, memory_data=self.memory_data, dst=self.dst, xref_type=self.type)
        return cr


from ..cfg.memory_data import MemoryDataSort
