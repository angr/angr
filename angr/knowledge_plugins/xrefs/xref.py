from __future__ import annotations
from ...serializable import Serializable
from ...protos import primitives_pb2
from .xref_types import XRefType


class XRef(Serializable):
    """
    XRef describes a reference to a MemoryData instance (if a MemoryData instance is available) or just an address.
    """

    __slots__ = (
        "ins_addr",
        "block_addr",
        "stmt_idx",
        "insn_op_idx",
        "insn_op_type",
        "memory_data",
        "dst",
        "type",
    )

    def __init__(
        self,
        ins_addr: int | None = None,
        block_addr: int | None = None,
        stmt_idx: int | None = None,
        insn_op_idx: int | None = None,
        memory_data=None,
        dst: int | None = None,
        xref_type=None,
    ):
        if dst is not None and not isinstance(dst, int):
            raise TypeError(f"XRefs must be pointing to a constant target. Target {dst!r} is not supported.")

        # src
        self.ins_addr: int | None = ins_addr
        self.insn_op_idx: int | None = insn_op_idx
        self.block_addr: int | None = block_addr
        self.stmt_idx: int | None = stmt_idx

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
        if self.dst is not None:
            dst_str = hex(self.dst) if isinstance(self.dst, int) else str(self.dst)
        elif self.memory_data is not None:
            dst_str = hex(self.memory_data.addr)
        else:
            dst_str = "unknown"
        return "<XRef {}: {}->{}>".format(
            self.type_string,
            f"{self.ins_addr:#x}" if self.ins_addr is not None else "%#x[%d]" % (self.block_addr, self.stmt_idx),
            dst_str,
        )

    def __eq__(self, other):
        return (
            type(other) is XRef
            and other.type == self.type
            and other.ins_addr == self.ins_addr
            and other.dst == self.dst
        )

    def __hash__(self):
        return hash((XRef, self.type, self.ins_addr, self.dst))

    @classmethod
    def _get_cmsg(cls):
        return primitives_pb2.CodeReference()

    def serialize_to_cmessage(self):
        # pylint:disable=no-member

        # delayed import
        from ...engines.light import SpOffset  # pylint:disable=import-outside-toplevel

        cmsg = self._get_cmsg()
        if self.memory_data is not None:
            # determine target_type from memory_data.sort
            if self.memory_data.sort == MemoryDataSort.CodeReference:
                cmsg.target_type = primitives_pb2.CodeReference.CodeTarget
            else:
                cmsg.target_type = primitives_pb2.CodeReference.DataTarget

            cmsg.location = primitives_pb2.CodeReference.Internal
            cmsg.data_ea = self.memory_data.addr
        elif self.dst is not None:
            if isinstance(self.dst, SpOffset):
                cmsg.target_type = primitives_pb2.CodeReference.StackTarget
                cmsg.data_ea = self.dst.offset
            else:
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
    def parse_from_cmessage(cls, cmsg, bits=None, **kwargs):  # pylint:disable=arguments-differ
        # Note that we cannot recover _memory_data from cmsg

        # delayed import
        from ...engines.light import SpOffset  # pylint:disable=import-outside-toplevel

        if not isinstance(bits, int):
            raise TypeError("bits must be provided.")

        if cmsg.target_type == primitives_pb2.CodeReference.StackTarget:  # pylint:disable=no-member
            dst = SpOffset(bits, cmsg.data_ea, is_base=False)
        else:
            dst = cmsg.data_ea

        return XRef(
            ins_addr=cmsg.ea,
            block_addr=cmsg.block_ea,
            stmt_idx=cmsg.stmt_idx,
            insn_op_idx=None if cmsg.operand_idx == -1 else cmsg.operand_idx,
            dst=dst,
            xref_type=cmsg.ref_type,
        )

    def copy(self):
        return XRef(
            ins_addr=self.ins_addr,
            block_addr=self.block_addr,
            stmt_idx=self.stmt_idx,
            insn_op_idx=self.insn_op_idx,
            memory_data=self.memory_data,
            dst=self.dst,
            xref_type=self.type,
        )


from ..cfg.memory_data import MemoryDataSort
