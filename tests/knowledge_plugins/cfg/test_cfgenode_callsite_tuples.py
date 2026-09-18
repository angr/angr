#!/usr/bin/env python3
# pylint:disable=missing-class-docstring
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.cfg"  # pylint:disable=redefined-builtin

import unittest

from angr.knowledge_plugins.cfg.block_id import BlockID
from angr.knowledge_plugins.cfg.cfg_node import CFGENode
from angr.protos import cfg_pb2
from angr.utils.ins_addr_list import InsAddrList


class TestCFGENodeCallsiteTuples(unittest.TestCase):
    @staticmethod
    def _roundtrip(node: CFGENode) -> CFGENode:
        data = node.serialize_to_cmessage().SerializeToString()
        cmsg = cfg_pb2.CFGENode()
        cmsg.ParseFromString(data)
        return CFGENode.parse_from_cmessage(cmsg)

    @staticmethod
    def _node(block_id: BlockID) -> CFGENode:
        return CFGENode(
            0x401000,
            5,
            None,
            block_id=block_id,
            instruction_addrs=InsAddrList(0x401000, b"\x05"),
            callstack_key=(None,),
        )

    def test_block_id_without_callsite_tuples(self):
        node = self._roundtrip(self._node(BlockID(0x401000, None, "normal")))
        assert isinstance(node.block_id, BlockID)
        assert node.block_id.addr == 0x401000
        assert node.block_id.callsite_tuples is None
        assert node.block_id.jump_type == "normal"

    def test_block_id_with_callsite_tuples(self):
        node = self._roundtrip(self._node(BlockID(0x401000, (0x400500, None, 0x400600, 0x400700), "call")))
        assert isinstance(node.block_id, BlockID)
        assert node.block_id.callsite_tuples == (0x400500, None, 0x400600, 0x400700)
        assert node.block_id.jump_type == "call"


if __name__ == "__main__":
    unittest.main()
