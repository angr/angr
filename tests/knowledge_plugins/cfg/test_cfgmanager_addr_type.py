# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import pickle
from unittest import TestCase, main

from angr.knowledge_plugins.cfg.block_id import BlockID
from angr.knowledge_plugins.cfg.cfg_manager import CFGManager
from angr.knowledge_plugins.cfg.cfg_node import CFGENode
from angr.knowledge_plugins.cfg.spilling_cfg import _ObjKeys


class TestCFGManagerNewCFGModelAddrType(TestCase):
    """Verify that new_model propagates addr_type correctly."""

    def test_new_model_first_call_sets_addr_type(self):
        """new_model should set addr_type even when the prefix doesn't exist yet (first call)."""
        manager = CFGManager(None)  # type: ignore
        model = manager.new_model("CFGEmulated", addr_type="block_id")
        assert model.addr_type == "block_id"

    def test_new_model_second_call_sets_addr_type(self):
        """new_model should set addr_type when the prefix already exists (subsequent calls)."""
        manager = CFGManager(None)  # type: ignore
        # first call
        manager.new_model("CFGEmulated", addr_type="block_id")
        # second call
        model2 = manager.new_model("CFGEmulated", addr_type="block_id")
        assert model2.addr_type == "block_id"

    def test_graph_addr_type_matches_model(self):
        """The SpillingCFG and its key table should inherit addr_type from the model."""
        manager = CFGManager(None)  # type: ignore
        model = manager.new_model("CFGEmulated", addr_type="block_id")
        assert model.graph.addr_type == "block_id"
        assert isinstance(model.graph._keys, _ObjKeys)

    def test_block_id_keys_round_trip(self):
        """Edges between BlockID-keyed nodes survive a pickle round trip."""
        manager = CFGManager(None)  # type: ignore
        model = manager.new_model("CFGEmulated", addr_type="block_id")
        src = CFGENode(0x400FF0, 0x10, model, block_id=BlockID(0x400FF0, None, "normal"))
        dst = CFGENode(0x401000, 0x10, model, block_id=BlockID(0x401000, None, "normal"))
        model.graph.add_edge(src, dst, jumpkind="Ijk_Boring", ins_addr=0x400FFC, stmt_idx=0)
        restored = pickle.loads(pickle.dumps(model))
        assert [(s.addr, d.addr, data) for s, d, data in restored.graph.edges(data=True)] == [
            (0x400FF0, 0x401000, {"jumpkind": "Ijk_Boring", "ins_addr": 0x400FFC, "stmt_idx": 0})
        ]


if __name__ == "__main__":
    main()
