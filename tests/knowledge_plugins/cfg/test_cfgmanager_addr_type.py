# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

from unittest import main, TestCase

from angr.knowledge_plugins.cfg.cfg_manager import CFGManager
from angr.knowledge_plugins.cfg.block_id import BlockID
from angr.knowledge_plugins.cfg.spilling_digraph import SpillingAdjDict, DirtyDict


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
        """The SpillingCFG and underlying SpillingDiGraph should inherit addr_type from the model."""
        manager = CFGManager(None)  # type: ignore
        model = manager.new_model("CFGEmulated", addr_type="block_id")
        assert model.graph.addr_type == "block_id"
        assert model.graph._graph.addr_type == "block_id"

    @staticmethod
    def _make_block_id_key(addr):
        bid = BlockID(addr, callsite_tuples=None, jump_type="normal")
        return bid, 0x10, 0

    def test_serialize_with_correct_addr_type(self):
        """Serialization works when addr_type='block_id' matches the key type."""
        adj = SpillingAdjDict(addr_type="block_id")
        inner = DirtyDict(dirty=True)
        dst_key = self._make_block_id_key(0x401000)
        inner[dst_key] = {"jumpkind": "Ijk_Boring", "ins_addr": 0x400FFC, "stmt_idx": 0}

        data = adj._serialize_inner_dict(inner)
        assert isinstance(data, bytes)
        assert len(data) > 0


if __name__ == "__main__":
    main()
