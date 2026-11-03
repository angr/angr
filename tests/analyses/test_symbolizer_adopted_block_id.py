#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest
from types import SimpleNamespace

import networkx

import angr
from angr.analyses.cfg.vm_cfg_model import VMCFGModel
from angr.analyses.symbolizer.symbolizer import Symbolizer
from angr.knowledge_plugins.cfg.block_id import BlockID
from angr.knowledge_plugins.cfg.cfg_node import CFGENode


class _State:
    def __init__(self, addr, globals_):
        self.addr = addr
        self.globals = globals_
        self.history = SimpleNamespace(jumpkind="Ijk_Boring")

    def copy(self):
        return _State(self.addr, dict(self.globals))


class TestSymbolizerAdoptedBlockId(unittest.TestCase):
    """A node adopted for a recomputed successor gets a block id of its own."""

    def _setup(self):
        proj = angr.load_shellcode(b"\x90" * 0x30, "AMD64", load_address=0x1000)
        model = VMCFGModel("test", cfg_manager=proj.kb.cfgs, addr_type="block_id")
        pred_id = BlockID(0x1000, (0x0, 0x0), "normal", vm_vpc=388176)
        stale_id = BlockID(0x1020, (0x0, 0x0), "normal", vm_vpc=388177)
        pred = CFGENode(0x1000, 4, model, block_id=pred_id)
        stale = CFGENode(0x1020, 4, model, block_id=stale_id)
        g = networkx.DiGraph()
        g.add_edge(pred, stale, jumpkind="Ijk_Boring")
        sym = Symbolizer.__new__(Symbolizer)
        sym.project = proj
        sym._graph = g
        sym._once_only = set()
        sym._shared_block_ids = set()
        return sym, pred, stale

    @staticmethod
    def _succ(addr, cur_block_id):
        return _State(addr, {"cur_block_id": cur_block_id, "cur_vm_vpc": None})

    def _check(self, cur_block_id):
        sym, pred, _ = self._setup()
        succ = self._succ(0x1010, cur_block_id)
        (target,) = sym._adopt_recomputed_successors(pred, [succ])
        self.assertEqual(target.addr, 0x1010)
        self.assertEqual(target.block_id.addr, 0x1010)
        ids = [n.block_id for n in sym._graph.nodes()]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(sym._shared_block_ids, set())
        # the state goes to the new node only, not to the node its stale id names
        self.assertIs(succ.globals["cur_block_id"], target.block_id)

    def test_exit_without_block_id(self):
        # the exit carried no block id: cur_block_id still names the predecessor
        sym, pred, _ = self._setup()
        self._check(pred.block_id)

    def test_exit_with_stale_block_id(self):
        # the exit names the stale graph successor at another address
        _, _, stale = self._setup()
        self._check(stale.block_id)

    def test_keeps_matching_block_id(self):
        sym, pred, _ = self._setup()
        own = BlockID(0x1010, (0x0, 0x0), "normal", vm_vpc=None)
        succ = self._succ(0x1010, own)
        (target,) = sym._adopt_recomputed_successors(pred, [succ])
        self.assertIs(target.block_id, own)
        self.assertIs(succ.globals["cur_block_id"], own)

    def test_existing_node_elsewhere(self):
        # the target already exists, but not as a successor of pred: route to it, not to the stale id
        sym, pred, stale = self._setup()
        other_id = BlockID(0x1010, (0x0, 0x0), "normal", vm_vpc=None)
        other = CFGENode(0x1010, 4, pred._cfg_model, block_id=other_id)
        sym._graph.add_node(other)
        succ = self._succ(0x1010, stale.block_id)
        (target,) = sym._adopt_recomputed_successors(pred, [succ])
        self.assertIs(target, other)
        self.assertIs(succ.globals["cur_block_id"], other_id)


if __name__ == "__main__":
    unittest.main()
