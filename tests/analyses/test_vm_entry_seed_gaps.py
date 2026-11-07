#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import pickle
import tempfile
import unittest
from unittest import mock

import networkx
import pyvex

import angr
from angr.analyses.vm_deobfuscation.entry_seeds import seeded_fold_enabled, seeds_for_block_id
from angr.analyses.vm_deobfuscation.vm_deobfuscation import VMDeobfuscation
from angr.knowledge_plugins.cfg.block_id import BlockID
from angr.knowledge_plugins.cfg.cfg_node import CFGENode

SEEDS = {("vip", 64, 8): 0x1100}


class _CFG:
    def __init__(self, project=None):
        self.graph = networkx.DiGraph()
        self.project = project

    def add_node(self, block_id, node):
        pass

    def remove_node(self, block_id, node):
        pass


def _project():
    return angr.load_shellcode(b"\x90" * 0x40, "AMD64", load_address=0x1000)


def _analysis(project):
    self = VMDeobfuscation.__new__(VMDeobfuscation)
    self.project = project
    self.start_addr = self.vm_start_addr = 0x1000
    self.deobfuscation_start_addr = self.deobfuscation_end_addr = None
    self.vm_function_extent = self.vm_entry_sites = None
    return self


class TestOldCheckpointTurnsSeedingOff(unittest.TestCase):
    def _resume(self, keep_seeds):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"PUSHAN_CHECKPOINT_DIR": d}):
            p = _project()
            a = _analysis(p)
            assert a._checkpoint_load("data_sens_cfg") is None
            p.vm_entry_seeds[BlockID(0x1000, None, "normal", vm_vpc=7)] = dict(SEEDS)
            a._checkpoint_save(_CFG(), "data_sens_cfg")
            path = a._checkpoint_path("data_sens_cfg")
            if not keep_seeds:
                # a checkpoint written before entry seeds were recorded
                with open(path, "rb") as f:
                    saved = pickle.load(f)
                del saved["project_attrs"]["vm_entry_seeds"]
                with open(path, "wb") as f:
                    pickle.dump(saved, f)
            p2 = _project()
            assert _analysis(p2)._checkpoint_load("data_sens_cfg") is not None
            return p2

    def test_checkpoint_with_seeds_keeps_seeding_on(self):
        assert seeded_fold_enabled(self._resume(keep_seeds=True))

    def test_checkpoint_without_seeds_turns_seeding_off(self):
        assert not seeded_fold_enabled(self._resume(keep_seeds=False))


class TestSplitCopiesAreNotSeeded(unittest.TestCase):
    def test_synthesized_block_ids_have_no_seeds(self):
        p = _project()
        a = _analysis(p)
        cfg = _CFG(p)
        irsb = p.factory.block(0x1000, 1).vex

        def node(addr, vpc):
            return CFGENode(addr, 1, cfg, block_id=BlockID(addr, None, "normal", vm_vpc=vpc), irsb=irsb,
                            instruction_addrs=[addr], function_address=0x1000)

        pred, start, other, end, after = (node(0x1000 + i, 0x100 + i) for i in range(5))
        for src, dst in ((pred, start), (start, other), (start, end), (end, after)):
            cfg.graph.add_edge(src, dst, jumpkind="Ijk_Boring")
        # the copies of start and end land on block ids that exploration also reached
        off = 0x10
        copies = [BlockID(n.addr, None, "normal", vm_vpc=n.block_id.vm_vpc + off) for n in (start, end)]
        for bid in copies:
            p.vm_entry_seeds[bid] = dict(SEEDS)
        a.split_redundant_branch_obf(cfg, [(start, end, chr(off))])
        new_ids = {n.block_id for n in cfg.graph.nodes()} - {pred.block_id, other.block_id, after.block_id}
        assert new_ids == set(copies)
        assert all(seeds_for_block_id(p, bid) is None for bid in copies)


if __name__ == "__main__":
    unittest.main()
