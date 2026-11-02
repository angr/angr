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

import angr
from angr.analyses.vm_deobfuscation.vm_deobfuscation import VMDeobfuscation
from angr.knowledge_plugins.cfg.block_id import BlockID

from ..common import bin_location


class _Node:
    def __init__(self, block_id):
        self.addr = block_id.addr
        self.block_id = block_id


class _CFG:
    def __init__(self, nodes):
        self.graph = networkx.DiGraph()
        self.graph.add_nodes_from(nodes)


def _project():
    return angr.Project(os.path.join(bin_location, "tests", "x86_64", "fauxware"), auto_load_libs=False)


def _analysis(project):
    self = VMDeobfuscation.__new__(VMDeobfuscation)
    self.project = project
    self.start_addr = self.vm_start_addr = 0x400580
    self.deobfuscation_start_addr = self.deobfuscation_end_addr = None
    self.vm_function_extent = self.vm_entry_sites = None
    return self


class TestCheckpointResume(unittest.TestCase):
    def test_phase_side_effects_restored(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"PUSHAN_CHECKPOINT_DIR": d}):
            p = _project()
            a = _analysis(p)
            assert a._checkpoint_load("data_sens_cfg") is None
            # what the data-sensitive CFG leaves on the project
            bid = BlockID(0x400580, None, "normal", vm_vpc=7)
            p.bt_ins_addrs.add(0x400590)
            p.updated_block_id_map[bid] = bid
            p.vm_sp_start_value = 0x7FFF0000
            p.hook(0x400600, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())
            p.kb.functions.function(0x400580, create=True)
            p.kb.functions.callgraph.add_edge(0x400580, 0x400600, key=0, type="call")
            a._checkpoint_save(_CFG([_Node(bid)]), "data_sens_cfg")

            p2 = _project()
            cfg = _analysis(p2)._checkpoint_load("data_sens_cfg")
            assert cfg is not None and cfg.graph.number_of_nodes() == 1
            assert p2.bt_ins_addrs == {0x400590}
            assert p2.vm_sp_start_value == 0x7FFF0000
            # a freshly built key must find the restored entry
            assert BlockID(0x400580, None, "normal", vm_vpc=7) in p2.updated_block_id_map
            assert p2.is_hooked(0x400600)
            assert 0x400580 in p2.kb.functions and p2.kb.functions[0x400580].project is p2
            assert p2.kb.functions.callgraph.has_edge(0x400580, 0x400600, 0)

    def test_bare_cfg_checkpoint_recomputed(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"PUSHAN_CHECKPOINT_DIR": d}):
            a = _analysis(_project())
            with open(a._checkpoint_path("data_sens_cfg"), "wb") as f:
                pickle.dump(_CFG([]), f)
            assert a._checkpoint_load("data_sens_cfg") is None

    def test_block_id_pickle_drops_cached_hash(self):
        bid = BlockID(0x1000, None, "normal")
        hash(bid)
        assert pickle.loads(pickle.dumps(bid))._hash is None


if __name__ == "__main__":
    unittest.main()
