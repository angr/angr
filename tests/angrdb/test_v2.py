#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
"""
A version-2 CFG record (nodes plus one Edge message per edge, no graph segments) loads through AngrDbV2 on both the
resident and the spilled node path and yields the same graph as the live model.
"""

from __future__ import annotations

import os
import unittest

import angr
from angr.angrdb.v2 import AngrDbV2
from angr.knowledge_plugins.cfg.cfg_model import CFGModel
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _edges(model: CFGModel) -> set[tuple]:
    return {
        (src.addr, dst.addr, data.get("jumpkind"), data.get("ins_addr"), data.get("stmt_idx"))
        for src, dst, data in model.graph.edges(data=True)
    }


class TestAngrDbV2(unittest.TestCase):
    def test_v2_cfg_record_round_trips(self):
        binary = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(binary, auto_load_libs=False)
        model = proj.analyses.CFGFast(normalize=True).model
        assert len(model.graph) > 0 and len(model.graph.edges) > 0

        cmsg = AngrDbV2.serialize_cfg(model)
        assert not cmsg.graph_header and not cmsg.graph_segments
        assert len(cmsg.edges) == len(model.graph.edges)

        # resident node path: no project, plain CFGNode objects
        loaded = CFGModel.parse_from_cmessage(cmsg)
        assert {n.addr for n in loaded.nodes()} == {n.addr for n in model.nodes()}
        assert _edges(loaded) == _edges(model)

        # spilled node path: bulk-imported node bytes, edges resolved through the key table
        spilling = angr.Project(binary, auto_load_libs=False, cache_limits={"cfg_nodes": 5})
        loaded = CFGModel.parse_from_cmessage(cmsg, cfg_manager=spilling.kb.cfgs)
        assert loaded.graph.spilled_count > 0
        assert {n.addr for n in loaded.nodes()} == {n.addr for n in model.nodes()}
        assert _edges(loaded) == _edges(model)


if __name__ == "__main__":
    unittest.main()
