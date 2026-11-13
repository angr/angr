#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os.path
import unittest
from unittest import mock

import angr
from angr.analyses.cfg.cfg_fast import CFGFast
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestConstResolver(unittest.TestCase):
    def test_resolving_arm_bx_r9(self):
        bin_path = os.path.join(test_location, "armhf", "amp_challenge_10.gcc")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(
            regions=[(0x40400C, 0x4041EE), (0x404F04, 0x404F20)], function_starts=[0x40400D], start_at_entry=False
        )

        b0 = cfg.model.get_any_node(0x404F15)
        assert b0 is not None
        b0_successors = list(cfg.model.get_successors(b0))
        assert len(b0_successors) == 1
        assert b0_successors[0].addr == 0x404133

        b1 = cfg.model.get_any_node(0x404F1B)
        assert b1 is not None
        b1_successors = list(cfg.model.get_successors(b1))
        assert len(b1_successors) == 1
        assert b1_successors[0].addr == 0x40402D

    def test_full_propagation_without_target_skips_the_slice(self):
        # the Rust ConstantResolver answers Unresolved without slicing when a full-function FCP has no valid target;
        # the Python resolver (which always slices) must agree
        bin_path = os.path.join(test_location, "mips", "ld.so.1")

        def run(kinds):
            proj = angr.Project(bin_path, auto_load_libs=False)
            with mock.patch.object(CFGFast, "_rust_ijr_kinds", kinds):
                cfg = proj.analyses.CFGFast(normalize=True)
            ijs = sorted(
                (a, j.func_addr, j.jumpkind, sorted(j.resolved_targets), str(j.type))
                for a, j in cfg.indirect_jumps.items()
            )
            edges = sorted((s.addr, d.addr, data["jumpkind"]) for s, d, data in cfg.graph.edges(data=True))
            return cfg, ijs, edges

        cfg_rust, ijs_rust, edges_rust = run(CFGFast._rust_ijr_kinds)
        assert cfg_rust._ijr_stats.get("ConstantResolver:full_fcp_unresolved", 0) > 0
        cfg_py, ijs_py, edges_py = run(CFGFast._rust_ijr_kinds - {"ConstantResolver"})
        assert cfg_py._ijr_stats.get("ConstantResolver:rust", 0) == 0
        assert ijs_rust == ijs_py
        assert edges_rust == edges_py


if __name__ == "__main__":
    unittest.main()
