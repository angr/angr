#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"  # pylint:disable=redefined-builtin

import os
import unittest

from archinfo import ArchAMD64

import angr
from angr.utils.constants import DEFAULT_STATEMENT

from ...common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestFunctionManager(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)

    def test_amd64(self):
        expected_functions = {
            0x4004E0,
            0x400510,
            0x400520,
            0x400530,
            0x400540,
            0x400550,
            0x400560,
            0x400570,
            0x400580,
            0x4005AC,
            0x400640,
            0x400664,
            0x4006ED,
            0x4006FD,
            0x40071D,
            0x4007E0,
            0x400880,
        }
        expected_blocks = {
            0x40071D,
            0x40073E,
            0x400754,
            0x40076A,
            0x400774,
            0x40078A,
            0x4007A0,
            0x4007B3,
            0x4007C7,
            0x4007C9,
            0x4007BD,
            0x4007D3,
        }
        expected_callsites = {0x40071D, 0x40073E, 0x400754, 0x40076A, 0x400774, 0x40078A, 0x4007A0, 0x4007BD, 0x4007C9}
        expected_callsite_targets = {4195600, 4195632, 4195940, 4196077, 4196093}
        expected_callsite_returns = {
            0x40073E,
            0x400754,
            0x40076A,
            0x400774,
            0x40078A,
            0x4007A0,
            0x4007B3,
            0x4007C7,
            None,
        }

        self.project.analyses.CFGEmulated()
        assert {k for k in self.project.kb.functions if k < 0x500000} == expected_functions

        main = self.project.kb.functions.function(name="main")
        assert main.startpoint.addr == 0x40071D
        assert set(main.block_addrs) == expected_blocks
        assert [bl.addr for bl in main.endpoints] == [0x4007D3]
        assert set(main.get_call_sites()) == expected_callsites
        assert set(map(main.get_call_target, main.get_call_sites())) == expected_callsite_targets
        assert set(map(main.get_call_return, main.get_call_sites())) == expected_callsite_returns
        assert main.has_return

        rejected = self.project.kb.functions.function(name="rejected")
        assert rejected.returning is False

        # transition graph
        main_g = main.transition_graph
        main_g_edges_ = main_g.edges(data=True)

        # Convert nodes those edges from blocks to addresses
        main_g_edges = []
        for src_node, dst_node, data in main_g_edges_:
            main_g_edges.append((src_node.addr, dst_node.addr, data))

        edges = [
            (0x40071D, 0x400510, {"type": "call", "stmt_idx": DEFAULT_STATEMENT, "ins_addr": 0x400739}),
            (0x40071D, 0x400510, {"type": "call", "stmt_idx": DEFAULT_STATEMENT, "ins_addr": 0x400739}),
            (0x40071D, 0x40073E, {"type": "fake_return", "confirmed": True, "outside": False}),
            (0x40073E, 0x400530, {"type": "call", "stmt_idx": DEFAULT_STATEMENT, "ins_addr": 0x40074F}),
            (0x40073E, 0x400754, {"type": "fake_return", "confirmed": True, "outside": False}),
            # rejected() does not return
            (0x4007C9, 0x4006FD, {"type": "call", "stmt_idx": DEFAULT_STATEMENT, "ins_addr": 0x4007CE}),
            (0x4007C9, 0x4007D3, {"type": "fake_return", "outside": False}),
        ]
        for edge in edges:
            assert edge in main_g_edges

        # These tests fail for reasons of fastpath, probably
        # assert main.bp_on_stack
        # assert main.name == 'main'
        # assert main.retaddr_on_stack
        # assert 0x50 == main.sp_difference

        # TODO: Check the result returned
        # func_man.dbg_draw()

    def test_call_to(self):
        self.project.arch = ArchAMD64()

        self.project.kb.functions._add_call_to(0x400000, 0x400410, 0x400420, 0x400414)
        assert 0x400000 in self.project.kb.functions
        assert 0x400420 in self.project.kb.functions

    def test_query(self):
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True, data_references=True)

        assert proj.kb.functions["::read"].addr == 0x400530
        assert proj.kb.functions["::0x400530::read"].addr == 0x400530
        assert proj.kb.functions["::libc.so.0::read"].addr == 0x700010
        with self.assertRaises(KeyError):
            proj.kb.functions["::0x400531::read"]  # pylint:disable=pointless-statement
        with self.assertRaises(KeyError):
            proj.kb.functions["::bad::read"]  # pylint:disable=pointless-statement


if __name__ == "__main__":
    unittest.main()
