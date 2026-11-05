#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest
from collections import namedtuple
from types import SimpleNamespace

import networkx as nx

import angr
from angr import claripy
from angr.analyses.cfg.cfg_vm_deobfuscation import CFGVMDeobfuscation
from angr.analyses.symbolizer.symbolizer import Symbolizer
from angr.analyses.vm_deobfuscation.vm_deobfuscation import AndingSimSolver
from angr.knowledge_plugins.cfg.block_id import BlockID
from angr.storage.memory_mixins.eval_top_merger_mixin import EvalTopMergerMixin
from angr.storage.memory_mixins.paged_memory.pages.list_page import ListPage
from angr.storage.memory_object import SimMemoryObject

_Node = namedtuple("_Node", ["addr", "block_id"])

# a VM branch on an argument check (CNIC sub_275a4): the traced target and the common error target
TRACED, UNTRACED = 0x4F618, 0x6E362


class TestVipPin(unittest.TestCase):
    """The symbolizer pins a VM branch the VM-CFG traced on one side only to that side."""

    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90" * 16, "AMD64", load_address=0x1000)
        self.rsi = self.proj.arch.registers["rsi"]
        self.bid = BlockID(0x236F4, (), "normal", 325143)

    def _state(self):
        s = self.proj.factory.blank_state(addr=0x1000, mode="fastpath")
        s.register_plugin(
            "partial_symbolic_constraint_solver", AndingSimSolver(claripy.SolverReplacement(auto_replace=False))
        )
        s.globals["existing_mba_split_constraints"] = []
        s.globals["last_added_state_split_cond"] = None
        return s

    def _symbolizer(self, graph=None):
        fake = SimpleNamespace(project=self.proj, _graph=graph)
        fake._entry_vip = lambda block_id, state: Symbolizer._entry_vip(fake, block_id, state)
        return fake

    def test_cfg_records_the_entry_vip(self):
        cfgvm = CFGVMDeobfuscation.__new__(CFGVMDeobfuscation)
        cfgvm.project = self.proj
        s = self._state()
        s.globals["cur_vm_reg"] = self.rsi
        s.regs.rsi = TRACED
        cfgvm._record_block_entry_vip(self.bid, s)
        assert self.proj.vip_at_block_entry[self.bid] == (*self.rsi, TRACED)
        # a VIP the VM-CFG has not decided is not recorded
        other = BlockID(0x236F4, (), "normal", 325144)
        s.regs.rsi = claripy.If(claripy.BoolS("mba_state_split_cond_1"), claripy.BVV(TRACED, 64), claripy.BVV(UNTRACED, 64))
        cfgvm._record_block_entry_vip(other, s)
        assert other not in self.proj.vip_at_block_entry

    def test_pin_to_the_traced_target(self):
        self.proj.vip_at_block_entry[self.bid] = (*self.rsi, TRACED)
        c1 = claripy.BoolS("mba_state_split_cond_1")
        c2 = claripy.BoolS("mba_state_split_cond_2")
        s = self._state()
        s.globals["cur_block_id"] = self.bid
        s.globals["last_added_state_split_cond"] = c2
        s.regs.rsi = claripy.If(c1, claripy.BVV(0x501A1, 64), claripy.If(c2, claripy.BVV(TRACED, 64), claripy.BVV(UNTRACED, 64)))
        Symbolizer._pin_vip_to_label(self._symbolizer(), s)
        solver = s.partial_symbolic_constraint_solver
        assert solver.eval_upto(s.regs.rsi, 3) == [TRACED]
        assert solver.eval_upto(c1, 2) == [False] and solver.eval_upto(c2, 2) == [True]
        assert sorted(s.globals["existing_mba_split_constraints"]) == [c1.args[0], c2.args[0]]
        assert s.globals["last_added_state_split_cond"] is None

    def test_no_pin_off_the_traced_targets(self):
        self.proj.vip_at_block_entry[self.bid] = (*self.rsi, TRACED)
        c1 = claripy.BoolS("mba_state_split_cond_1")
        s = self._state()
        s.globals["cur_block_id"] = self.bid
        s.regs.rsi = claripy.If(c1, claripy.BVV(0x501A1, 64), claripy.BVV(UNTRACED, 64))
        Symbolizer._pin_vip_to_label(self._symbolizer(), s)
        assert len(s.partial_symbolic_constraint_solver.eval_upto(s.regs.rsi, 3)) == 2

    def test_successors_at_one_address_are_told_apart_by_their_entry_vip(self):
        node = BlockID(0x22553, (), "normal", 325140)
        succs = [_Node(0x236F4, BlockID(0x236F4, (), "normal", v)) for v in (325143, 457570)]
        graph = nx.DiGraph()
        for succ in succs:
            graph.add_edge(node, succ)
        self.proj.vip_at_block_entry[succs[0].block_id] = (*self.rsi, TRACED)
        self.proj.vip_at_block_entry[succs[1].block_id] = (*self.rsi, UNTRACED)
        for vip, expected in ((TRACED, succs[0]), (UNTRACED, succs[1])):
            s = self._state()
            s.regs.rsi = vip
            assert Symbolizer._graph_succ_for_state(self._symbolizer(graph), node, s, 0x236F4) is expected

    def test_a_node_without_graph_successors_names_none(self):
        node = BlockID(0x401A41, (), "normal", None)
        graph = nx.DiGraph()
        graph.add_node(node)
        s = self._state()
        s.regs.rip = claripy.If(claripy.BoolS("c"), claripy.BVV(0x1000, 64), claripy.BVV(0x1008, 64))
        s.globals["cur_block_id"] = node
        fake = self._symbolizer(graph)
        fake._graph_succ_for_state = lambda n, st, a: Symbolizer._graph_succ_for_state(fake, n, st, a)
        # the ip is two-valued: it must not be evaluated
        Symbolizer._name_successors_by_graph(fake, node, [s])
        assert s.globals["cur_block_id"] is node


class TestSplitSelectedMerge(unittest.TestCase):
    """A split-selected value is resolved under each path's own pins when paths join."""

    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90" * 16, "AMD64", load_address=0x1000)
        self.merger = EvalTopMergerMixin.__new__(EvalTopMergerMixin)
        self.merger.id = "mem"

    def _state(self, *constraints):
        s = self.proj.factory.blank_state(addr=0x1000, mode="fastpath")
        s.register_plugin(
            "partial_symbolic_constraint_solver", AndingSimSolver(claripy.SolverReplacement(auto_replace=False))
        )
        s.globals["last_added_state_split_cond"] = None
        for c in constraints:
            s.partial_symbolic_constraint_solver.add(c)
        return s

    def test_one_value_both_paths_decide_alike(self):
        c, d = claripy.BoolS("mba_state_split_cond_1"), claripy.BoolS("mba_state_split_cond_2")
        v = claripy.If(c, claripy.BVV(TRACED, 64), claripy.If(d, claripy.BVV(TRACED, 64), claripy.BVV(UNTRACED, 64)))
        states = [self._state(c), self._state(claripy.Not(c), d)]
        merged = self.merger._merge_values([(v, None), (v, None)], 8, all_states=states)
        assert not merged.symbolic and merged.concrete_value == TRACED
        # paths that decide it differently keep it
        states = [self._state(c), self._state(claripy.Not(c), claripy.Not(d))]
        assert self.merger._merge_values([(v, None), (v, None)], 8, all_states=states) is v

    def test_split_selected_frame_values_that_agree(self):
        sp = claripy.BVS("precon_sp_1", 64)
        c, d = claripy.BoolS("mba_state_split_cond_1"), claripy.BoolS("mba_state_split_cond_2")
        v0 = claripy.If(c, sp + 0xC70, sp + 0xC78)
        v1 = claripy.If(d, sp + 0xC70, sp + 0xC80)
        states = [self._state(sp == 0x7FFF0000, c), self._state(sp == 0x7FFF0000, d)]
        merged = self.merger._merge_values([(v0, None), (v1, None)], 8, all_states=states)
        assert not merged.symbolic and merged.concrete_value == 0x7FFF0C70

    def test_list_page_reports_a_shared_split_selected_object(self):
        c = claripy.BoolS("mba_state_split_cond_1")
        mo = SimMemoryObject(claripy.If(c, claripy.BVV(TRACED, 64), claripy.BVV(UNTRACED, 64)), 0x10, "Iend_BE")
        memory = SimpleNamespace(page_size=0x100)
        p0, p1 = ListPage(memory=memory), ListPage(memory=memory)
        for p in (p0, p1):
            p.store(0x10, mo, size=8, endness="Iend_BE", cooperate=True)
        states = [self._state(c), self._state(claripy.Not(c))]
        assert set(range(0x10, 0x18)) <= p0.changed_bytes(p1, page_addr=0, all_states=states)
        # unrelated identical objects are no difference
        plain = SimMemoryObject(claripy.BVS("x", 64), 0x20, "Iend_BE")
        q0, q1 = ListPage(memory=memory), ListPage(memory=memory)
        for q in (q0, q1):
            q.store(0x20, plain, size=8, endness="Iend_BE", cooperate=True)
        assert not q0.changed_bytes(q1, page_addr=0, all_states=states)


if __name__ == "__main__":
    unittest.main()
