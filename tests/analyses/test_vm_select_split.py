#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest
from types import SimpleNamespace

import angr
from angr import claripy
from angr.analyses.cfg.cfg_vm_deobfuscation import CFGVMDeobfuscation
from angr.analyses.symbolizer.symbolizer import Symbolizer
from angr.analyses.vm_deobfuscation.vm_deobfuscation import AndingSimSolver
from angr.engines.vex.light.light import VEXMixin
from angr.knowledge_plugins.cfg.block_id import BlockID

A, B = 0x69EF991D, 0x69EF27D6  # the two values a VMProtect branch selects between (CNIC sub_279f8)


class TestSelectSplit(unittest.TestCase):
    """A VM branch splits at its select, before its targets run different handlers."""

    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90" * 16, "AMD64", load_address=0x1000)
        self.cfgvm = CFGVMDeobfuscation.__new__(CFGVMDeobfuscation)
        self.cfgvm.project = self.proj

    def _blank(self, **kwargs):
        s = self.proj.factory.blank_state(**kwargs)
        s.register_plugin("partial_symbolic_constraint_solver", AndingSimSolver(claripy.SolverReplacement(auto_replace=False)))
        return s

    def _state(self, cond):
        s = self._blank(addr=0x1008)
        s.globals["last_added_state_split_cond"] = cond
        s.globals["existing_mba_split_constraints"] = []
        return s

    def test_split_when_the_select_reaches_a_register(self):
        cond = claripy.BoolS("mba_state_split_cond")
        s = self._state(cond)
        succs = SimpleNamespace(all_successors=[s])
        # the select is only on the VM stack so far: no split
        assert self.cfgvm._vm_state_split_var(succs) is None
        s.regs.rax = claripy.If(cond, claripy.BVV(A, 64), claripy.BVV(B, 64))
        assert self.cfgvm._vm_state_split_var(succs) is cond
        # already split on it
        s.globals["existing_mba_split_constraints"].append(cond.args[0])
        assert self.cfgvm._vm_state_split_var(succs) is None

    def test_no_split_when_the_ip_is_two_valued(self):
        cond = claripy.BoolS("mba_state_split_cond")
        s = self._state(cond)
        s.regs.rax = claripy.If(cond, claripy.BVV(A, 64), claripy.BVV(B, 64))
        s.regs.rip = claripy.If(cond, claripy.BVV(0x1008, 64), claripy.BVV(0x100C, 64))
        assert self.cfgvm._vm_state_split_var(SimpleNamespace(all_successors=[s])) is None

    def test_targets_keep_distinct_labels_until_the_jump(self):
        site = (0x23431, 0x554B9)
        states = []
        for arm in (True, False):
            s = self.proj.factory.blank_state()
            s.globals["vm_branch_arm"] = (site, arm, frozenset())
            states.append(s)
        # both targets run the same handlers at the same VIP
        for vip in (0x554B9, 0x554B8, 0x554A7):
            t, f = (self.cfgvm._branch_arm_label(s, vip) for s in states)
            assert t != f and vip not in (t, f)
            assert {t, f} <= self.proj.composite_vpc_values
            assert self.cfgvm._branch_arm_vip(t) == self.cfgvm._branch_arm_vip(f) == vip
            # stable per (site, target, VIP)
            assert self.cfgvm._branch_arm_label(states[0], vip) == t
        # the jump handler loaded each target's VIP: real VPCs from here on
        assert self.cfgvm._branch_arm_label(states[0], 0x6116B) == 0x6116B
        assert self.cfgvm._branch_arm_label(states[1], 0x6AF32) == 0x6AF32
        assert states[0].globals["vm_branch_arm"] is None
        assert self.cfgvm._branch_arm_vip(0x6116B) == 0x6116B

    def test_arm_labels_do_not_collide_with_composite_labels(self):
        composite = VEXMixin.composite_vpc(self.proj, (0x6116B, 0x6AF64))
        arm = VEXMixin.branch_arm_vpc(self.proj, (0x23431, 0x554B9), True, composite)
        assert arm not in (composite, 0x6116B, 0x6AF64)
        assert VEXMixin.branch_arm_vpc(self.proj, (0x23431, 0x554B9), True, composite) == arm

    def test_symbolizer_puts_each_target_under_its_value(self):
        rax = self.proj.arch.registers["rax"][0]
        split_bid = BlockID(0x23431, (), "normal", 0x554B9)
        labels = {True: 0x1000000554B9, False: 0x2000000554B9}
        self.proj.same_ip_split_guards = {split_bid: (rax, {labels[True]: A, labels[False]: B})}
        fake = SimpleNamespace(project=self.proj)
        node = SimpleNamespace(block_id=split_bid)
        picked = claripy.BVS("symbolic_read_unconstrained", 64)
        for arm, value in ((True, A), (False, B)):
            s = self._blank()
            s.regs.rax = picked
            s.regs.rdx = picked ^ 0x1234
            s.globals["cur_block_id"] = BlockID(0x23431, (), "normal", labels[arm])
            s.globals["last_added_state_split_cond"] = None
            # the fall-through guard only says rax != A; the target's own value must be used
            Symbolizer._constrain_same_ip_arm(fake, node, s)
            assert s.solver.eval_one(s.regs.rax) == value and not s.regs.rax.symbolic
            assert not s.regs.rdx.symbolic and s.solver.eval_one(s.regs.rdx) == value ^ 0x1234


if __name__ == "__main__":
    unittest.main()
