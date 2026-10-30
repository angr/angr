#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest

import pyvex
from pyvex.const import U64

import angr
from angr import claripy
from angr.analyses.cfg.cfg_vm_deobfuscation import CFGVMDeobfuscation
from angr.analyses.cfg.vm_cfg_model import VMCFGModel
from angr.engines.vex.data_sensitive import DataSensitiveRdTmp, DataSensitiveU64, is_same_ip_branch
from angr.knowledge_plugins.cfg.block_id import BlockID
from angr.knowledge_plugins.cfg.cfg_node import CFGENode

from .test_vm_deob_dae_fixpoint import _analysis

HANDLER = 0x1008


def _dispatch_block(proj, addr):
    """t0 = GET(rbx); next = t0 -- an indirect jump to the next handler"""
    arch = proj.arch
    stmts = [pyvex.stmt.IMark(addr, 2, 0), pyvex.stmt.WrTmp(0, pyvex.expr.Get(arch.registers["rbx"][0], "Ity_I64"))]
    return pyvex.IRSB.empty_block(
        arch, addr, statements=stmts, tyenv=pyvex.block.IRTypeEnv(arch, types=["Ity_I64"]),
        nxt=DataSensitiveRdTmp(0, None), jumpkind="Ijk_Boring", size=2,
    )


def _handler_block(proj):
    stmts = [pyvex.stmt.IMark(HANDLER, 1, 0)]
    return pyvex.IRSB.empty_block(
        proj.arch, HANDLER, statements=stmts, tyenv=pyvex.block.IRTypeEnv(proj.arch, types=[]),
        nxt=pyvex.expr.Const(U64(HANDLER + 1)), jumpkind="Ijk_Boring", size=1,
    )


def _split_cfg(proj):
    """a dispatch node whose two successors run the same handler under two VIPs (VPC 0x100 / 0x200)"""
    model = VMCFGModel("test", cfg_manager=proj.kb.cfgs, addr_type="block_id")
    bid = BlockID(0x1000, (), "normal", 0x10)
    node = CFGENode(0x1000, 2, model, block_id=bid, vm_vpc=0x10, irsb=_dispatch_block(proj, 0x1000))
    model.add_node(bid, node)
    succs = []
    for vpc in (0x100, 0x200):
        sbid = BlockID(HANDLER, (), "normal", vpc)
        succ = CFGENode(HANDLER, 1, model, block_id=sbid, vm_vpc=vpc, irsb=_handler_block(proj))
        model.add_node(sbid, succ)
        model.graph.add_edge(node, succ, jumpkind="Ijk_Boring")
        succs.append(succ)
    return model, node, succs


class TestSameIpSplit(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90" * 16, "AMD64", load_address=0x1000)
        self.r11 = self.proj.arch.registers["r11"][0]

    def test_guard_names_successors_by_block_id(self):
        cfg, node, (s0, s1) = _split_cfg(self.proj)
        self.proj.same_ip_split_guards = {node.block_id: (self.r11, {0x100: 0x1400a00a3, 0x200: 0x1400a049b})}
        a = _analysis(self.proj, 0x1000)
        assert not is_same_ip_branch(node.irsb)
        assert a._add_same_ip_guard(cfg, node)
        irsb = node.irsb
        assert is_same_ip_branch(irsb)
        exit_stmt = irsb.statements[-1]
        assert isinstance(exit_stmt, pyvex.stmt.Exit)
        assert (exit_stmt.dst.value, exit_stmt.dst.block_id) == (HANDLER, s0.block_id)
        assert (irsb.next.con.value, irsb.next.con.block_id) == (HANDLER, s1.block_id)
        cmp = irsb.statements[-2].data
        assert cmp.op == "Iop_CmpEQ64" and cmp.args[1].con.value == 0x1400a00a3
        assert irsb.statements[-3].data.offset == self.r11
        # the guard executes: r11 == the value of successor 0 takes the exit
        for r11, taken in ((0x1400a00a3, True), (0x1400a049b, False)):
            state = self.proj.factory.blank_state(addr=0x1000)
            state.regs.r11 = r11
            succ = self.proj.factory.successors(state, irsb=irsb)
            sat = [s for s in succ.flat_successors if s.solver.is_true(s.scratch.guard)]
            assert len(sat) == 1 and (sat[0].scratch.exit_stmt_idx != -2) == taken

    def test_guard_is_added_once_and_needs_a_record(self):
        cfg, node, _ = _split_cfg(self.proj)
        self.proj.same_ip_split_guards = {}
        a = _analysis(self.proj, 0x1000)
        assert not a._add_same_ip_guard(cfg, node)
        self.proj.same_ip_split_guards = {node.block_id: (self.r11, {0x100: 1, 0x200: 2})}
        a._add_same_ip_guard(cfg, node)
        n_stmts = len(node.irsb.statements)
        a.start_addr = 0x1000
        a.convert_to_data_sensitive_irsb(cfg, self.proj, None)
        assert len(node.irsb.statements) == n_stmts and is_same_ip_branch(node.irsb)

    def test_record_prefers_register_nearest_the_condition(self):
        cond = claripy.BoolS("mba_state_split_cond")
        pre = self.proj.factory.blank_state()
        vip = claripy.If(cond, claripy.BVV(0x1400A049F, 64), claripy.BVV(0x1400A00A7, 64))
        pre.regs.r11 = vip - 4
        pre.regs.rdi = ((vip ^ 0x1234) + 7) ^ 0x55
        succs = []
        for c, vpc in ((False, 0x100), (True, 0x200)):
            s = pre.copy()
            s.regs.r11 = s.solver.eval_one(vip - 4, extra_constraints=[cond == c])
            s.regs.rdi = s.solver.eval_one(pre.regs.rdi, extra_constraints=[cond == c])
            s.globals["cur_vm_vpc"] = vpc
            succs.append(s)
        cfgvm = CFGVMDeobfuscation.__new__(CFGVMDeobfuscation)
        cfgvm.project = self.proj
        self.proj.same_ip_split_guards = {}
        bid = BlockID(0x1000, (), "normal", 0x10)
        cfgvm._record_same_ip_split_guard(bid, pre, succs)
        assert self.proj.same_ip_split_guards[bid] == (self.r11, {0x100: 0x1400A00A3, 0x200: 0x1400A049B})

    def test_same_address_without_block_ids_is_not_a_same_ip_branch(self):
        irsb = _handler_block(self.proj)
        irsb.statements.append(
            pyvex.stmt.Exit(pyvex.expr.Const(pyvex.const.U1(1)), U64(HANDLER + 1), "Ijk_Boring", self.proj.arch.ip_offset)
        )
        assert not is_same_ip_branch(irsb)
        irsb.statements[-1] = pyvex.stmt.Exit(
            pyvex.expr.Const(pyvex.const.U1(1)), DataSensitiveU64(HANDLER + 1, "a"), "Ijk_Boring",
            self.proj.arch.ip_offset,
        )
        irsb.next = pyvex.expr.Const(DataSensitiveU64(HANDLER + 1, "a"))
        assert not is_same_ip_branch(irsb)
        irsb.next = pyvex.expr.Const(DataSensitiveU64(HANDLER + 1, "b"))
        assert is_same_ip_branch(irsb)


if __name__ == "__main__":
    unittest.main()
