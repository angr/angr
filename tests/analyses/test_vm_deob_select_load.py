#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest
from collections import defaultdict
from types import SimpleNamespace
from unittest import mock

import pyvex
from pyvex.const import U64

import angr
from angr import claripy
from angr.analyses.vm_deobfuscation.vex_concrete_fold import bounded_load_offsets
from angr.analyses.vm_deobfuscation.vm_deobfuscation import InputConcretizeEngine
from angr.state_plugins.solver import SimSolver

from .test_vm_deob_dae_fixpoint import _analysis, _cfg_with


def _c(v):
    return pyvex.expr.Const(U64(v))


def _select_block(proj, addr, offset_from_stack=True, mask=8):
    """
    Two stack slots get two values, a load picks one by an input-dependent offset, then both slots are
    overwritten:  STle(sp-16) = 0x11; STle(sp-8) = 0x22; t = LDle(sp-16 + (rdi & 8)); STle(sp-16) = 0;
    STle(sp-8) = 0; PUT(rax) = t
    """
    arch = proj.arch
    rsp, rdi, rax = arch.registers["rsp"][0], arch.registers["rdi"][0], arch.registers["rax"][0]
    rd = pyvex.expr.RdTmp
    base = (pyvex.expr.Binop("Iop_Sub64", [rd(0), _c(16)]) if offset_from_stack
            else pyvex.expr.Get(arch.registers["rsi"][0], "Ity_I64"))
    stmts = [
        pyvex.stmt.IMark(addr, 1, 0),
        pyvex.stmt.WrTmp(0, pyvex.expr.Get(rsp, "Ity_I64")),
        pyvex.stmt.WrTmp(1, pyvex.expr.Binop("Iop_Sub64", [rd(0), _c(16)])),
        pyvex.stmt.WrTmp(2, pyvex.expr.Binop("Iop_Sub64", [rd(0), _c(8)])),
        pyvex.stmt.Store(rd(1), _c(0x11), "Iend_LE"),
        pyvex.stmt.Store(rd(2), _c(0x22), "Iend_LE"),
        pyvex.stmt.WrTmp(3, pyvex.expr.Binop("Iop_And64", [pyvex.expr.Get(rdi, "Ity_I64"), _c(mask)])),
        pyvex.stmt.WrTmp(4, base),
        pyvex.stmt.WrTmp(5, pyvex.expr.Binop("Iop_Add64", [rd(4), rd(3)])),
        pyvex.stmt.WrTmp(6, pyvex.expr.Load("Iend_LE", "Ity_I64", rd(5))),
        pyvex.stmt.Store(rd(1), _c(0), "Iend_LE"),
        pyvex.stmt.Store(rd(2), _c(0), "Iend_LE"),
        pyvex.stmt.Put(rd(6), rax),
    ]
    return pyvex.IRSB.empty_block(
        arch, addr, statements=stmts, tyenv=pyvex.block.IRTypeEnv(arch, types=["Ity_I64"] * 7),
        nxt=_c(addr + 1), jumpkind="Ijk_Boring", size=1,
    )


class TestSelectLoadDae(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90" * 16, "AMD64", load_address=0x1000)
        self.proj.vm_deobfuscation = True  # block-wise RDA seeds sp

    def _stores(self, node):
        return [s.pp_str(arch=self.proj.arch, tyenv=node.irsb.tyenv) for s in node.irsb.statements
                if isinstance(s, pyvex.stmt.Store)]

    def _dae(self, irsb):
        a = _analysis(self.proj, 0x1000)
        cfg, node = _cfg_with(self.proj, irsb)
        a._eliminate_dead_assignments(cfg, self.proj)
        return self._stores(node)

    def _proved_select(self):
        # the VM-CFG saw the load at 0x1000 read its address' stack part (sp - 16) + 0 or + 8
        self.proj.vm_select_load_deltas = defaultdict(set, {0x1000: {(0, 8), (8, 8)}})

    def test_rda_records_unresolved_loads_with_sp(self):
        irsb = _select_block(self.proj, 0x1000)
        rd = self.proj.analyses.ReachingDefinitions(angr.Block(0x1000, project=self.proj, vex=irsb), track_tmps=True)
        loads = {c.stmt_idx: v for c, v in rd.unresolved_load_codelocs.items()}
        # (size, stack offset of the known part of the address)
        assert loads == {9: (8, -16)}
        assert {c.ins_addr for c in rd.unresolved_load_codelocs} == {0x1000}

    def test_selected_slots_survive(self):
        self._proved_select()
        assert self._dae(_select_block(self.proj, 0x1000)) == [
            "STle(t1) = 0x0000000000000011",
            "STle(t2) = 0x0000000000000022",
            "STle(t1) = 0x0000000000000000",
            "STle(t2) = 0x0000000000000000",
        ]

    def test_slots_the_select_cannot_reach_go(self):
        # a store to sp-0x40, overwritten after the select load, is still dead
        self._proved_select()
        irsb = _select_block(self.proj, 0x1000)
        far = pyvex.expr.Binop("Iop_Sub64", [pyvex.expr.RdTmp(0), _c(0x40)])
        irsb.statements[4:4] = [pyvex.stmt.Store(far, _c(0x33), "Iend_LE")]
        irsb.statements[11:11] = [pyvex.stmt.Store(far, _c(0x44), "Iend_LE")]
        stores = self._dae(irsb)
        assert "STle(Sub64(t0,0x0000000000000040)) = 0x0000000000000033" not in stores
        assert "STle(Sub64(t0,0x0000000000000040)) = 0x0000000000000044" in stores
        assert "STle(t1) = 0x0000000000000011" in stores and "STle(t2) = 0x0000000000000022" in stores

    def test_block_bounded_select_keeps_stores(self):
        # not seen by the VM-CFG (a loop exit's condition is concrete in every explored run), but the block bounds the
        # offset to {0, 8}
        self.proj.vm_select_load_deltas = defaultdict(set)
        assert self._dae(_select_block(self.proj, 0x1000)) == [
            "STle(t1) = 0x0000000000000011",
            "STle(t2) = 0x0000000000000022",
            "STle(t1) = 0x0000000000000000",
            "STle(t2) = 0x0000000000000000",
        ]

    def test_unbounded_loads_do_not_keep_stores(self):
        self.proj.vm_select_load_deltas = defaultdict(set)
        for from_stack, mask in ((True, 0xFFFFFFFFFFFFFFFF), (False, 8)):
            assert self._dae(_select_block(self.proj, 0x1000, offset_from_stack=from_stack, mask=mask)) == [
                "STle(t1) = 0x0000000000000000",
                "STle(t2) = 0x0000000000000000",
            ]


class TestBoundedLoadOffsets(unittest.TestCase):
    def test_selector_read_back_from_memory(self):
        # diskgen's loop exit: the flags go through a VM stack slot before the select masks them
        proj = angr.load_shellcode(b"\x90" * 16, "AMD64", load_address=0x1000)
        irsb = _select_block(proj, 0x1000)
        rd, rdi = pyvex.expr.RdTmp, proj.arch.registers["rdi"][0]
        slot = pyvex.expr.Binop("Iop_Sub64", [rd(0), _c(0x40)])
        irsb.statements[6:7] = [
            pyvex.stmt.Store(slot, pyvex.expr.Get(rdi, "Ity_I64"), "Iend_LE"),
            pyvex.stmt.WrTmp(3, pyvex.expr.Binop("Iop_And64", [pyvex.expr.Load("Iend_LE", "Ity_I64", slot), _c(8)])),
        ]
        assert bounded_load_offsets(proj, irsb, {10}) == {10: {-16, -8}}
        irsb.statements[7] = pyvex.stmt.WrTmp(3, pyvex.expr.Load("Iend_LE", "Ity_I64", slot))
        assert bounded_load_offsets(proj, irsb, {10}) == {}

    def test_unbounded_load_needs_no_solver(self):
        # random inputs already give the address more than four values
        proj = angr.load_shellcode(b"\x90" * 16, "AMD64", load_address=0x1000)
        irsb = _select_block(proj, 0x1000, mask=0xFFFFFFFFFFFFFFFF)
        with mock.patch.object(SimSolver, "eval_upto", side_effect=AssertionError("solver queried")):
            assert bounded_load_offsets(proj, irsb, {9}) == {}

    def test_value_sets_are_reused_across_variable_names(self):
        # each call names the block's entry registers afresh; the second call reuses the first one's proof
        proj = angr.load_shellcode(b"\x90" * 16, "AMD64", load_address=0x1000)
        irsb = _select_block(proj, 0x1000)
        assert bounded_load_offsets(proj, irsb, {9}) == {9: {-16, -8}}
        with mock.patch.object(SimSolver, "eval_upto", side_effect=AssertionError("solver queried")):
            assert bounded_load_offsets(proj, irsb, {9}) == {9: {-16, -8}}


class TestSelectLoadRecord(unittest.TestCase):
    def test_slots_relative_to_the_stack_part_of_the_address(self):
        sp = claripy.BVS("precon_sp_0", 64)
        x = claripy.BVS("scanf_d", 32)
        solver = claripy.Solver()
        solver.add(sp == 0x7FFFFFFF0000)
        # VMProtect 3.10: sel(x) + (precon_sp - 0x38) - 0x10, sel in {0, 8}
        sel = ~claripy.LShR(claripy.ZeroExt(32, ~(x | (x + 0x7FFFFFFF)) & 0x80000000), 0x1C) & 8
        addr = sel + ~(~sp + 0x38) + 0xFFFFFFFFFFFFFFF0
        state = SimpleNamespace(
            partial_symbolic_constraint_solver=SimpleNamespace(eval_one=lambda e: solver.eval(e, 1)[0]),
            project=SimpleNamespace(vm_select_load_deltas=defaultdict(set)),
            scratch=SimpleNamespace(ins_addr=0x1234),
        )
        base = 0x7FFFFFFF0000 - 0x48
        InputConcretizeEngine._note_select_load(SimpleNamespace(state=state), addr, [base, base + 8], 8)
        assert state.project.vm_select_load_deltas == {0x1234: {(0, 8), (8, 8)}}
        # an address without a stack part is not recorded
        InputConcretizeEngine._note_select_load(SimpleNamespace(state=state), sel.zero_extend(0) + 0x1000, [0x1000], 8)
        assert set(state.project.vm_select_load_deltas) == {0x1234}


if __name__ == "__main__":
    unittest.main()
