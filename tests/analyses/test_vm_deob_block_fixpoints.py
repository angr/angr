#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest

import pyvex

import angr
from angr.analyses.cfg.vm_cfg_model import VMCFGModel
from angr.analyses.vm_deobfuscation.vm_deobfuscation import VMDeobfuscation
from angr.knowledge_plugins.cfg.cfg_node import CFGENode

ADDR = 0x1000


def _analysis(proj):
    self = VMDeobfuscation.__new__(VMDeobfuscation)
    self.project = proj
    self.kb = proj.kb
    self.vm_start_addr = ADDR
    self._pass_changed = False
    self._change_counter = 0
    self._coarse_epoch = 0
    self._pass_seen = {}
    self._node_dirty = {}
    self._node_seen = {}
    return self


def _c(v):
    return pyvex.expr.Const(pyvex.const.U64(v))


def _t(i):
    return pyvex.expr.RdTmp(i)


def _block(proj, stmts, ntmps):
    stmts = [pyvex.stmt.IMark(ADDR, 4, 0)] + stmts
    return pyvex.IRSB.empty_block(
        proj.arch, ADDR, statements=stmts, tyenv=pyvex.block.IRTypeEnv(proj.arch, types=["Ity_I64"] * ntmps),
        nxt=_c(ADDR + 4), jumpkind="Ijk_Boring", size=4,
    )


def _cfg_with(irsb, proj):
    model = VMCFGModel("test", cfg_manager=proj.kb.cfgs, addr_type="block_id")
    node = CFGENode(irsb.addr, irsb.size, model, irsb=irsb)
    model.add_node(irsb.addr, node)
    return model, node


def _vm_stack_block(proj):
    """
    The VM stack pointer lives in a stack slot: the load of the pushed value has an address that is only known once
    the load of the VM stack pointer is forwarded.
    """
    rsp, rax, rbx = (proj.arch.registers[r][0] for r in ("rsp", "rax", "rbx"))
    stmts = [
        pyvex.stmt.WrTmp(0, pyvex.expr.Get(rsp, "Ity_I64")),
        pyvex.stmt.WrTmp(1, pyvex.expr.Binop("Iop_Add64", [_t(0), _c(0xFFFFFFFFFFFFFFF0)])),
        pyvex.stmt.WrTmp(2, pyvex.expr.Binop("Iop_Add64", [_t(0), _c(0xFFFFFFFFFFFFFFE0)])),
        pyvex.stmt.Store(_t(1), _t(2), "Iend_LE"),
        pyvex.stmt.WrTmp(3, pyvex.expr.Get(rax, "Ity_I64")),
        pyvex.stmt.Store(_t(2), _t(3), "Iend_LE"),
        pyvex.stmt.WrTmp(4, pyvex.expr.Load("Iend_LE", "Ity_I64", _t(1))),
        pyvex.stmt.WrTmp(5, pyvex.expr.Load("Iend_LE", "Ity_I64", _t(4))),
        pyvex.stmt.Put(_t(5), rbx),
    ]
    return _block(proj, stmts, 6)


def _add_chain_block(proj):
    """t1 = t0 + 1; t2 = t1 + 2; t3 = t2 + 4; PUT(rbx) = t3"""
    rax, rbx = proj.arch.registers["rax"][0], proj.arch.registers["rbx"][0]
    stmts = [
        pyvex.stmt.WrTmp(0, pyvex.expr.Get(rax, "Ity_I64")),
        pyvex.stmt.WrTmp(1, pyvex.expr.Binop("Iop_Add64", [_t(0), _c(1)])),
        pyvex.stmt.WrTmp(2, pyvex.expr.Binop("Iop_Add64", [_t(1), _c(2)])),
        pyvex.stmt.WrTmp(3, pyvex.expr.Binop("Iop_Add64", [_t(2), _c(4)])),
        pyvex.stmt.Put(_t(3), rbx),
    ]
    return _block(proj, stmts, 4)


def _add_chain_back_block(proj):
    """t1 = t0 + 1; t2 = t1 + 2; t3 = t2 + 4; t4 = t3 - 4; PUT(rbx) = t3; PUT(rcx) = t4"""
    rax, rbx, rcx = (proj.arch.registers[r][0] for r in ("rax", "rbx", "rcx"))
    stmts = [
        pyvex.stmt.WrTmp(0, pyvex.expr.Get(rax, "Ity_I64")),
        pyvex.stmt.WrTmp(1, pyvex.expr.Binop("Iop_Add64", [_t(0), _c(1)])),
        pyvex.stmt.WrTmp(2, pyvex.expr.Binop("Iop_Add64", [_t(1), _c(2)])),
        pyvex.stmt.WrTmp(3, pyvex.expr.Binop("Iop_Add64", [_t(2), _c(4)])),
        pyvex.stmt.WrTmp(4, pyvex.expr.Binop("Iop_Sub64", [_t(3), _c(4)])),
        pyvex.stmt.Put(_t(3), rbx),
        pyvex.stmt.Put(_t(4), rcx),
    ]
    return _block(proj, stmts, 5)


class TestBlockFixpoints(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90" * 16, "AMD64", load_address=ADDR)

    def _pp(self, node, idx):
        return node.irsb.statements[idx].pp_str(arch=self.proj.arch, tyenv=node.irsb.tyenv)

    def _store_load(self, fixpoint):
        self.proj.vm_deob_store_load_block_fixpoint = fixpoint
        a = _analysis(self.proj)
        cfg, node = _cfg_with(_vm_stack_block(self.proj), self.proj)
        a.remove_redundant_store_load(cfg, self.proj)
        return a, node

    def test_store_load_forwards_through_forwarded_address(self):
        a, node = self._store_load(True)
        assert self._pp(node, 7) == "t4 = t2"
        assert self._pp(node, 8) == "t5 = t3"
        assert a._pass_changed

    def test_store_load_one_level_without_fixpoint(self):
        _, node = self._store_load(False)
        assert self._pp(node, 7) == "t4 = t2"
        assert self._pp(node, 8) == "t5 = LDle:I64(t4)"

    def _arith(self, fixpoint, block=_add_chain_block):
        self.proj.vm_deob_bas_block_fixpoint = fixpoint
        a = _analysis(self.proj)
        cfg, node = _cfg_with(block(self.proj), self.proj)
        a.block_arithmetic_simplifications_using_dep_graph(cfg, self.proj)
        return node

    def test_arith_folds_whole_chain(self):
        node = self._arith(True)
        assert self._pp(node, 3) == "t2 = Add64(t0,0x0000000000000003)"
        assert self._pp(node, 4) == "t3 = Add64(t0,0x0000000000000007)"

    def test_arith_reuses_a_value_the_fold_recomputes(self):
        node = self._arith(True, _add_chain_back_block)
        assert self._pp(node, 4) == "t3 = Add64(t0,0x0000000000000007)"
        assert self._pp(node, 5) == "t4 = t2"

    def test_arith_one_level_without_fixpoint(self):
        node = self._arith(False)
        assert self._pp(node, 3) == "t2 = Add64(t0,0x0000000000000003)"
        assert self._pp(node, 4) == "t3 = Add64(t2,0x0000000000000004)"


if __name__ == "__main__":
    unittest.main()
