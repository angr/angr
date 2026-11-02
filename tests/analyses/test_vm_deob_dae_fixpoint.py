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


def _analysis(proj, start_addr):
    self = VMDeobfuscation.__new__(VMDeobfuscation)
    self.project = proj
    self.kb = proj.kb
    self.vm_start_addr = start_addr
    self._pass_changed = False
    self._change_counter = 0
    self._coarse_epoch = 0
    self._pass_seen = {}
    self._node_dirty = {}
    self._node_seen = {}
    return self


def _dead_chain_block(proj, addr):
    """
    t0 = GET(rax); t1 = t0 + 1; PUT(rbx) = t1; PUT(rbx) = 5
    The first PUT is dead, which makes t1 dead, which makes t0 dead: three layers.
    """
    arch = proj.arch
    rax, rbx = arch.registers["rax"][0], arch.registers["rbx"][0]
    stmts = [
        pyvex.stmt.IMark(addr, 2, 0),
        pyvex.stmt.WrTmp(0, pyvex.expr.Get(rax, "Ity_I64")),
        pyvex.stmt.WrTmp(1, pyvex.expr.Binop("Iop_Add64", [pyvex.expr.RdTmp(0), pyvex.expr.Const(pyvex.const.U64(1))])),
        pyvex.stmt.Put(pyvex.expr.RdTmp(1), rbx),
        pyvex.stmt.IMark(addr + 2, 2, 0),
        pyvex.stmt.Put(pyvex.expr.Const(pyvex.const.U64(5)), rbx),
    ]
    return pyvex.IRSB.empty_block(
        arch,
        addr,
        statements=stmts,
        tyenv=pyvex.block.IRTypeEnv(arch, types=["Ity_I64", "Ity_I64"]),
        nxt=pyvex.expr.Const(pyvex.const.U64(addr + 4)),
        jumpkind="Ijk_Boring",
        size=4,
    )


def _cfg_with(proj, irsb):
    model = VMCFGModel("test", cfg_manager=proj.kb.cfgs, addr_type="block_id")
    node = CFGENode(irsb.addr, irsb.size, model, irsb=irsb)
    model.add_node(irsb.addr, node)
    return model, node


class TestDaeBlockFixpoint(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90" * 16, "AMD64", load_address=0x1000)

    def _stmts(self, node):
        return [
            s.pp_str(arch=self.proj.arch, tyenv=node.irsb.tyenv) if not isinstance(s, pyvex.stmt.IMark) else "IMark"
            for s in node.irsb.statements
        ]

    def test_whole_chain_goes_in_one_round(self):
        self.proj.vm_deob_dae_block_fixpoint = True
        a = _analysis(self.proj, 0x1000)
        cfg, node = _cfg_with(self.proj, _dead_chain_block(self.proj, 0x1000))
        a._eliminate_dead_assignments(cfg, self.proj)
        assert self._stmts(node) == ["IMark", "PUT(rbx) = 0x0000000000000005"]
        assert a._pass_changed

    def test_layered_mode_needs_a_round_per_layer(self):
        self.proj.vm_deob_dae_block_fixpoint = False
        a = _analysis(self.proj, 0x1000)
        cfg, node = _cfg_with(self.proj, _dead_chain_block(self.proj, 0x1000))
        lengths = []
        for _ in range(4):
            a._eliminate_dead_assignments(cfg, self.proj)
            lengths.append(len(node.irsb.statements))
        # one dead PUT, then t1, then t0, then the orphaned IMark
        assert lengths == [5, 4, 3, 2], lengths
        assert self._stmts(node) == ["IMark", "PUT(rbx) = 0x0000000000000005"]

    def test_live_out_definition_stays(self):
        self.proj.vm_deob_dae_block_fixpoint = True
        a = _analysis(self.proj, 0x1000)
        irsb = _dead_chain_block(self.proj, 0x1000)
        irsb.statements = irsb.statements[:4]  # no overwrite: PUT(rbx) = t1 reaches the exit
        cfg, node = _cfg_with(self.proj, irsb)
        a._eliminate_dead_assignments(cfg, self.proj)
        assert len(node.irsb.statements) == 4
        assert not a._pass_changed


if __name__ == "__main__":
    unittest.main()
