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

from .test_vm_deob_dae_fixpoint import _analysis

CALLEE = 0x2000


def _block(arch, addr, stmts, types, nxt, jumpkind):
    return pyvex.IRSB.empty_block(
        arch, addr, statements=[pyvex.stmt.IMark(addr, 4, 0), *stmts], tyenv=pyvex.block.IRTypeEnv(arch, types=types),
        nxt=pyvex.expr.Const(pyvex.const.U64(nxt)), jumpkind=jumpkind, size=4,
    )


class TestWholeDaeAcrossHookedCalls(unittest.TestCase):
    def test_callee_saved_register_restored_at_a_vm_exit_stays(self):
        # VM exit: rbx = rcx (callee-saved), r11 = rcx (caller-saved, not an argument), call; the re-entry pushes rbx
        proj = angr.load_shellcode(b"\x90" * 16, "AMD64", load_address=0x1000)
        proj.hook(CALLEE, angr.SIM_PROCEDURES["stubs"]["Nop"](), replace=True)
        proj.vm_deobfuscation = True
        arch = proj.arch
        reg = lambda name: arch.registers[name][0]
        exit_irsb = _block(arch, 0x1000, [
            pyvex.stmt.WrTmp(0, pyvex.expr.Get(reg("rcx"), "Ity_I64")),
            pyvex.stmt.Put(pyvex.expr.RdTmp(0), reg("rbx")),
            pyvex.stmt.Put(pyvex.expr.RdTmp(0), reg("r11")),
        ], ["Ity_I64"], CALLEE, "Ijk_Call")
        entry_irsb = _block(arch, 0x1010, [
            pyvex.stmt.WrTmp(0, pyvex.expr.Get(reg("rbx"), "Ity_I64")),
            pyvex.stmt.WrTmp(1, pyvex.expr.Get(reg("rsp"), "Ity_I64")),
            pyvex.stmt.Store(pyvex.expr.RdTmp(1), pyvex.expr.RdTmp(0), "Iend_LE"),
        ], ["Ity_I64", "Ity_I64"], 0x1020, "Ijk_Ret")

        model = VMCFGModel("test", cfg_manager=proj.kb.cfgs, addr_type="block_id")
        exit_node = CFGENode(0x1000, 4, model, irsb=exit_irsb, block_id=1)
        callee = CFGENode(CALLEE, None, model, simprocedure_name="Nop", function_address=CALLEE, block_id=2)
        entry_node = CFGENode(0x1010, 4, model, irsb=entry_irsb, block_id=3)
        for n in (exit_node, callee, entry_node):
            model.add_node(n.addr, n)
        model.graph.add_edge(exit_node, callee)
        model.graph.add_edge(callee, entry_node)

        a = _analysis(proj, 0x1000)
        a.allow_global_mem_simplifications = False
        VMDeobfuscation.testing_new_improved_whole_vm_RDA_deadassignment_elimination(a, model, proj)

        puts = [s.offset for s in exit_node.irsb.statements if isinstance(s, pyvex.stmt.Put)]
        assert reg("rbx") in puts
        # the call clobbers r11, so its definition is still dead
        assert reg("r11") not in puts


if __name__ == "__main__":
    unittest.main()
