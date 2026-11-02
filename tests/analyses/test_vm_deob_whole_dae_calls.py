#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest

import archinfo
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
    def _run(self, exit_stmts, exit_types, entry_stmts, entry_types):
        """VM exit block -> hooked callee -> VM re-entry block (the last one)."""
        proj = angr.load_shellcode(b"\x90" * 16, "AMD64", load_address=0x1000)
        proj.hook(CALLEE, angr.SIM_PROCEDURES["stubs"]["Nop"](), replace=True)
        proj.vm_deobfuscation = True
        arch = proj.arch
        exit_irsb = _block(arch, 0x1000, exit_stmts, exit_types, CALLEE, "Ijk_Call")
        entry_irsb = _block(arch, 0x1010, entry_stmts, entry_types, 0x1020, "Ijk_Ret")
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
        puts = lambda node: [s.offset for s in node.irsb.statements if isinstance(s, pyvex.stmt.Put)]
        return puts(exit_node), puts(entry_node)

    @staticmethod
    def _reg(name):
        return archinfo.ArchAMD64().registers[name][0]

    def _push(self, name):
        # t0 = GET(name); STle(rsp) = t0
        return [
            pyvex.stmt.WrTmp(0, pyvex.expr.Get(self._reg(name), "Ity_I64")),
            pyvex.stmt.WrTmp(1, pyvex.expr.Get(self._reg("rsp"), "Ity_I64")),
            pyvex.stmt.Store(pyvex.expr.RdTmp(1), pyvex.expr.RdTmp(0), "Iend_LE"),
        ]

    def test_callee_saved_register_restored_at_a_vm_exit_stays(self):
        # VM exit: rbx = rcx (callee-saved), r11 = rcx (caller-saved, not an argument), call; the re-entry pushes rbx
        get_rcx = pyvex.stmt.WrTmp(0, pyvex.expr.Get(self._reg("rcx"), "Ity_I64"))
        exit_puts, _ = self._run(
            [get_rcx, pyvex.stmt.Put(pyvex.expr.RdTmp(0), self._reg("rbx")), pyvex.stmt.Put(pyvex.expr.RdTmp(0), self._reg("r11"))],
            ["Ity_I64"], self._push("rbx"), ["Ity_I64", "Ity_I64"],
        )
        assert self._reg("rbx") in exit_puts
        # the call clobbers r11, so its definition is still dead
        assert self._reg("r11") not in exit_puts

    def test_condition_flags_die_at_the_call_and_at_the_exit(self):
        # the exit's popfq sets cc_dep1 and the re-entry's pushfq reads it, but the callee clobbered it in between;
        # the re-entry's own cc_op write only reaches the function's exit
        get_rcx = pyvex.stmt.WrTmp(0, pyvex.expr.Get(self._reg("rcx"), "Ity_I64"))
        exit_puts, entry_puts = self._run(
            [get_rcx, pyvex.stmt.Put(pyvex.expr.RdTmp(0), self._reg("cc_dep1"))], ["Ity_I64"],
            [*self._push("cc_dep1"), pyvex.stmt.Put(pyvex.expr.RdTmp(0), self._reg("cc_op"))], ["Ity_I64", "Ity_I64"],
        )
        assert self._reg("cc_dep1") not in exit_puts
        assert self._reg("cc_op") not in entry_puts


if __name__ == "__main__":
    unittest.main()
