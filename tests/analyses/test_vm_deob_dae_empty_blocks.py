#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest

import pyvex

import angr
from angr.analyses.cfg.vm_cfg_model import VMCFGModel
from angr.knowledge_plugins.cfg.cfg_node import CFGENode

from .test_vm_deob_dae_fixpoint import _analysis


def _u64(v):
    return pyvex.expr.Const(pyvex.const.U64(v))


def _block(arch, addr, stmts, types, nxt):
    return pyvex.IRSB.empty_block(
        arch, addr, statements=[pyvex.stmt.IMark(addr, 4, 0), *stmts], tyenv=pyvex.block.IRTypeEnv(arch, types=types),
        nxt=nxt, jumpkind="Ijk_Boring", size=4,
    )


class TestDaeEmptyBlocks(unittest.TestCase):
    def test_empty_block_entered_from_a_vm_branch_is_kept(self):
        # entry -> body; body -> test; test -> {body, exit}. body is dead code (a junk jcc), test picks its
        # target from a computed value. Removing body must not cut test's back edge.
        proj = angr.load_shellcode(b"\x90" * 16, "AMD64", load_address=0x1000)
        arch = proj.arch
        rax = arch.registers["rax"][0]
        live = lambda addr: [pyvex.stmt.WrTmp(0, pyvex.expr.Get(rax, "Ity_I64")), pyvex.stmt.Store(_u64(addr), pyvex.expr.RdTmp(0), "Iend_LE")]
        entry = _block(arch, 0x1000, live(0x5000), ["Ity_I64"], _u64(0x1010))
        body = _block(arch, 0x1010, [pyvex.stmt.WrTmp(0, pyvex.expr.Get(rax, "Ity_I64"))], ["Ity_I64"], _u64(0x1020))
        test = _block(arch, 0x1020, live(0x5008), ["Ity_I64"], pyvex.expr.RdTmp(0))
        exit_ = _block(arch, 0x1030, live(0x5010), ["Ity_I64"], _u64(0x1040))

        model = VMCFGModel("test", cfg_manager=proj.kb.cfgs, addr_type="block_id")
        nodes = [CFGENode(b.addr, 4, model, irsb=b, block_id=i + 1) for i, b in enumerate((entry, body, test, exit_))]
        for n in nodes:
            model.add_node(n.addr, n)
        n_entry, n_body, n_test, n_exit = nodes
        for u, v in ((n_entry, n_body), (n_body, n_test), (n_test, n_body), (n_test, n_exit)):
            model.graph.add_edge(u, v, jumpkind="Ijk_Boring")

        a = _analysis(proj, 0x1000)
        a._eliminate_dead_assignments(model, proj)

        succs = set(model.graph.successors(n_test))
        assert n_exit in succs
        assert len(succs) == 2, "the loop's back edge was dropped"


if __name__ == "__main__":
    unittest.main()
