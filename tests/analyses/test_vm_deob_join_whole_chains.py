#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import re
import unittest

import pyvex

import angr
from angr.analyses.cfg.vm_cfg_model import VMCFGModel
from angr.analyses.vm_deobfuscation.vm_deobfuscation import VMDeobfuscation
from angr.knowledge_plugins.cfg.cfg_node import CFGENode

GLOBAL = 0x2000


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


def _c64(v):
    return pyvex.expr.Const(pyvex.const.U64(v))


def _irsb(arch, addr, stmts, types, nxt):
    return pyvex.IRSB.empty_block(
        arch, addr, statements=stmts, tyenv=pyvex.block.IRTypeEnv(arch, types=types),
        nxt=_c64(nxt), jumpkind="Ijk_Boring", size=4,
    )


def _store_block(arch, addr, nxt, values):
    """STle(GLOBAL) = v for each v, one instruction each."""
    stmts = []
    for i, v in enumerate(values):
        stmts += [pyvex.stmt.IMark(addr + i, 1, 0), pyvex.stmt.Store(_c64(GLOBAL), _c64(v), "Iend_LE")]
    return _irsb(arch, addr, stmts, [], nxt)


def _tmp_block(arch, addr, nxt, store_value=None):
    """t0 = GET(rax); t1 = LDle(t0); t2 = t1 + 1; PUT(rbx) = t2 [; STle(GLOBAL) = store_value]"""
    rax, rbx = arch.registers["rax"][0], arch.registers["rbx"][0]
    stmts = [
        pyvex.stmt.IMark(addr, 1, 0),
        pyvex.stmt.WrTmp(0, pyvex.expr.Get(rax, "Ity_I64")),
        pyvex.stmt.WrTmp(1, pyvex.expr.Load("Iend_LE", "Ity_I64", pyvex.expr.RdTmp(0))),
        pyvex.stmt.WrTmp(2, pyvex.expr.Binop("Iop_Add64", [pyvex.expr.RdTmp(1), _c64(1)])),
        pyvex.stmt.Put(pyvex.expr.RdTmp(2), rbx),
    ]
    if store_value is not None:
        stmts += [pyvex.stmt.IMark(addr + 1, 1, 0), pyvex.stmt.Store(_c64(GLOBAL), _c64(store_value), "Iend_LE")]
    return _irsb(arch, addr, stmts, ["Ity_I64"] * 3, nxt)


def _cfg(proj, irsbs, edges):
    model = VMCFGModel("test", cfg_manager=proj.kb.cfgs, addr_type="block_id")
    nodes = {}
    for irsb in irsbs:
        node = CFGENode(irsb.addr, irsb.size, model, irsb=irsb)
        model.add_node(irsb.addr, node)
        nodes[irsb.addr] = node
    for u, v in edges:
        model.graph.add_edge(nodes[u], nodes[v], jumpkind="Ijk_Boring")
    return model, nodes


def _canon(proj, irsb):
    """Statements with tmps renumbered by first appearance."""
    names = {}
    out = []
    for s in [*irsb.statements, irsb.next]:
        text = s.pp_str(arch=proj.arch, tyenv=irsb.tyenv) if isinstance(s, pyvex.stmt.IRStmt) else str(s)
        out.append(re.sub(r"\bt\d+\b", lambda m: "T%d" % names.setdefault(m.group(0), len(names)), text))
    return out


def _shape(proj, model):
    return (
        sorted((n.addr, tuple(_canon(proj, n.irsb))) for n in model.graph.nodes()),
        sorted((u.addr, v.addr, d["jumpkind"]) for u, v, d in model.graph.edges(data=True)),
    )


class TestJoinWholeChains(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90" * 16, "AMD64", load_address=0x1000)
        self.proj.vm_select_load_deltas = {}

    def _diamond_with_chains(self):
        # 0x1000 -> 0x1010 -> 0x1020 -> 0x1030 -> {0x1040, 0x1050}; 0x1040 -> 0x1060 -> 0x1030 (loop);
        # 0x1050 -> 0x1070. Node order puts chain tails first so pairwise rounds join out of order.
        arch = self.proj.arch
        order = [0x1070, 0x1020, 0x1060, 0x1000, 0x1050, 0x1030, 0x1010, 0x1040]
        succ = {0x1000: 0x1010, 0x1010: 0x1020, 0x1020: 0x1030, 0x1040: 0x1060, 0x1060: 0x1030, 0x1050: 0x1070}
        irsbs = [_tmp_block(arch, a, succ.get(a, a + 0x10), store_value=a) for a in order]
        edges = [*succ.items(), (0x1030, 0x1040), (0x1030, 0x1050)]
        return _cfg(self.proj, irsbs, edges)

    def test_whole_chain_join_equals_pairwise_rounds_to_fixpoint(self):
        self.proj.vm_deob_join_whole_chains = False
        a = _analysis(self.proj, 0x1000)
        pair, _ = self._diamond_with_chains()
        rounds = 0
        while True:
            before = _shape(self.proj, pair)
            a.join_basic_blocks(pair, self.proj, 0x1000, None)
            rounds += 1
            if _shape(self.proj, pair) == before:
                break
        assert rounds > 2

        self.proj.vm_deob_join_whole_chains = True
        a = _analysis(self.proj, 0x1000)
        whole, _ = self._diamond_with_chains()
        a.join_basic_blocks(whole, self.proj, 0x1000, None)
        assert _shape(self.proj, whole) == _shape(self.proj, pair)
        assert sorted(n.addr for n in whole.graph.nodes()) == [0x1000, 0x1030, 0x1040, 0x1050]

    def _dae_then_join(self, whole_chain):
        """Block DAE before or after joining A -> B, A: two stores, B: symbolic load, then a third store."""
        arch = self.proj.arch
        model, nodes = _cfg(
            self.proj,
            [_store_block(arch, 0x1000, 0x1010, [1, 2]), _tmp_block(arch, 0x1010, 0x1020, store_value=3)],
            [(0x1000, 0x1010)],
        )
        a = _analysis(self.proj, 0x1000)
        if whole_chain:
            a._join_chain(model, model, nodes[0x1000], False)
            a._eliminate_dead_assignments(model, self.proj)
        else:
            a._eliminate_dead_assignments(model, self.proj)
            a._join_with_successor(model, model, nodes[0x1000], False)
        return _canon(self.proj, nodes[0x1000].irsb)

    def test_block_dae_does_not_depend_on_block_boundaries(self):
        # STle(GLOBAL) = 1 is overwritten by STle(GLOBAL) = 2 before any load. Scanning for symbolic loads up to the
        # block's last store instead (in B once joined) kept it in the joined block only.
        self.proj.vm_deob_dae_first_overwrite = False
        assert self._dae_then_join(True) != self._dae_then_join(False)

        self.proj.vm_deob_dae_first_overwrite = True
        joined_first = self._dae_then_join(True)
        assert joined_first == self._dae_then_join(False)
        stores = [s for s in joined_first if s.startswith("STle")]
        assert stores == ["STle(0x0000000000002000) = 0x0000000000000002", "STle(0x0000000000002000) = 0x0000000000000003"]

    def test_symbolic_load_before_the_overwrite_keeps_the_store(self):
        self.proj.vm_deob_dae_first_overwrite = True
        arch = self.proj.arch
        # STle(GLOBAL) = 1; t1 = LDle(t0); ...; STle(GLOBAL) = 3: the load may read the first store
        irsb = _tmp_block(arch, 0x1000, 0x1010, store_value=3)
        irsb.statements = [pyvex.stmt.IMark(0x1000, 1, 0), pyvex.stmt.Store(_c64(GLOBAL), _c64(1), "Iend_LE"),
                           *irsb.statements]
        model, nodes = _cfg(self.proj, [irsb], [])
        _analysis(self.proj, 0x1000)._eliminate_dead_assignments(model, self.proj)
        stores = [s for s in _canon(self.proj, nodes[0x1000].irsb) if s.startswith("STle")]
        assert len(stores) == 2


if __name__ == "__main__":
    unittest.main()
