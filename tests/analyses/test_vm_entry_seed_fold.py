#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import tempfile
import unittest
from unittest import mock

import pyvex
from pyvex.const import U64
from pyvex.expr import Binop, Const, Get, Load, RdTmp, Unop
from pyvex.stmt import IMark, Put, WrTmp

import angr
from angr.analyses.vm_deobfuscation.deobf_reader import load_decompilation_input
from angr.analyses.vm_deobfuscation.deobf_writer import dump_decompilation_input
from angr.analyses.vm_deobfuscation.entry_seeds import apply_seeded_fold
from angr.analyses.vm_deobfuscation.vex_concrete_fold import fold_concrete_tmps, seeded_fold_tmps
from angr.knowledge_plugins.cfg.block_id import BlockID
from angr.knowledge_plugins.cfg.cfg_node import CFGENode
from angr.knowledge_plugins.functions.function import Function

ADDR = 0x1000
VIP = 0x1100  # byte code: 0x5a
KEY = 0x0F
BID = BlockID.new(ADDR, (), "normal", VIP)


def _project():
    code = b"\x90" * 0x100 + b"\x5a" + b"\x00" * 0xFF
    proj = angr.load_shellcode(code, "AMD64", load_address=ADDR)
    proj.byte_code_regions = [(VIP, VIP + 0xFF)]
    return proj


def _handler(arch):
    """Decode one byte-code byte with the key, read the VM register it names, and keep the decoded byte in rdx."""
    r = arch.registers
    stmts = [
        IMark(ADDR, 1, 0),
        WrTmp(0, Get(r["rsi"][0], "Ity_I64")),
        WrTmp(1, Load("Iend_LE", "Ity_I8", RdTmp(0))),
        WrTmp(2, Get(r["rbx"][0], "Ity_I64")),
        WrTmp(3, Unop("Iop_64to8", [RdTmp(2)])),
        WrTmp(4, Binop("Iop_Xor8", [RdTmp(1), RdTmp(3)])),
        WrTmp(5, Unop("Iop_8Uto64", [RdTmp(4)])),
        WrTmp(6, Get(r["rsp"][0], "Ity_I64")),
        WrTmp(7, Binop("Iop_Add64", [RdTmp(6), RdTmp(5)])),
        WrTmp(8, Load("Iend_LE", "Ity_I64", RdTmp(7))),
        Put(RdTmp(8), r["rcx"][0]),
        # the decoded byte is also a program value: t4 must stay
        WrTmp(9, Unop("Iop_8Uto64", [RdTmp(4)])),
        Put(RdTmp(9), r["rdx"][0]),
    ]
    types = ["Ity_I64", "Ity_I8", "Ity_I64", "Ity_I8", "Ity_I8", "Ity_I64", "Ity_I64", "Ity_I64", "Ity_I64", "Ity_I64"]
    return pyvex.IRSB.empty_block(
        arch,
        ADDR,
        statements=stmts,
        tyenv=pyvex.block.IRTypeEnv(arch, types=types),
        nxt=Const(U64(ADDR + 0x10)),
        jumpkind="Ijk_Boring",
        size=1,
    )


def _consts(irsb):
    return {s.tmp: s.data.con.value for s in irsb.statements if isinstance(s, WrTmp) and isinstance(s.data, Const)}


class TestEntrySeedFold(unittest.TestCase):
    def setUp(self):
        self.proj = _project()
        a = self.proj.arch
        self.irsb = _handler(a)
        self.seeds = {("vip", a.registers["rsi"][0], 8): VIP, ("key", a.registers["rbx"][0], 8): KEY}

    def test_folds_only_address_tmps(self):
        assert fold_concrete_tmps(self.proj, self.irsb) is None
        folded = seeded_fold_tmps(self.proj, self.irsb, self.seeds, VIP)
        assert folded is not None
        # the byte-code address and the VM register index; not the decoded byte, which rdx also takes, nor the
        # sp-relative address
        assert _consts(folded) == {0: VIP, 5: 0x5A ^ KEY}

    def test_label_must_be_a_vip_of_the_block(self):
        assert seeded_fold_tmps(self.proj, self.irsb, self.seeds, VIP + 0x50) is None

    def test_no_vip_no_fold(self):
        seeds = {k: v for k, v in self.seeds.items() if k[0] != "vip"}
        assert seeded_fold_tmps(self.proj, self.irsb, seeds, VIP) is None

    def test_reader_applies_the_seeded_fold(self):
        self.proj.vm_entry_seeds[BID] = self.seeds
        model = self.proj.kb.cfgs.new_model("deobf_graph")
        node = CFGENode(ADDR, 1, model, irsb=self.irsb, block_id=BID, function_address=ADDR)
        func = Function(self.proj.kb.functions, ADDR, "VM_1", None, is_simprocedure=False)
        self.proj.kb.functions[func.addr] = func
        func.register_node(True, node)
        func.startpoint = node
        func.mark_ret_site(node)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "dump.json.gz")
            dump_decompilation_input(func, self.proj, path, vm_deobfuscation=True)
            results = {}
            for env in ("1", "0"):
                with mock.patch.dict(os.environ, {"PUSHAN_ENTRY_SEEDS": env}):
                    fresh = _project()
                    loaded, _ = load_decompilation_input(fresh, path)
                    (n,) = [x for x in loaded.transition_graph.nodes() if getattr(x, "irsb", None) is not None]
                    results[env] = _consts(n.irsb)
        assert results == {"1": {0: VIP, 5: 0x5A ^ KEY}, "0": {}}
        # the in-process path folds the same
        assert apply_seeded_fold(self.proj, [node]) == 1 and _consts(node.irsb) == results["1"]


if __name__ == "__main__":
    unittest.main()
