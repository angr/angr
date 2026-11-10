#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import tempfile
import unittest

import pyvex
from pyvex.const import U64
from pyvex.expr import Binop, Const, Get, Load, RdTmp, Unop
from pyvex.stmt import IMark, Put, WrTmp

import angr
from angr import claripy
from angr.analyses.cfg.cfg_vm_deobfuscation import CFGVMDeobfuscation
from angr.analyses.vm_deobfuscation.deobf_reader import load_decompilation_input
from angr.analyses.vm_deobfuscation.deobf_writer import dump_decompilation_input
from angr.analyses.vm_deobfuscation.entry_seeds import seed_locations
from angr.analyses.vm_deobfuscation.vex_concrete_fold import seeded_fold_tmps
from angr.analyses.vm_deobfuscation.vm_deobfuscation import VMDeobfuscation
from angr.knowledge_plugins.cfg.block_id import BlockID
from angr.knowledge_plugins.cfg.cfg_node import CFGENode
from angr.knowledge_plugins.functions.function import Function

ADDR = 0x1000
VIP = 0x1100  # byte code: 0x5a
VIP2 = 0x1180
KEY = 0x0F
SLOT = 0x5A ^ KEY  # the VM register the byte code names
CTX = 0x100  # context base - sp
BID = BlockID.new(ADDR, (), "normal", VIP)


def _project():
    code = b"\x90" * 0x100 + b"\x5a" + b"\x00" * 0xFF
    proj = angr.load_shellcode(code, "AMD64", load_address=ADDR)
    proj.byte_code_regions = [(VIP, VIP + 0xFF)]
    return proj


def _handler(arch):
    """Decode a byte-code byte, reload the VIP from the VM register it names, and read byte code through it."""
    r = arch.registers
    stmts = [
        IMark(ADDR, 1, 0),
        WrTmp(0, Get(r["rsi"][0], "Ity_I64")),
        WrTmp(1, Load("Iend_LE", "Ity_I8", RdTmp(0))),
        WrTmp(2, Get(r["rbx"][0], "Ity_I64")),
        WrTmp(3, Unop("Iop_64to8", [RdTmp(2)])),
        WrTmp(4, Binop("Iop_Xor8", [RdTmp(1), RdTmp(3)])),
        WrTmp(5, Unop("Iop_8Uto64", [RdTmp(4)])),
        WrTmp(6, Get(r["rdi"][0], "Ity_I64")),
        WrTmp(7, Binop("Iop_Add64", [RdTmp(6), RdTmp(5)])),
        WrTmp(8, Load("Iend_LE", "Ity_I64", RdTmp(7))),
        WrTmp(9, Load("Iend_LE", "Ity_I8", RdTmp(8))),
        WrTmp(10, Unop("Iop_8Uto64", [RdTmp(9)])),
        Put(RdTmp(10), r["rdx"][0]),
    ]
    types = ["Ity_I64", "Ity_I8", "Ity_I64", "Ity_I8", "Ity_I8", "Ity_I64", "Ity_I64", "Ity_I64", "Ity_I64", "Ity_I8",
             "Ity_I64"]
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


class TestEntrySeedContext(unittest.TestCase):
    def setUp(self):
        self.proj = _project()
        a = self.proj.arch
        self.irsb = _handler(a)
        self.rsi, self.rdi = a.registers["rsi"], a.registers["rdi"]
        self.cfg = object.__new__(CFGVMDeobfuscation)
        self.cfg.project = self.proj
        self.cfg._seed_regs_cache = {}
        self.sp = claripy.BVS("precon_sp", 64)

    def _arrival(self, ctx=CTX, other=0x1111, flags=None, irsb=None):
        s = self.proj.factory.blank_state(addr=ADDR)
        s.add_constraints(self.sp == 0x7FFE_0000)
        s.regs.sp = self.sp
        s.regs.rsi = VIP
        s.regs.rbx = KEY
        s.regs.rdi = self.sp + ctx
        le = self.proj.arch.memory_endness
        s.memory.store(self.sp + ctx + SLOT, claripy.BVV(VIP2, 64), endness=le)
        s.memory.store(self.sp + ctx + 0x10, claripy.BVV(other, 64), endness=le)
        # a VM register holding a program input
        s.memory.store(self.sp + ctx + 0x20, claripy.BVS("input", 64) if flags is None else claripy.BVV(flags, 64))
        s.globals["cur_vm_reg"] = self.rsi
        self.cfg._record_block_entry_vip(BID, s, irsb=irsb or self.irsb)
        return self.proj.vm_entry_seeds.get(BID)

    def _mem(self, seeds):
        return {k[2]: v for k, v in seeds.items() if k[0] == "mem"}

    def test_scan_finds_the_context(self):
        # the operand is one byte: the context is what it reaches, plus the word read there
        assert seed_locations(self.irsb, self.rsi[0], self.proj.arch)[2] == {(self.rdi[0], 0, 0xFF + 8)}

    def test_arrivals_agree_bytewise(self):
        vip2 = {SLOT + i: b for i, b in enumerate(VIP2.to_bytes(8, "little"))}
        seeds = self._arrival(flags=0x44)
        assert seeds[("ctx", self.rdi[0], 8)] == CTX
        mem = self._mem(seeds)
        assert vip2.items() <= mem.items() and mem[0x10] == 0x11 and mem[0x27] == 0x44
        # a symbolic slot and a slot holding another value are dropped; the low byte of 0x1011 still agrees
        mem = self._mem(self._arrival(other=0x1011))
        assert vip2.items() <= mem.items() and mem[0x10] == 0x11 and 0x11 not in mem and 0x27 not in mem
        # and stay dropped
        assert 0x27 not in self._mem(self._arrival(flags=0x44))
        # another base: the context is not one place, its bytes go too
        seeds = self._arrival(ctx=CTX + 8)
        assert set(seeds) == {("vip", self.rsi[0], 8), ("key", self.proj.arch.registers["rbx"][0], 8)}

    def test_context_is_recorded_at_blocks_that_do_not_index_it(self):
        self._arrival()
        other = BlockID.new(ADDR + 0x40, (), "normal", VIP + 1)
        irsb = self.proj.factory.block(ADDR + 0x40, size=1).vex  # a nop
        s = self.proj.factory.blank_state(addr=ADDR + 0x40)
        s.add_constraints(self.sp == 0x7FFE_0000)
        s.regs.sp = self.sp
        s.regs.rsi = VIP + 1
        s.regs.rdi = self.sp + CTX
        s.memory.store(self.sp + CTX + 0x30, claripy.BVV(0x99, 8))
        s.globals["cur_vm_reg"] = self.rsi
        self.cfg._record_block_entry_vip(other, s, irsb=irsb)
        assert self.proj.vm_entry_seeds[other][("mem", self.rdi[0], 0x30)] == 0x99

    def test_fold_reloads_the_vip_from_the_context(self):
        seeds = self._arrival()
        folded = seeded_fold_tmps(self.proj, self.irsb, seeds, VIP)
        # the reloaded VIP only addresses byte code; the byte read through it is a value and stays
        consts = _consts(folded)
        assert consts[5] == SLOT and consts[8] == VIP2 and 9 not in consts and 6 not in consts
        registers = {k: v for k, v in seeds.items() if k[0] in ("vip", "key")}
        assert 8 not in _consts(seeded_fold_tmps(self.proj, self.irsb, registers, VIP))

    def test_context_seeds_survive_the_dump_and_the_checkpoint(self):
        seeds = self._arrival()
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
            fresh = _project()
            fresh.vm_deob_entry_seeds = False  # compare the table, not the fold
            load_decompilation_input(fresh, path)
        assert fresh.vm_entry_seeds == {BID: seeds}
        assert self.proj.vm_seed_contexts == {self.rdi[0]: (0, 0xFF + 8)}
        assert "vm_seed_contexts" in VMDeobfuscation._CHECKPOINT_PROJECT_ATTRS


if __name__ == "__main__":
    unittest.main()
