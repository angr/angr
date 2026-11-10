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
from angr.analyses.vm_deobfuscation.entry_seeds import seed_locations, seed_scan
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

    def test_operand_read_in_the_block_before(self):
        a, r = self.proj.arch, self.proj.arch.registers

        def block(stmts, types):
            return pyvex.IRSB.empty_block(a, ADDR, statements=[IMark(ADDR, 1, 0), *stmts], size=1, jumpkind="Ijk_Boring",
                                          tyenv=pyvex.block.IRTypeEnv(a, types=types), nxt=Const(U64(ADDR + 0x10)))

        # one block reads the operand into rax, the next indexes the context with it
        read = block([WrTmp(0, Get(r["rsi"][0], "Ity_I64")), WrTmp(1, Load("Iend_LE", "Ity_I8", RdTmp(0))),
                      WrTmp(2, Unop("Iop_8Uto64", [RdTmp(1)])), Put(RdTmp(2), r["rax"][0])],
                     ["Ity_I64", "Ity_I8", "Ity_I64"])
        index = block([WrTmp(0, Get(r["rdi"][0], "Ity_I64")), WrTmp(1, Get(r["rax"][0], "Ity_I64")),
                       WrTmp(2, Binop("Iop_Add64", [RdTmp(0), RdTmp(1)])), WrTmp(3, Load("Iend_LE", "Ity_I64", RdTmp(2))),
                       Put(RdTmp(3), r["rax"][0])],
                      ["Ity_I64"] * 4)
        ops = seed_scan(read, self.rsi[0], a)[3]
        assert ops == {(r["rax"][0], 8)}
        assert not seed_scan(index, self.rsi[0], a)[2]
        scan = seed_scan(index, self.rsi[0], a, ops)
        assert scan[2] == {(self.rdi[0], 0, 0xFF + 8)}
        # rax is overwritten there: no longer an operand
        assert not scan[3]
        # a block that leaves rax alone passes it on
        assert seed_scan(self.proj.factory.block(ADDR + 0x40, size=1).vex, self.rsi[0], a, ops)[3] == ops

    def test_operand_registers_follow_the_path(self):
        a, r = self.proj.arch, self.proj.arch.registers
        read = pyvex.IRSB.empty_block(
            a, ADDR, size=1, jumpkind="Ijk_Boring", nxt=Const(U64(ADDR + 0x10)),
            statements=[IMark(ADDR, 1, 0), WrTmp(0, Get(r["rsi"][0], "Ity_I64")),
                        WrTmp(1, Load("Iend_LE", "Ity_I8", RdTmp(0))), WrTmp(2, Unop("Iop_8Uto64", [RdTmp(1)])),
                        Put(RdTmp(2), r["rax"][0])],
            tyenv=pyvex.block.IRTypeEnv(a, types=["Ity_I64", "Ity_I8", "Ity_I64"]))
        s, succ = self.proj.factory.blank_state(addr=ADDR), self.proj.factory.blank_state(addr=ADDR + 0x10)
        s.globals["cur_vm_reg"] = self.rsi
        self.cfg._track_operand_regs(s, read, [succ])
        assert succ.globals["vm_operand_regs"] == {(r["rax"][0], 8)}
        # a copy of the state keeps them; without the VIP register nothing is known
        assert succ.copy().globals["vm_operand_regs"] == {(r["rax"][0], 8)}
        del s.globals["cur_vm_reg"]
        self.cfg._track_operand_regs(s, read, [succ])
        assert not succ.globals["vm_operand_regs"]

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

    def _nop_arrival(self, byte=0x99, other=0x55, ctx=CTX):
        bid = BlockID.new(ADDR + 0x40, (), "normal", VIP + 1)
        irsb = self.proj.factory.block(ADDR + 0x40, size=1).vex  # a nop
        s = self.proj.factory.blank_state(addr=ADDR + 0x40)
        s.add_constraints(self.sp == 0x7FFE_0000)
        s.regs.sp = self.sp
        s.regs.rsi = VIP + 1
        s.regs.rdi = self.sp + ctx
        s.memory.store(self.sp + ctx + 0x30, claripy.BVV(byte, 8))
        s.memory.store(self.sp + ctx + 0x38, claripy.BVV(other, 8))
        s.globals["cur_vm_reg"] = self.rsi
        self.cfg._record_block_entry_vip(bid, s, irsb=irsb)
        return self.proj.vm_entry_seeds.get(bid)

    def test_context_is_recorded_at_blocks_that_do_not_index_it(self):
        self._arrival()
        assert self._nop_arrival()[("mem", self.rdi[0], 0x30)] == 0x99

    def test_arrivals_before_the_context_is_known_get_it(self):
        ctx = ("ctx", self.rdi[0], 8)
        assert ctx not in self._nop_arrival()
        assert ctx not in self._nop_arrival(other=0x56)
        self._arrival()  # the first block that indexes the context
        seeds = self._nop_arrival()
        assert seeds[ctx] == CTX and self._mem(seeds) == {0x30: 0x99}
        # the earlier arrivals are not held any longer
        assert not self.cfg._seed_pending

    def test_snapshot_gives_the_seeds_of_the_state(self):
        from angr.analyses.vm_deobfuscation.entry_seeds import context_seeds, context_snapshot, entry_seeds

        s = self.proj.factory.blank_state(addr=ADDR)
        s.add_constraints(self.sp == 0x7FFE_0000)
        s.regs.sp = self.sp
        s.regs.rsi = VIP
        s.regs.rdi = self.sp + CTX
        s.memory.store(self.sp + CTX + 3, claripy.BVV(0x1122334455667788, 64))
        s.memory.store(self.sp + CTX + 0x40, claripy.BVS("input", 64))
        s.memory.store(self.sp + CTX + 0x100, claripy.BVV(0xAABB, 16))
        contexts = [(self.rdi[0], 0, 0xFF + 8)]
        single = self.cfg._single_value
        want = {k: v for k, v in entry_seeds(s, self.rsi, (), (), single, contexts).items() if k[0] != "vip"}
        assert len(want) == 11 and context_seeds([context_snapshot(s, single)], contexts) == want
        # no register at a constant distance from the stack pointer: nothing to keep
        s.regs.rdi = claripy.BVS("p", 64)
        assert context_snapshot(s, single) is None

    def test_early_arrivals_at_another_base_get_no_context(self):
        self._nop_arrival()
        self._nop_arrival(ctx=CTX + 8)
        self._arrival()
        assert not any(k[0] in ("ctx", "mem") for k in self._nop_arrival())

    def test_arrivals_of_an_earlier_run_are_not_filled_in(self):
        self._nop_arrival()
        # another CFG run: the states of the first arrival are gone
        self.cfg = object.__new__(CFGVMDeobfuscation)
        self.cfg.project = self.proj
        self._nop_arrival()
        self._arrival()
        assert not any(k[0] in ("ctx", "mem") for k in self._nop_arrival())

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
