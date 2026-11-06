#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import tempfile
import unittest

import angr
from angr import claripy
from angr.analyses.cfg.cfg_vm_deobfuscation import CFGVMDeobfuscation
from angr.analyses.vm_deobfuscation.deobf_reader import load_decompilation_input
from angr.analyses.vm_deobfuscation.deobf_writer import dump_decompilation_input
from angr.analyses.vm_deobfuscation.entry_seeds import seed_registers
from angr.knowledge_plugins.cfg.block_id import BlockID
from angr.knowledge_plugins.cfg.cfg_node import CFGENode
from angr.knowledge_plugins.functions.function import Function

# a VMProtect-style handler: fetch a byte-code byte, decode it with the rolling key, pop the VM stack
HANDLER = bytes.fromhex(
    "0fb606"  # movzx eax, byte [rsi]
    "30d8"  # xor al, bl
    "488b4d00"  # mov rcx, [rbp]
    "4883c508"  # add rbp, 8
    "488b3a"  # mov rdi, [rdx]       rdx: a program pointer into the stack
    "48ffc6"  # inc rsi
    "ffe0"  # jmp rax
)
ADDR = 0x1000
VIP = 0x5000
BID = BlockID.new(ADDR, (), "normal", VIP)


class TestEntrySeedRecording(unittest.TestCase):
    def setUp(self):
        self.proj = angr.load_shellcode(HANDLER, "AMD64", load_address=ADDR)
        self.irsb = self.proj.factory.block(ADDR).vex
        self.cfg = object.__new__(CFGVMDeobfuscation)
        self.cfg.project = self.proj
        self.cfg._seed_regs_cache = {}
        self.sp = claripy.BVS("precon_sp", 64)
        self.rsi = self.proj.arch.registers["rsi"]

    def _arrival(self, key=0x77, vsp=0x40, rdx=0x10):
        s = self.proj.factory.blank_state(addr=ADDR)
        s.regs.sp = self.sp
        s.regs.rsi = VIP
        s.regs.rbx = key
        s.regs.rbp = self.sp + vsp
        s.regs.rdx = self.sp + rdx
        s.globals["cur_vm_reg"] = self.rsi
        self.cfg._record_block_entry_vip(BID, s, irsb=self.irsb)
        return self.proj.vm_entry_seeds.get(BID)

    def test_scan_finds_key_and_vm_stack_pointer_only(self):
        a = self.proj.arch
        keys, vsps = seed_registers(self.irsb, self.rsi[0], a)
        assert keys == {a.registers["rbx"][0]}
        assert vsps == {a.registers["rbp"][0]}

    def test_arrivals_intersect(self):
        rbx, rbp = self.proj.arch.registers["rbx"][0], self.proj.arch.registers["rbp"][0]
        assert self._arrival() == {("vip", 64, 8): VIP, ("key", rbx, 8): 0x77, ("vsp", rbp, 8): 0x40}
        # rdx, a stack address, is not VM bookkeeping; a disagreeing key is dropped
        assert self._arrival(key=0x78, rdx=0x18) == {("vip", 64, 8): VIP, ("vsp", rbp, 8): 0x40}
        assert self._arrival(vsp=0x48) == {("vip", 64, 8): VIP}

    def test_a_disagreeing_vip_stops_tracking(self):
        self._arrival()
        s = self.proj.factory.blank_state(addr=ADDR)
        s.regs.rsi = VIP + 1
        s.globals["cur_vm_reg"] = self.rsi
        self.cfg._record_block_entry_vip(BID, s, irsb=self.irsb)
        assert BID in self.proj.vm_entry_seeds and self.proj.vm_entry_seeds[BID] is None
        assert self._arrival() is None

    def test_seeds_survive_the_dump(self):
        seeds = self._arrival()
        model = self.proj.kb.cfgs.new_model("deobf_graph")
        node = CFGENode(ADDR, len(HANDLER), model, irsb=self.irsb, block_id=BID, function_address=ADDR)
        func = Function(self.proj.kb.functions, ADDR, "VM_1", None, is_simprocedure=False)
        self.proj.kb.functions[func.addr] = func
        func.register_node(True, node)
        func.startpoint = node
        func.mark_ret_site(node)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "dump.json.gz")
            dump_decompilation_input(func, self.proj, path, vm_deobfuscation=True)
            fresh = angr.load_shellcode(HANDLER, "AMD64", load_address=ADDR)
            load_decompilation_input(fresh, path)
        assert fresh.vm_entry_seeds == {BID: seeds}


if __name__ == "__main__":
    unittest.main()
