#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import unittest

import angr
from angr.analyses.cfg.cfg_vm_deobfuscation import CFGVMDeobfuscation
from angr.knowledge_plugins.cfg.block_id import BlockID

RAX, RSI = (16, 8), (64, 8)
HEAD = BlockID.new(0x2223B, (), "normal", 396722)  # CNIC cmd_CP: the handler at VIP 396722


class TestEntryVipConsistency(unittest.TestCase):
    """A block id entered with another VIP than it was traced at is another handler instance."""

    def setUp(self):
        self.proj = angr.load_shellcode(b"\x90" * 16, "AMD64", load_address=0x1000)
        self.proj.vip_at_block_entry = {}
        self.proj.composite_vpc_values = set()
        self.cfg = object.__new__(CFGVMDeobfuscation)
        self.cfg.project = self.proj

    def _state(self, rsi, rax, vip_reg):
        s = self.proj.factory.blank_state(addr=0x1000)
        s.regs.rsi = rsi
        s.regs.rax = rax
        s.globals["cur_vm_reg"] = vip_reg
        return s

    def test_mislabelled_arrival_is_kept_apart(self):
        self.cfg._record_block_entry_vip(HEAD, self._state(396722, 0, RSI))
        # the VIP finder switched to rax, which held a decoded jump target, while the handler still reads rsi
        late = self._state(396593, 396722, RAX)
        assert self.cfg._entry_vip_mismatch(HEAD, late) == (396593, RSI)
        # the first trace's record stands
        self.cfg._record_block_entry_vip(HEAD, late)
        assert self.proj.vip_at_block_entry[HEAD] == (64, 8, 396722)

        self.cfg._track_vip_reg(late, RSI)
        assert (late.globals["cur_vm_reg"], late.globals["cur_vm_vpc"], late.globals["vpc"]) == (RSI, 396593, 396593)

    def test_agreeing_arrival_merges(self):
        self.cfg._record_block_entry_vip(HEAD, self._state(396722, 0, RSI))
        assert self.cfg._entry_vip_mismatch(HEAD, self._state(396722, 5, RAX)) is None

    def test_untraced_or_composite_block_is_left_alone(self):
        assert self.cfg._entry_vip_mismatch(HEAD, self._state(396593, 0, RSI)) is None
        self.cfg._record_block_entry_vip(HEAD, self._state(396722, 0, RSI))
        self.proj.composite_vpc_values.add(HEAD.vm_vpc)
        assert self.cfg._entry_vip_mismatch(HEAD, self._state(396593, 0, RSI)) is None


if __name__ == "__main__":
    unittest.main()
