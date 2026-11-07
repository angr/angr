#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import logging
import types
import unittest

import angr
from angr.analyses.cfg.cfg_vm_deobfuscation import CFGVMDeobfuscation
from angr.analyses.vm_deobfuscation.vm_deobfuscation import VMDeobfuscation
from angr.knowledge_plugins.cfg.block_id import BlockID


class _Node:
    def __init__(self, addr, vpc, irsb=None):
        self.addr, self.block_id, self.irsb, self.is_simprocedure = addr, BlockID.new(addr, (), "normal", vpc), irsb, False


class TestReentryRegionTags(unittest.TestCase):
    """CNICdriver sub_239a0: the VM re-entry at 0x23a82, retraced under widened native-join states."""

    def test_a_reentry_keeps_its_region_tag_across_retraces(self):
        cfg = types.SimpleNamespace(_vm_region_count=0, _VM_REGION_TAG_BASE=CFGVMDeobfuscation._VM_REGION_TAG_BASE)
        entry, other = BlockID.new(0x23A82, (), "normal", None), BlockID.new(0x23A42, (), "normal", None)
        tag = CFGVMDeobfuscation._vm_region_tag_for(cfg, entry)
        assert tag > CFGVMDeobfuscation._VM_REGION_TAG_BASE
        # a retrace re-enters the same region, so its successor keeps its block id
        assert CFGVMDeobfuscation._vm_region_tag_for(cfg, entry) == tag
        assert CFGVMDeobfuscation._vm_region_tag_for(cfg, other) != tag

    def test_a_jump_with_two_successors_is_flagged_not_resolved(self):
        # jmp 0x1010 with two successors (0x23a82 -> 0x629b1 under region tags ...985 and ...986)
        project = angr.load_shellcode(b"\xe9\x0b\x00\x00\x00" + b"\x90" * 0x20, arch="amd64", load_address=0x1000)
        src = _Node(0x1000, None, project.factory.block(0x1000).vex)
        succs = [_Node(0x1010, 0x7E00000000000001), _Node(0x1010, 0x7E00000000000002)]
        cfg = types.SimpleNamespace(nodes=lambda: [src], get_successors=lambda n: succs if n is src else [])
        project.same_ip_split_guards = {}
        deob = types.SimpleNamespace(project=project, start_addr=0x1000)
        deob._add_same_ip_guard = types.MethodType(VMDeobfuscation._add_same_ip_guard, deob)
        with self.assertLogs("angr.analyses.vm_deobfuscation.vm_deobfuscation", logging.WARNING) as logs:
            VMDeobfuscation.convert_to_data_sensitive_irsb(deob, cfg, project, None)
        assert any("no conditional exit but 2 successors" in m for m in logs.output)
        assert project.vm_ambiguous_successor_blocks == [src.block_id]
        assert src.irsb.next.con.block_id is None  # neither successor is named


if __name__ == "__main__":
    unittest.main()
