#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.knowledge_plugins.cfg.indirect_jump import IndirectJump
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestIndirectJumps(unittest.TestCase):
    def test_cfg_publishes_indirect_jump_records(self):
        # control-flow recovery must leave behind a record of every indirect jump and call site it encountered, not
        # just the bare block-address-to-targets mapping
        proj = angr.Project(os.path.join(test_location, "x86_64", "fpijr_global_table"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        indirect_jumps = proj.kb.indirect_jumps

        assert indirect_jumps
        for block_addr, record in indirect_jumps.items():
            assert isinstance(record, IndirectJump)
            # the records are keyed by the address of the block the site ends, and that block has to exist
            assert record.addr == block_addr
            node = cfg.model.get_any_node(block_addr)
            assert node is not None
            # the site itself is one of the instructions of that block, in the function the block belongs to
            assert record.ins_addr in node.instruction_addrs
            assert record.func_addr in proj.kb.functions
            assert record.jumpkind in ("Ijk_Boring", "Ijk_Call")
            # resolved_targets is a set no matter which path filled it in
            assert isinstance(record.resolved_targets, set)

        # every site that was resolved or left unresolved is one of the published records
        resolved = set(indirect_jumps.resolved)
        unresolved = set(indirect_jumps.unresolved)
        assert resolved
        assert unresolved
        assert not resolved & unresolved
        assert (resolved | unresolved) <= set(indirect_jumps)

        # a resolved site agrees with its record, and this one is a jump table
        for block_addr, targets in indirect_jumps.resolved.items():
            record = indirect_jumps[block_addr]
            assert record.resolved_targets == set(targets)
            assert record.jumptable
            assert record.jumptable_entries

        # an unresolved site has a record with no targets
        for block_addr in unresolved:
            assert not indirect_jumps[block_addr].resolved_targets

    def test_copy_preserves_records_and_outcomes(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fpijr_global_table"), auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        indirect_jumps = proj.kb.indirect_jumps

        copied = indirect_jumps.copy()
        assert dict(copied) == dict(indirect_jumps)
        assert copied.unresolved == indirect_jumps.unresolved
        assert copied.resolved == indirect_jumps.resolved

        # and it is a copy: mutating it must not reach back into the original
        block_addr = next(iter(indirect_jumps.resolved))
        copied.resolved[block_addr].append(0xDEADBEEF)
        copied.unresolved.add(0xDEADBEEF)
        assert 0xDEADBEEF not in indirect_jumps.resolved[block_addr]
        assert 0xDEADBEEF not in indirect_jumps.unresolved


if __name__ == "__main__":
    unittest.main()
