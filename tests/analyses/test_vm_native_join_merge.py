#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import types
import unittest
from collections import defaultdict

import angr
from angr.analyses.cfg.cfg_vm_deobfuscation import CFGVMDeobfuscation
from angr.knowledge_plugins.cfg.block_id import BlockID

JOIN = 0x25383


def _cfg(project):
    cfg = types.SimpleNamespace(
        project=project,
        vm_function_extent=(0x25180, 0x2550F),
        _join_states={},
        _join_widened={},
        _join_version=0,
        _join_stats=defaultdict(int),
        _traced_addrs=defaultdict(lambda: defaultdict(int)),
        _max_iterations=1,
    )
    cfg._differing_locations = CFGVMDeobfuscation._differing_locations
    cfg._entry_sp = lambda: None
    return cfg


def _job(project, dil):
    state = project.factory.blank_state(addr=JOIN)
    state.regs.rdi = dil
    state.globals["vm_exited"] = True
    state.globals["start_deobfuscation"] = False
    return types.SimpleNamespace(
        state=state, vm_vpc=None, block_id=BlockID.new(JOIN, (), "normal", None), call_stack_suffix=()
    )


class TestNativeJoinMerge(unittest.TestCase):
    """CNICdriver halt_cleanup_helper: two native paths with different dil join at 0x25383 before VM4."""

    def test_widening_reaches_a_fixpoint(self):
        project = angr.load_shellcode(b"\x90" * 16, arch="amd64", load_address=JOIN)
        cfg = _cfg(project)
        first = _job(project, 1)
        CFGVMDeobfuscation._merge_at_native_join(cfg, first, JOIN)
        assert first.state.globals.get("join_gen", 0) == 0  # first arrival is only recorded
        cfg._traced_addrs[(None,)][JOIN] = 1

        second = _job(project, 0)
        CFGVMDeobfuscation._merge_at_native_join(cfg, second, JOIN)
        assert second.state.globals["join_gen"] == 1
        # the VM after the join sees dil unknown, under a name fixed by the join and the register
        assert second.state.regs.rdi.symbolic
        assert "join_25383_reg_" in next(iter(second.state.regs.rdi.variables))

        # arrivals that differ only where the join is already widened change nothing
        for dil in (2, 0):
            again = _job(project, dil)
            CFGVMDeobfuscation._merge_at_native_join(cfg, again, JOIN)
            assert again.state.globals.get("join_gen", 0) == 0
        assert cfg._join_version == 1

    def test_no_merge_inside_the_vm_or_outside_the_function(self):
        project = angr.load_shellcode(b"\x90" * 16, arch="amd64", load_address=JOIN)
        cfg = _cfg(project)
        for job in (_job(project, 1), _job(project, 0)):
            job.vm_vpc = 0x1234
            CFGVMDeobfuscation._merge_at_native_join(cfg, job, JOIN)
        assert not cfg._join_states
        cfg.vm_function_extent = (0x30000, 0x30100)
        CFGVMDeobfuscation._merge_at_native_join(cfg, _job(project, 1), JOIN)
        assert not cfg._join_states


if __name__ == "__main__":
    unittest.main()
