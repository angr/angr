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
        _join_prevm_states={},
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

    def test_a_page_only_one_state_touched_differs(self):
        # CNICdriver sub_239a0: one arrival wrote the global g_69bab (page 0x69000), the other never touched the page
        project = angr.load_shellcode(b"\x00" * 0x2000, arch="amd64", load_address=0x68000)
        untouched = project.factory.blank_state(addr=0x68000)
        written = untouched.copy()
        written.memory.store(0x69BAB, 0x56BB0, size=8, endness="Iend_LE")
        expected = [("mem", 0x69BAB + i, 1) for i in range(3)]  # b0 6b 05: the nonzero bytes
        for a, b in ((untouched, written), (written, untouched)):
            locs = CFGVMDeobfuscation._differing_locations(a, b)
            assert [loc for loc in locs if loc[0] == "mem"] == expected

    def test_a_global_assigned_after_the_vm_less_pass_is_widened(self):
        # CNICdriver sub_239a0: the first pass through the join read g_69bab == 0 before any VM ran; every arrival after
        # a VM exit has the VM's lazily initialized pointer there. Only that image word is widened, not the registers
        project = angr.load_shellcode(b"\x00" * 0x2000, arch="amd64", load_address=0x68000)
        cfg = _cfg(project)
        cfg._traced_addrs[(None,)][JOIN] = 1
        pre = _job(project, 1)
        pre.state.globals["vm_exited"] = False
        CFGVMDeobfuscation._merge_at_native_join(cfg, pre, JOIN)
        assert JOIN in [k.addr for k in cfg._join_prevm_states] and not cfg._join_states

        post = _job(project, 0)  # dil differs too: the VM context is not widened against the VM-less pass
        post.state.memory.store(0x69BAB, 0x56BB0, size=8, endness="Iend_LE")
        CFGVMDeobfuscation._merge_at_native_join(cfg, post, JOIN)
        assert post.state.globals["join_gen"] == 1
        g = post.state.memory.load(0x69BAB, 3, inspect=False)
        assert g.symbolic and all(v.startswith("join_25383_mem_69ba") for v in g.variables)
        assert not post.state.regs.rdi.symbolic

    def test_each_arrival_of_a_generation_is_traced(self):
        # CNICdriver sub_239a0: 0x27a5b at VPC 406887 is reached in generation 17 from 0x25469 (successor 0x2806a)
        # and from 0x28ec6 (successor 0x27a64, the lazy-init arm); the second arrival must be traced too
        cfg = types.SimpleNamespace(_join_traced_gen={}, _join_traced_srcs={})
        for name in ("_new_arrival_in_join_gen", "_note_join_gen_trace"):
            setattr(cfg, name, types.MethodType(getattr(CFGVMDeobfuscation, name), cfg))
        key = ((406887,), 0x27A5B)
        path_b = BlockID.new(0x25469, (), "normal", 406887)
        path_a = BlockID.new(0x28EC6, (), "normal", 406887)
        assert not cfg._new_arrival_in_join_gen(key, 17, path_b)  # a newer generation retraces anyway
        cfg._join_traced_gen[key] = 17
        assert cfg._note_join_gen_trace(key, 17, path_b)  # the first trace replaces the earlier successors
        assert cfg._new_arrival_in_join_gen(key, 17, path_a)
        assert not cfg._note_join_gen_trace(key, 17, path_a)  # a later one adds its own
        assert not cfg._new_arrival_in_join_gen(key, 17, path_a)  # but traces once per source
        assert not cfg._new_arrival_in_join_gen(key, 0, path_a)

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
