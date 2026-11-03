#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import types
import unittest

from angr.analyses.cfg.cfg_vm_deobfuscation import CFGVMDeobfuscation
from angr.knowledge_plugins.cfg.block_id import BlockID


class _Solver:
    def __init__(self, vals):
        self._vals = vals

    def eval_one(self, e):
        if len(self._vals[e]) != 1:
            raise ValueError("not one")
        return self._vals[e][0]

    def eval_upto(self, e, n):
        return self._vals[e][:n]


def _state(ip=None, sp=None, **globals_):
    vals = {"ip": [ip] if ip is not None else [1, 2], "sp": [sp] if sp is not None else [1, 2]}
    solver = _Solver(vals)
    return types.SimpleNamespace(
        regs=types.SimpleNamespace(ip="ip", sp="sp"),
        solver=solver,
        partial_symbolic_constraint_solver=solver,
        globals=dict(globals_),
    )


def _cfg(seen_vpcs, composite=()):
    return types.SimpleNamespace(
        project=types.SimpleNamespace(existing_vpc_values=set(seen_vpcs), composite_vpc_values=set(composite)),
        _MAX_VPC_STEP=CFGVMDeobfuscation._MAX_VPC_STEP,
    )


def _job(entry_vpc, reg=(64, 8)):
    return types.SimpleNamespace(
        addr=0x2538F,
        block_id=BlockID.new(0x2538F, (), "normal", entry_vpc),
        state=_state(cur_vm_reg=reg),
    )


class TestStaleVIPSwitch(unittest.TestCase):
    def test_switch_to_seen_vpc_is_stale(self):
        # halt_cleanup_helper: at the VM exit the VIP finder moves from rsi to rcx, which holds the earlier VPC 429464
        cfg = _cfg([429464])
        assert CFGVMDeobfuscation._stale_vip_switch(cfg, _job(417849), 429464, _state(cur_vm_reg=(24, 8)))

    def test_switch_to_new_vpc_is_kept(self):
        # a re-entry stub loading a fresh VIP into another register
        cfg = _cfg([429464])
        assert not CFGVMDeobfuscation._stale_vip_switch(cfg, _job(417849), 438922, _state(cur_vm_reg=(24, 8)))

    def test_same_register_jump_is_kept(self):
        # a VM jump back to a seen VPC keeps the VIP register
        cfg = _cfg([429464])
        assert not CFGVMDeobfuscation._stale_vip_switch(cfg, _job(417849), 429464, _state(cur_vm_reg=(64, 8)))

    def test_small_step_is_kept(self):
        cfg = _cfg([417845])
        assert not CFGVMDeobfuscation._stale_vip_switch(cfg, _job(417849), 417845, _state(cur_vm_reg=(24, 8)))

    def test_composite_is_kept(self):
        cfg = _cfg([429464], composite=[429464])
        assert not CFGVMDeobfuscation._stale_vip_switch(cfg, _job(417849), 429464, _state(cur_vm_reg=(24, 8)))


class TestVMExitFrame(unittest.TestCase):
    def test_back_on_entry_frame(self):
        job = types.SimpleNamespace(state=_state(sp=0x7FF48, vm_entry_sp=0x7FF48, start_deobfuscation=True))
        assert CFGVMDeobfuscation._back_on_vm_entry_frame(job)

    def test_handler_below_entry_frame(self):
        job = types.SimpleNamespace(state=_state(sp=0x7FF28, vm_entry_sp=0x7FF48, start_deobfuscation=True))
        assert not CFGVMDeobfuscation._back_on_vm_entry_frame(job)

    def test_not_in_vm(self):
        job = types.SimpleNamespace(state=_state(sp=0x7FF48, vm_entry_sp=0x7FF48, start_deobfuscation=False))
        assert not CFGVMDeobfuscation._back_on_vm_entry_frame(job)


class TestVMRegionTag(unittest.TestCase):
    def test_tag_only_inside_vm(self):
        assert CFGVMDeobfuscation._vm_region_tag(_state(vm_region_tag=7, start_deobfuscation=True)) == 7
        assert CFGVMDeobfuscation._vm_region_tag(_state(vm_region_tag=7, start_deobfuscation=False)) is None
        assert CFGVMDeobfuscation._vm_region_tag(_state(start_deobfuscation=True)) is None


if __name__ == "__main__":
    unittest.main()
