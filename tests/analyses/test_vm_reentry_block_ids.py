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


def _cfg(extent=(0x25180, 0x2550F)):
    return types.SimpleNamespace(
        _VM_REGION_TAG_BASE=CFGVMDeobfuscation._VM_REGION_TAG_BASE,
        _on_vm_entry_frame=CFGVMDeobfuscation._on_vm_entry_frame,
        vm_function_extent=extent,
    )


def _job(vpc):
    return types.SimpleNamespace(addr=0x2538F, block_id=BlockID.new(0x2538F, (), "normal", vpc))


def _succ(sp, jumpkind="Ijk_Ret", ip=0x251B0):
    st = _state(ip=ip, sp=sp, vm_entry_sp=0x7FF28, start_deobfuscation=True)
    st.history = types.SimpleNamespace(jumpkind=jumpkind)
    return st


class TestStaleVIPSwitch(unittest.TestCase):
    def test_exit_keeps_vpc(self):
        # halt_cleanup_helper: the ret at 0x2538f returns to the entry frame while the VIP finder moves to 429464
        assert CFGVMDeobfuscation._stale_vip_switch(_cfg(), _job(417849), 429464, _succ(0x7FF28))

    def test_vm_internal_return_relabels(self):
        # a VM-internal return to a saved VPC runs below the entry frame
        assert not CFGVMDeobfuscation._stale_vip_switch(_cfg(), _job(379248), 416504, _succ(0x7FF20))

    def test_jump_to_entry_frame_relabels(self):
        # only a ret can be the shared exit
        assert not CFGVMDeobfuscation._stale_vip_switch(_cfg(), _job(417849), 429464, _succ(0x7FF28, "Ijk_Boring"))

    def test_ret_dispatch_outside_extent_relabels(self):
        # VMP 3.10 handlers dispatch via ret on the entry frame
        assert not CFGVMDeobfuscation._stale_vip_switch(_cfg(), _job(417849), 417842, _succ(0x7FF28, ip=0x6AC69))

    def test_no_extent_is_noop(self):
        assert not CFGVMDeobfuscation._stale_vip_switch(_cfg(None), _job(417849), 429464, _succ(0x7FF28))

    def test_no_vpc_yet(self):
        assert not CFGVMDeobfuscation._stale_vip_switch(_cfg(), _job(None), 429464, _succ(0x7FF28))

    def test_region_tag_relabels(self):
        tag = CFGVMDeobfuscation._VM_REGION_TAG_BASE + 1
        assert not CFGVMDeobfuscation._stale_vip_switch(_cfg(), _job(tag), 429464, _succ(0x7FF28))


class TestVMExitFrame(unittest.TestCase):
    def test_back_on_entry_frame(self):
        assert CFGVMDeobfuscation._on_vm_entry_frame(_state(sp=0x7FF48, vm_entry_sp=0x7FF48, start_deobfuscation=True))

    def test_handler_below_entry_frame(self):
        assert not CFGVMDeobfuscation._on_vm_entry_frame(
            _state(sp=0x7FF28, vm_entry_sp=0x7FF48, start_deobfuscation=True)
        )

    def test_not_in_vm(self):
        assert not CFGVMDeobfuscation._on_vm_entry_frame(
            _state(sp=0x7FF48, vm_entry_sp=0x7FF48, start_deobfuscation=False)
        )


class TestVMRegionTag(unittest.TestCase):
    def test_tag_only_inside_vm(self):
        assert CFGVMDeobfuscation._vm_region_tag(_state(vm_region_tag=7, start_deobfuscation=True)) == 7
        assert CFGVMDeobfuscation._vm_region_tag(_state(vm_region_tag=7, start_deobfuscation=False)) is None
        assert CFGVMDeobfuscation._vm_region_tag(_state(start_deobfuscation=True)) is None


if __name__ == "__main__":
    unittest.main()
