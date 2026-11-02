#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import random
import re
import unittest

import angr
from angr import claripy
from angr.state_plugins.inspect import BP_AFTER, BP_BEFORE
from angr.storage.memory_mixins import DefaultListPagesMemory
from angr.storage.memory_mixins.fast_register_store import NO_FAST_LOAD, fast_register_load, fast_register_store


def _state():
    proj = angr.load_shellcode(b"\x90" * 16, arch="amd64")
    plugins = {"registers": DefaultListPagesMemory(memory_id="reg", endness=proj.arch.register_endness)}
    return angr.SimState(project=proj, plugins=plugins)


def _norm(v):
    # fresh symbols for unset registers carry a global counter
    return re.sub(r"_\d+_(\d+)\b", r"_N_\1", str(v))


def _attrs(state, prefix):
    return {k: str(v) for k, v in vars(state.inspect.attrs).items() if k.startswith(prefix)}


class TestFastRegisterStore(unittest.TestCase):
    def test_same_as_store_stack(self):
        rng = random.Random(1)
        x = claripy.BVS("x", 64)
        slow, fast = _state(), _state()
        for i in range(300):
            off = rng.choice((16, 24, 32, 40, 184, 192))
            size = rng.choice((1, 2, 4, 8))
            data = (x + i)[size * 8 - 1 : 0] if i % 3 else claripy.BVV(i, size * 8)
            offset = claripy.BVV(off, 32) if i % 2 else off
            slow.registers.store(offset, data, action=None, inspect=True)
            assert fast_register_store(fast, offset, data, True)
            assert _attrs(slow, "reg_write") == _attrs(fast, "reg_write")
            r_slow = slow.registers.load(offset, size, action=None, inspect=True)
            r_fast = fast_register_load(fast, offset, size, True)
            assert r_fast is not NO_FAST_LOAD
            assert r_slow is r_fast or str(r_slow) == str(r_fast)
            assert _attrs(slow, "reg_read") == _attrs(fast, "reg_read")
        for off in (16, 24, 32, 40, 184, 192):
            assert _norm(slow.registers.load(off, 8, inspect=False)) == _norm(
                fast.registers.load(off, 8, inspect=False)
            )

    def test_falls_back(self):
        state = _state()
        hits = []
        state.inspect.b("reg_write", when=BP_BEFORE, action=lambda s: hits.append(1))
        assert not fast_register_store(state, 16, claripy.BVV(1, 64), True)
        state.inspect.b("reg_read", when=BP_AFTER, action=lambda s: hits.append(2))
        assert fast_register_load(state, 16, 8, True) is NO_FAST_LOAD
        # symbolic offsets and non-default memories take the normal path
        assert not fast_register_store(_state(), claripy.BVS("o", 32), claripy.BVV(1, 64), True)
        proj = angr.load_shellcode(b"\x90" * 16, arch="amd64")
        assert not fast_register_store(proj.factory.blank_state(), 16, claripy.BVV(1, 64), True)


if __name__ == "__main__":
    unittest.main()
