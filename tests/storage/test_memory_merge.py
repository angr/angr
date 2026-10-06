#!/usr/bin/env python3
# pylint:disable=isinstance-second-argument-not-valid-type,missing-class-docstring,no-self-use
from __future__ import annotations

import unittest
from unittest import TestCase

from angr import SimState, claripy
from angr.claripy.annotation import UninitializedAnnotation
from angr.storage.memory_mixins import (
    AddressConcretizationMixin,
    ConvenientMappingsMixin,
    DataNormalizationMixin,
    ListPagesMixin,
    PagedMemoryMixin,
    SizeNormalizationMixin,
    SymbolicMergerMixin,
    UltraPage,
    UltraPagesMixin,
)
from angr.storage.memory_mixins.paged_memory.pages.history_tracking_mixin import MAX_HISTORY_DEPTH
from tests.common import minimal_project


class UltraPageMemory(
    DataNormalizationMixin,
    SizeNormalizationMixin,
    AddressConcretizationMixin,
    SymbolicMergerMixin,
    ConvenientMappingsMixin,
    UltraPagesMixin,
    PagedMemoryMixin,
):
    pass


class ListPageMemory(
    DataNormalizationMixin,
    SizeNormalizationMixin,
    AddressConcretizationMixin,
    SymbolicMergerMixin,
    ConvenientMappingsMixin,
    ListPagesMixin,
    PagedMemoryMixin,
):
    pass


class TestMemoryMerge(TestCase):
    @staticmethod
    def _static_state():
        return SimState(project=minimal_project("AMD64"), mode="static")

    @staticmethod
    def _si(lo, hi, bits=32):
        return claripy.SI(bits=bits, stride=1, lower_bound=lo, upper_bound=hi)

    @staticmethod
    def _bounds(v):
        return claripy.vsa.min(v), claripy.vsa.max(v)

    def test_static_merge_concrete_into_symbolic(self):
        # ours is concrete and already covered by their interval: the join must still replace ours, i.e. "unchanged"
        # has to be judged against our value, not theirs
        a = self._static_state()
        b = a.copy()
        a.memory.store(0x1000, claripy.BVV(0, 32), endness="Iend_LE")
        b.memory.store(0x1000, self._si(0, 3), endness="Iend_LE")

        merged, _, occurred = a.merge(b, plugin_whitelist=("memory",))
        assert occurred
        assert self._bounds(merged.memory.load(0x1000, 4, endness="Iend_LE")) == (0, 3)

    def test_static_merge_keeps_object_whole(self):
        # ours: one 4-byte object; theirs: two 2-byte objects. The join is one named object that replace_all() can find
        a = self._static_state()
        b = a.copy()
        a.memory.store(0x1000, self._si(0, 10), endness="Iend_LE")
        b.memory.store(0x1000, self._si(0, 1, 16), endness="Iend_LE")
        b.memory.store(0x1002, self._si(0, 1, 16), endness="Iend_LE")

        merged, _, _ = a.merge(b, plugin_whitelist=("memory",))
        v = merged.memory.load(0x1000, 4, endness="Iend_LE")
        assert v.op == "BVS"
        region = merged.memory._regions["global"]
        for name in v.variables:
            assert set(region.addrs_for_name(name)) == set(range(0x1000, 0x1004))

        merged.memory.replace_all(v, v.intersection(self._si(0, 5)))
        assert claripy.vsa.max(merged.memory.load(0x1000, 4, endness="Iend_LE")) == 5

    def test_static_merge_records_changed_bytes(self):
        # a merged object must show up in changed_bytes(), otherwise a later widening pass skips it
        a = self._static_state()
        a.memory.store(0x1000, self._si(0, 10), endness="Iend_LE")
        b = a.copy()
        b.memory.store(0x1000, self._si(0, 20), endness="Iend_LE")

        merged, _, _ = a.merge(b, plugin_whitelist=("memory",))
        changed = a.memory._regions["global"].changed_bytes(merged.memory._regions["global"])
        assert set(range(0x1000, 0x1004)) <= changed

    def test_static_widen(self):
        a = self._static_state()
        b = a.copy()
        a.memory.store(0x1000, self._si(0, 8), endness="Iend_LE")
        b.memory.store(0x1000, self._si(0, 9), endness="Iend_LE")
        a.regs.rax = self._si(0, 8, 64)
        b.regs.rax = self._si(0, 9, 64)

        merged, _, _ = a.merge(b, plugin_whitelist=("memory", "registers"))
        assert claripy.vsa.max(merged.memory.load(0x1000, 4, endness="Iend_LE")) == 9
        assert claripy.vsa.max(merged.regs.rax) == 9

        widened = a.copy()
        widened.memory.widen([b.memory])
        widened.registers.widen([b.registers])
        assert claripy.vsa.max(widened.memory.load(0x1000, 4, endness="Iend_LE")) > 9
        assert claripy.vsa.max(widened.regs.rax) > 9

    def test_static_merge_uninitialized_rule(self):
        # a never-written default (bare BVS) is dropped from the join; a value derived from one still takes part
        uninit = claripy.BVS("u", 32).annotate(UninitializedAnnotation())

        a = self._static_state()
        b = a.copy()
        a.memory.store(0x1000, uninit, endness="Iend_LE")
        b.memory.store(0x1000, claripy.BVV(5, 32), endness="Iend_LE")
        merged, _, _ = a.merge(b, plugin_whitelist=("memory",))
        assert self._bounds(merged.memory.load(0x1000, 4, endness="Iend_LE")) == (5, 5)

        a = self._static_state()
        b = a.copy()
        a.memory.store(0x1000, uninit + 1, endness="Iend_LE")
        b.memory.store(0x1000, claripy.BVV(5, 32), endness="Iend_LE")
        merged, _, _ = a.merge(b, plugin_whitelist=("memory",))
        assert self._bounds(merged.memory.load(0x1000, 4, endness="Iend_LE")) == (0, 0xFFFFFFFF)

    def test_merge_memory_object_endness(self):
        for memcls in [UltraPageMemory, ListPageMemory]:
            state0 = SimState(project=minimal_project("AMD64"), mode="symbolic", plugins={"memory": memcls()})
            state0.memory.store(0x20000, claripy.BVS("x", 64), endness="Iend_LE")

            state1 = SimState(project=minimal_project("AMD64"), mode="symbolic", plugins={"memory": memcls()})
            state1.memory.store(0x20000, claripy.BVS("y", 64), endness="Iend_LE")

            state, _, _ = state0.merge(state1)
            obj = state.memory.load(0x20000, size=8, endness="Iend_LE")
            assert isinstance(obj, claripy.ast.Base)
            # the original endness should be respected, and obj.op should not be Reverse
            assert obj.op == "If"

    def test_merge_seq(self):
        state1 = SimState(project=minimal_project("AMD64"), mode="symbolic", plugins={"memory": UltraPageMemory()})
        state2 = SimState(project=minimal_project("AMD64"), mode="symbolic", plugins={"memory": UltraPageMemory()})

        state1.regs.rsp = 0x80000000
        state2.regs.rsp = 0x80000000

        state1.memory.store(state1.regs.rsp, 0x11, 1)
        state1.memory.store(state1.regs.rsp + 1, 0x22, 1)
        state2.memory.store(state2.regs.rsp, 0xAA, 1)
        state2.memory.store(state2.regs.rsp + 1, 0xBB, 1)

        state3, _, __ = state1.merge(state2)
        vals = (v for v in state3.solver.eval_upto(state3.memory.load(state3.regs.rsp, 2), 10))
        assert {0x1122, 0xAABB} == set(vals)

    def test_history_tracking(self):
        state = SimState(project=minimal_project("AMD64"), mode="symbolic", plugins={"memory": UltraPageMemory()})

        states = [state]

        for i in range(25):
            state = state.copy()
            states.append(state)  # keep references
            state.memory.store(i, claripy.BVV(i, 8))

        assert len(state.memory._pages) == 1
        page: UltraPage = next(iter(state.memory._pages.values()))

        parents = list(page.parents())
        assert len(parents) == 24

    def test_history_tracking_collapse(self):
        state = SimState(project=minimal_project("AMD64"), mode="symbolic", plugins={"memory": UltraPageMemory()})
        state.memory.store(1000, claripy.BVV(1, 8))

        states = [state]

        for i in range(MAX_HISTORY_DEPTH + 4):
            state = state.copy()
            states.append(state)  # keep references
            state.memory.store(i, claripy.BVV(i, 8))
            assert next(iter(state.memory._pages.values()))._history_depth == (i + 1) % (MAX_HISTORY_DEPTH + 1)

        assert len(state.memory._pages) == 1
        page: UltraPage = next(iter(state.memory._pages.values()))

        parents = list(page.parents())
        assert len(parents) == 3


if __name__ == "__main__":
    unittest.main()
