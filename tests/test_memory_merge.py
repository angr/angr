# pylint:disable=isinstance-second-argument-not-valid-type,missing-class-docstring,no-self-use
import unittest
from unittest import TestCase

import claripy

from angr.storage.memory_mixins.paged_memory.pages.history_tracking_mixin import MAX_HISTORY_DEPTH
from angr.storage.memory_mixins import (
    DataNormalizationMixin,
    SizeNormalizationMixin,
    AddressConcretizationMixin,
    UltraPagesMixin,
    ListPagesMixin,
    PagedMemoryMixin,
    SymbolicMergerMixin,
    ConvenientMappingsMixin,
)
from angr import SimState
from angr.storage.memory_mixins import UltraPage


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
    def test_merge_memory_object_endness(self):
        for memcls in [UltraPageMemory, ListPageMemory]:
            state0 = SimState(arch="AMD64", mode="symbolic", plugins={"memory": memcls()})
            state0.memory.store(0x20000, claripy.BVS("x", 64), endness="Iend_LE")

            state1 = SimState(arch="AMD64", mode="symbolic", plugins={"memory": memcls()})
            state1.memory.store(0x20000, claripy.BVS("y", 64), endness="Iend_LE")

            state, _, _ = state0.merge(state1)
            obj = state.memory.load(0x20000, size=8, endness="Iend_LE")
            assert isinstance(obj, claripy.ast.Base)
            # the original endness should be respected, and obj.op should not be Reverse
            assert obj.op == "If"

    def test_merge_seq(self):
        state1 = SimState(arch="AMD64", mode="symbolic", plugins={"memory": UltraPageMemory()})
        state2 = SimState(arch="AMD64", mode="symbolic", plugins={"memory": UltraPageMemory()})

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
        state = SimState(arch="AMD64", mode="symbolic", plugins={"memory": UltraPageMemory()})

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
        state = SimState(arch="AMD64", mode="symbolic", plugins={"memory": UltraPageMemory()})
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
