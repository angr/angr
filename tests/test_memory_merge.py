# pylint:disable=isinstance-second-argument-not-valid-type

import claripy

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


def test_merge_memory_object_endness():

    for memcls in [UltraPageMemory, ListPageMemory]:
        state0 = SimState(arch='AMD64', mode='symbolic', plugins={'memory': memcls()})
        state0.memory.store(0x20000, claripy.BVS("x", 64), endness="Iend_LE")

        state1 = SimState(arch="AMD64", mode="symbolic", plugins={'memory': memcls()})
        state1.memory.store(0x20000, claripy.BVS("y", 64), endness="Iend_LE")

        state, _, _ = state0.merge(state1)
        obj = state.memory.load(0x20000, size=8, endness="Iend_LE")
        assert isinstance(obj, claripy.ast.Base)
        # the original endness should be respected, and obj.op should not be Reverse
        assert obj.op == "If"


def test_merge_seq():
    state1 = SimState(arch='AMD64', mode='symbolic', plugins={'memory': UltraPageMemory()})
    state2 = SimState(arch='AMD64', mode='symbolic', plugins={'memory': UltraPageMemory()})

    state1.regs.rsp = 0x80000000
    state2.regs.rsp = 0x80000000

    state1.memory.store(state1.regs.rsp, 0x11, 1)
    state1.memory.store(state1.regs.rsp + 1, 0x22, 1)
    state2.memory.store(state2.regs.rsp, 0xAA, 1)
    state2.memory.store(state2.regs.rsp + 1, 0xBB, 1)

    state3, _, __ = state1.merge(state2)
    vals = [v for v in state3.solver.eval_upto(state3.memory.load(state3.regs.rsp, 2), 10)]
    assert set([0x1122, 0xaabb]) == set(vals)


if __name__ == '__main__':
    test_merge_seq()
    test_merge_memory_object_endness()
