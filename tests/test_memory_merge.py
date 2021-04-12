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


if __name__ == '__main__':
    test_merge_memory_object_endness()
