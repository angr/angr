#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os.path
from unittest import TestCase, main

import angr
from angr.analyses.cfg.cfb import Unknown
from angr.knowledge_base import KnowledgeBase
from angr.knowledge_plugins.cfg.memory_data import MemoryData, MemoryDataSort
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def assert_no_overlap(cfb) -> None:
    """
    Assert that no two objects in the blanket overlap (objects without an integer size count as one byte).
    """
    prev_key, prev_end = None, None
    for key, obj in cfb._blanket.items():
        size = obj.size if isinstance(getattr(obj, "size", None), int) else None
        if prev_end is not None:
            assert key >= prev_end, f"object at {key:#x} overlaps the object at {prev_key:#x} (ends at {prev_end:#x})"
        prev_key, prev_end = key, key + max(size or 1, 1)


# pylint: disable=no-self-use
class CFBlanketTests(TestCase):
    """
    Test CFBlanket analysis
    """

    def _fresh_cfb(self, **kwargs):
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), load_options={"auto_load_libs": False})
        # a fresh knowledge base: the blanket covers the binary with Unknown regions only
        cfb = p.analyses.CFB(kb=KnowledgeBase(p), **kwargs)
        return p, cfb

    def test_on_object_added_callback(self):
        my_callback_artifacts = {}

        def my_callback(addr, obj):
            my_callback_artifacts[addr] = obj

        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), load_options={"auto_load_libs": False})
        cfb = p.analyses.CFB(on_object_added=my_callback)

        addr = 0x1_00000000
        obj = "my object"
        cfb.add_obj(addr, obj)
        assert addr in my_callback_artifacts and my_callback_artifacts[addr] == obj

    def test_lazy_unknown_bytes(self):
        p, cfb = self._fresh_cfb()
        main_object = p.loader.main_object
        unknowns = [
            obj
            for addr, obj in cfb._blanket.items()
            if isinstance(obj, Unknown) and main_object.min_addr <= addr < main_object.max_addr
        ]
        assert unknowns
        # nothing is loaded at construction time
        assert all(u._bytes is None for u in unknowns)

        u = max(unknowns, key=lambda x: x.size)
        loaded = u.bytes
        assert loaded is not None
        assert len(loaded) == min(u.size, Unknown.MAX_BYTES)
        # memoized
        assert u.bytes is loaded

    def test_add_block_carves_unknown(self):
        p, cfb = self._fresh_cfb()
        assert_no_overlap(cfb)

        # pick an address strictly inside an Unknown region so that both remainders exist
        unknown_addr, unknown = cfb.floor_item(p.loader.main_object.entry)
        assert isinstance(unknown, Unknown)
        unknown_end = unknown_addr + unknown.size
        addr = unknown_addr + 0x10

        block = p.factory.block(addr)
        cfb.add_obj(addr, block)
        assert_no_overlap(cfb)

        assert cfb._blanket[addr] is block
        # exact left remainder
        left_addr, left = cfb.floor_item(addr - 1)
        assert isinstance(left, Unknown)
        assert left_addr == unknown_addr
        assert left_addr + left.size == addr
        # exact right remainder
        right_addr, right = cfb.ceiling_item(addr + 1)
        assert isinstance(right, Unknown)
        assert right_addr == addr + block.size
        assert right_addr + right.size == unknown_end

    def test_block_overlap_left_contained_covered(self):
        p, cfb = self._fresh_cfb()
        addr = p.loader.main_object.entry
        block = p.factory.block(addr)
        cfb.add_obj(addr, block)

        # a block starting midway through the previous block trims the previous block (the jump-into-middle case)
        mid = addr + 8
        cfb.add_obj(mid, p.factory.block(mid))
        assert_no_overlap(cfb)
        trimmed = cfb._blanket[addr]
        assert trimmed.size == 8

        # a small block fully inside a larger block splits it into left and right block pieces
        p2, cfb2 = self._fresh_cfb()
        addr2 = p2.loader.main_object.entry
        big = p2.factory.block(addr2)
        assert big.size > 12
        cfb2.add_obj(addr2, big)
        inner_addr = addr2 + 8
        cfb2.add_obj(inner_addr, p2.factory.block(inner_addr, size=4))
        assert_no_overlap(cfb2)
        assert cfb2._blanket[addr2].size == 8
        right_addr, right_piece = cfb2.ceiling_item(inner_addr + 4)
        assert right_addr == inner_addr + 4
        assert right_addr + right_piece.size == addr2 + big.size

        # a block fully covering an existing block drops it
        p3, cfb3 = self._fresh_cfb()
        addr3 = p3.loader.main_object.entry
        cfb3.add_obj(addr3 + 8, p3.factory.block(addr3 + 8, size=4))
        covering = p3.factory.block(addr3)
        assert covering.size > 12
        cfb3.add_obj(addr3, covering)
        assert_no_overlap(cfb3)
        assert cfb3._blanket[addr3] is covering
        assert addr3 + 8 not in cfb3._blanket

    def test_memory_data_trim_is_copy(self):
        p, cfb = self._fresh_cfb()
        addr = p.loader.main_object.entry

        md = MemoryData(addr, 0x40, MemoryDataSort.Integer, reference_size=8)
        cfb.add_obj(addr, md)

        # a block overlapping the head of the memory data trims a copy
        block_addr = addr + 0x20
        cfb.add_obj(block_addr, p.factory.block(block_addr, size=0x30))
        assert_no_overlap(cfb)

        trimmed = cfb._blanket[addr]
        assert isinstance(trimmed, MemoryData)
        assert trimmed is not md
        assert trimmed.addr == addr
        assert trimmed.size == 0x20
        assert trimmed.reference_size == 8
        # the original is unmutated
        assert md.addr == addr
        assert md.size == 0x40

    def test_remove_obj_refills_unknown(self):
        added, removed = [], []
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), load_options={"auto_load_libs": False})
        cfb = p.analyses.CFB(
            kb=KnowledgeBase(p),
            on_object_added=lambda a, o: added.append((a, o)),
            on_object_removed=lambda a, o: removed.append((a, o)),
        )
        addr = p.loader.main_object.entry
        block = p.factory.block(addr)
        cfb.add_obj(addr, block)
        added.clear()

        out = cfb.remove_obj(addr)
        assert out is block
        assert removed and removed[-1] == (addr, block)
        filler = cfb._blanket[addr]
        assert isinstance(filler, Unknown)
        assert filler.size == block.size
        assert added and added[-1] == (addr, filler)
        assert filler.bytes is not None and len(filler.bytes) == block.size
        assert_no_overlap(cfb)

        # removing a missing address is a no-op
        assert cfb.remove_obj(0xDEADBEEF) is None

    def test_callbacks_fire_for_pieces(self):
        added = []
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), load_options={"auto_load_libs": False})
        cfb = p.analyses.CFB(kb=KnowledgeBase(p), on_object_added=lambda a, o: added.append((a, o)))

        # pick an address strictly inside an Unknown region so that both remainders exist
        unknown_addr, _unknown = cfb.floor_item(p.loader.main_object.entry)
        addr = unknown_addr + 0x10
        added.clear()

        block = p.factory.block(addr)
        cfb.add_obj(addr, block)
        # left remainder, right remainder, and the primary object are all reported
        reported = {(a, type(o).__name__) for a, o in added}
        assert (unknown_addr, "Unknown") in reported
        assert (addr + block.size, "Unknown") in reported
        assert (addr, "Block") in reported
        # the reported spans match what is in the blanket
        for a, o in added:
            assert cfb._blanket[a] is o

    def test_cfgfast_streaming_keeps_blanket_nonoverlapping(self):
        for arch, binary in (("x86_64", "fauxware"), ("armel", "fauxware")):
            p = angr.Project(os.path.join(test_location, arch, binary), load_options={"auto_load_libs": False})

            def check_neighbors(cfb_holder, addr, obj, _arch=arch):
                # O(log n) local invariant check on every added object
                cfb = cfb_holder[0]
                if cfb is None:
                    return
                size = obj.size if isinstance(getattr(obj, "size", None), int) else None
                end = addr + max(size or 1, 1)
                floor_key = next(cfb._blanket.irange(maximum=addr - 1, reverse=True), None)
                if floor_key is not None:
                    fobj = cfb._blanket.get(floor_key)
                    if fobj is not None:
                        fsize = fobj.size if isinstance(getattr(fobj, "size", None), int) else None
                        assert floor_key + max(fsize or 1, 1) <= addr, f"{_arch}: overlap left of {addr:#x}"
                ceil_key = next(cfb._blanket.irange(minimum=addr + 1), None)
                if ceil_key is not None:
                    assert ceil_key >= end, f"{_arch}: overlap right of {addr:#x}"

            holder = [None]
            cfb = p.analyses.CFB(
                kb=KnowledgeBase(p),
                exclude_region_types={"kernel", "tls"},
                on_object_added=lambda a, o, _h=holder, _check=check_neighbors: _check(_h, a, o),
            )
            holder[0] = cfb
            p.analyses.CFGFast(normalize=True, cfb=cfb)
            assert_no_overlap(cfb)


if __name__ == "__main__":
    main()
