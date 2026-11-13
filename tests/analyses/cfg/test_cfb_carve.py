#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
"""CFBlanket.add_obj/_carve against the original two-range-query implementation on random overlap sequences."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import random
import unittest

import angr
from angr.analyses.cfg.cfb import CFBlanket, Unknown
from angr.block import Block
from angr.knowledge_base import KnowledgeBase
from angr.knowledge_plugins.cfg.memory_data import MemoryData, MemoryDataSort
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class _ReferenceCFBlanket(CFBlanket):
    """
    The original add_obj/_carve: one floor query and one range query per add, pop-and-reinsert of every overlapping
    key, callbacks fired while carving.
    """

    def add_obj(self, addr, obj):
        size = self._obj_size(obj)
        if size is not None and size > 0:
            self._ref_carve(addr, addr + size)
        self._blanket[addr] = obj
        if self._on_object_added_callback:
            self._on_object_added_callback(addr, obj)

    def _ref_carve(self, start: int, end: int) -> None:
        overlapping: list[int] = []
        floor_key = next(self._blanket.irange(maximum=start - 1, reverse=True), None)
        if floor_key is not None:
            floor_size = self._obj_size(self._blanket[floor_key])
            if floor_key + max(floor_size or 1, 1) > start:
                overlapping.append(floor_key)
        overlapping.extend(self._blanket.irange(minimum=start, maximum=end - 1))

        for key in overlapping:
            obj = self._blanket.pop(key)
            obj_end = key + max(self._obj_size(obj) or 1, 1)
            if key < start:
                left = self._trim(obj, key, start)
                if left is not None:
                    self._blanket[key] = left
                    if self._on_object_added_callback:
                        self._on_object_added_callback(key, left)
            if obj_end > end:
                right = self._trim(obj, end, obj_end)
                if right is not None:
                    self._blanket[end] = right
                    if self._on_object_added_callback:
                        self._on_object_added_callback(end, right)


def _desc(obj) -> tuple:
    if isinstance(obj, Block):
        return ("Block", obj.addr, obj.size, obj.thumb)
    if isinstance(obj, Unknown):
        return ("Unknown", obj.addr, obj.size, obj.object, obj.section, obj._loader is not None)
    if isinstance(obj, MemoryData):
        return ("MemoryData", obj.addr, obj.size, obj.sort, obj.reference_size)
    return (type(obj).__name__, obj)


class TestCFBlanketCarve(unittest.TestCase):
    def _blanket(self, cls, proj, events):
        cfb = proj.analyses[cls].prep(kb=KnowledgeBase(proj))(on_object_added=lambda a, o: events.append((a, _desc(o))))
        events.clear()
        return cfb

    def _random_objs(self, proj, rng: random.Random, base: int, span: int, n: int) -> list:
        objs = []
        for _ in range(n):
            addr = base + rng.randrange(span)
            size = rng.choice((1, 2, 3, 4, 7, 8, 16, 33, 64, 200))
            kind = rng.randrange(5)
            if kind == 0:
                objs.append((addr, proj.factory.block(addr, size=size)))
            elif kind == 1:
                objs.append((addr, MemoryData(addr, size, MemoryDataSort.Integer, reference_size=4)))
            elif kind == 2:
                objs.append((addr, Unknown(addr, size, loader=proj.loader)))
            elif kind == 3:
                # neighboring adds: the common sequential CFG pattern
                prev = objs[-1][0] if objs else addr
                objs.append((prev + 4, proj.factory.block(prev + 4, size=size)))
            else:
                # objects without an integer size occupy one byte and are never trimmed
                objs.append((addr, f"obj_{addr:x}"))
        return objs

    def test_random_sequences_match_reference(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        base = proj.loader.main_object.sections_map[".text"].vaddr
        ev_ref: list = []
        ev_new: list = []
        for seed in range(40):
            rng = random.Random(seed)
            objs = self._random_objs(proj, rng, base, 0x300, 150)
            ref = self._blanket(_ReferenceCFBlanket, proj, ev_ref)
            new = self._blanket(CFBlanket, proj, ev_new)
            if seed % 2:
                # tiny SortedList sublists: lookups cross sublist boundaries
                new._blanket._list._reset(4)
            for addr, obj in objs:
                ref.add_obj(addr, obj)
                new.add_obj(addr, obj)
                if rng.random() < 0.05:
                    key = rng.choice(list(ref._blanket.irange(minimum=base, maximum=base + 0x300)))
                    ref.remove_obj(key)
                    new.remove_obj(key)
            assert ev_new == ev_ref, f"seed {seed}: callbacks differ"
            assert [(a, _desc(o)) for a, o in new._blanket.items()] == [
                (a, _desc(o)) for a, o in ref._blanket.items()
            ], f"seed {seed}: items differ"

    def test_carve_edges(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        base = proj.loader.main_object.sections_map[".text"].vaddr
        ev_ref: list = []
        ev_new: list = []
        ref = self._blanket(_ReferenceCFBlanket, proj, ev_ref)
        new = self._blanket(CFBlanket, proj, ev_new)
        seq = [
            (base, proj.factory.block(base, size=0x20)),
            # exactly at an existing key, same size: replaced without pieces
            (base, proj.factory.block(base, size=0x20)),
            # exactly at an existing key, shorter: right piece only
            (base, proj.factory.block(base, size=0x8)),
            # strictly inside: left and right pieces
            (base + 0xC, MemoryData(base + 0xC, 4, MemoryDataSort.Integer)),
            # covers several keys and ends inside the next one
            (base + 0x4, proj.factory.block(base + 0x4, size=0x14)),
            # an untrimmable floor object overlapping the start is dropped
            (base + 0x40, "untrimmable"),
            (base + 0x40, proj.factory.block(base + 0x40, size=0)),
            (base + 0x3F, proj.factory.block(base + 0x3F, size=2)),
            # no overlap at all, past the last key of the region
            (base + 0x1000, proj.factory.block(base + 0x1000, size=4)),
        ]
        for addr, obj in seq:
            ref.add_obj(addr, obj)
            new.add_obj(addr, obj)
            assert ev_new == ev_ref
            assert [(a, _desc(o)) for a, o in new._blanket.items()] == [(a, _desc(o)) for a, o in ref._blanket.items()]


if __name__ == "__main__":
    unittest.main()
