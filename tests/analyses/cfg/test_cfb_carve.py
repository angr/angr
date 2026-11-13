#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
"""CFBlanket.add_obj/_carve against the original two-range-query implementation on random overlap sequences."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import random
import unittest

import cle

import angr
from angr.analyses.cfg.cfb import CFBlanket, Unknown
from angr.block import Block
from angr.knowledge_base import KnowledgeBase
from angr.knowledge_plugins.cfg.memory_data import MemoryData, MemoryDataSort
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class _ReferenceCFBlanket(CFBlanket):
    """
    The original add_obj/_carve (one floor query and one range query per add, pop-and-reinsert of every overlapping
    key, callbacks fired while carving) and _mark_unknowns_core (floor and ceiling queries per object).
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

    def _mark_unknowns_core(self, min_addr, max_addr, obj=None, segment=None, section=None):
        try:
            addr = self.floor_addr(min_addr)
            if addr < min_addr:
                raise KeyError
        except KeyError:
            try:
                next_addr = self.ceiling_addr(min_addr)
                if next_addr >= max_addr:
                    raise KeyError
            except KeyError:
                next_addr = max_addr

            size = next_addr - min_addr
            loader = None if obj is None or isinstance(obj, cle.ExternObject) else self.project.loader
            self.add_obj(
                min_addr, Unknown(min_addr, size, object_=obj, segment=segment, section=section, loader=loader)
            )

        addr = min_addr
        while addr < max_addr:
            last_addr, last_item = self.floor_item(addr)
            last_item_size = 1 if last_item.size == 0 or last_item.size is None else last_item.size
            end_addr = last_addr + last_item_size
            if end_addr < max_addr:
                try:
                    next_addr = self.ceiling_addr(end_addr)
                except KeyError:
                    next_addr = max_addr
                if next_addr > end_addr:
                    size = next_addr - end_addr
                    loader = None if obj is None or isinstance(obj, cle.ExternObject) else self.project.loader
                    self.add_obj(
                        end_addr, Unknown(end_addr, size, object_=obj, segment=segment, section=section, loader=loader)
                    )
                addr = next_addr
            else:
                addr = max_addr


class _Opaque:
    """
    An object the blanket cannot trim: no integer size.
    """

    size = None

    def __init__(self, name: str):
        self.name = name


def _desc(obj) -> tuple:
    if isinstance(obj, Block):
        return ("Block", obj.addr, obj.size, obj.thumb)
    if isinstance(obj, Unknown):
        return ("Unknown", obj.addr, obj.size, obj.object, obj.section, obj._loader is not None)
    if isinstance(obj, MemoryData):
        return ("MemoryData", obj.addr, obj.size, obj.sort, obj.reference_size)
    assert isinstance(obj, _Opaque)
    return ("Opaque", obj.name)


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
                objs.append((addr, _Opaque(f"obj_{addr:x}")))
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
            keys = list(new._blanket.keys())
            for probe in [keys[0] - 1, keys[-1] + 1, *(base + rng.randrange(-0x10, 0x310) for _ in range(100))]:
                floor = next(new._blanket.irange(maximum=probe, reverse=True), None)
                ceiling = next(new._blanket.irange(minimum=probe), None)
                assert new._floor_key(probe) == floor, f"seed {seed}: floor of {probe:#x}"
                assert new._ceiling_key(probe) == ceiling, f"seed {seed}: ceiling of {probe:#x}"
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
            (base + 0x40, _Opaque("untrimmable")),
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

    def test_mark_unknowns_matches_reference(self):
        for binary in ("x86_64/fauxware", "armel/fauxware"):
            proj = angr.Project(os.path.join(test_location, binary), auto_load_libs=False)
            cfg = proj.analyses.CFGFast(normalize=True)
            ev_ref: list = []
            ev_new: list = []
            ref = proj.analyses[_ReferenceCFBlanket].prep(kb=cfg.kb)(
                on_object_added=lambda a, o, ev=ev_ref: ev.append((a, _desc(o)))
            )
            new = proj.analyses[CFBlanket].prep(kb=cfg.kb)(
                on_object_added=lambda a, o, ev=ev_new: ev.append((a, _desc(o)))
            )
            assert ev_new == ev_ref, binary
            assert [(a, _desc(o)) for a, o in new._blanket.items()] == [(a, _desc(o)) for a, o in ref._blanket.items()]

        # gaps around random objects, including zero-size and sizeless ones, and objects crossing region ends
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        text = proj.loader.main_object.sections_map[".text"]
        for seed in range(10):
            rng = random.Random(seed)
            ev_ref, ev_new = [], []
            ref = self._blanket(_ReferenceCFBlanket, proj, ev_ref)
            new = self._blanket(CFBlanket, proj, ev_new)
            for bl in (ref._blanket, new._blanket):
                bl.clear()
            for addr, obj in self._random_objs(proj, rng, text.vaddr - 0x20, text.memsize + 0x40, 60):
                ref._blanket[addr] = obj
                new._blanket[addr] = obj
            ref._mark_unknowns()
            new._mark_unknowns()
            assert ev_new == ev_ref, f"seed {seed}"
            assert [(a, _desc(o)) for a, o in new._blanket.items()] == [(a, _desc(o)) for a, o in ref._blanket.items()]


if __name__ == "__main__":
    unittest.main()
