#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
"""CFBlanket on the Rust interval store against the frozen SortedDict implementation (cfb_reference.py)."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import pickle
import random
import unittest

import angr
from angr.analyses.cfg.cfb import CFBlanket, Unknown
from angr.block import Block
from angr.knowledge_base import KnowledgeBase
from angr.knowledge_plugins.cfg.memory_data import MemoryData, MemoryDataSort
from tests.analyses.cfg.cfb_reference import ReferenceCFBlanket
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")
CHECK_ALL = False


def _row(addr, obj) -> list:
    if isinstance(obj, Block):
        return [addr, "Block", obj.addr, obj.size, obj.thumb]
    if isinstance(obj, Unknown):
        return [addr, "Unknown", obj.addr, obj.size, id(obj.object), id(obj.section), obj._loader is None, obj._bytes]
    if isinstance(obj, MemoryData):
        return [addr, "MemoryData", obj.addr, obj.size, obj.sort, obj.reference_size, obj.max_size, obj.content]
    return [addr, repr(obj)]


def _rows(cfb) -> list:
    return [_row(a, o) for a, o in cfb._blanket.items()]


class _Arm:
    def __init__(self, cls, proj, kb, batch: bool):
        self.events: list = []
        self.removed: list = []
        kwargs = {"exclude_region_types": {"kernel", "tls"}, "on_object_removed": lambda a, o: self.removed.append(a)}
        if batch:
            kwargs["on_objects_added"] = self.events.extend
        else:
            kwargs["on_object_added"] = lambda a, o: self.events.append((a, o))
        self.cfb = proj.analyses[cls].prep(kb=kb)(**kwargs)


class TestCfbStore(unittest.TestCase):
    def _fuzz(self, binary: str, seed: int, n_ops: int, batch: bool, with_cfg: bool):
        proj = angr.Project(os.path.join(test_location, binary), auto_load_libs=False)
        if with_cfg:
            cfg = proj.analyses.CFGFast(normalize=True)
            kb = cfg.kb
        else:
            kb = KnowledgeBase(proj)
        ref = _Arm(ReferenceCFBlanket, proj, kb, batch)
        new = _Arm(CFBlanket, proj, kb, batch)
        assert _rows(new.cfb) == _rows(ref.cfb)
        assert [_row(a, o) for a, o in new.events] == [_row(a, o) for a, o in ref.events]

        rng = random.Random(seed)
        # queries draw from their own generator, so that checking does not change the operations
        qrng = random.Random(seed + 1000)
        main_obj = proj.loader.main_object
        lo, hi = main_obj.min_addr, main_obj.max_addr
        is_arm = proj.arch.name.startswith("ARM")
        keys = list(ref.cfb._blanket.keys())

        def addr():
            r = rng.random()
            if r < 0.4 and keys:
                # an existing key, or next to one
                return max(0, rng.choice(keys) + rng.choice((0, 0, 0, -2, -1, 1, 2, 4)))
            return rng.randrange(lo, hi)

        def make(a: int):
            r = rng.random()
            if r < 0.45:
                size = rng.choice((0, 1, 2, 4, 8, 16, 33, 64, 200))
                thumb = is_arm and rng.random() < 0.5
                return lambda: Block(a, project=proj, size=size, thumb=thumb)
            if r < 0.6:
                size = rng.choice((1, 3, 16, 100))
                if rng.random() < 0.5:
                    data = bytes(rng.randrange(256) for _ in range(size))
                    return lambda: Unknown(a, size, bytes_=data, object_=main_obj)
                return lambda: Unknown(a, size, object_=main_obj, loader=proj.loader)
            if r < 0.8:
                size = rng.choice((None, 0, 1, 4, 24, 80))
                ref_size = rng.choice((None, 4))
                return lambda: MemoryData(a, size, MemoryDataSort.String, reference_size=ref_size)
            if r < 0.9:
                # no integer size: a zero-span entry
                tag = rng.randrange(10)
                return lambda: f"obj{tag}"
            size = rng.choice((0, 5, 40))
            return lambda: Block(a, project=proj, size=size)

        for i in range(n_ops):
            r = rng.random()
            if r < 0.12 and keys:
                a = rng.choice(keys)
                fill = rng.random() < 0.7
                assert _row(a, new.cfb.remove_obj(a, fill)) == _row(a, ref.cfb.remove_obj(a, fill))
            elif r < 0.25:
                pairs = [(addr(), None) for _ in range(rng.randrange(1, 12))]
                makers = [(a, make(a)) for a, _ in pairs]
                ref.cfb.add_objs([(a, m()) for a, m in makers])
                new.cfb.add_objs([(a, m()) for a, m in makers])
            else:
                a = addr()
                m = make(a)
                ref.cfb.add_obj(a, m())
                new.cfb.add_obj(a, m())
            keys = list(ref.cfb._blanket.keys())
            if i % 25 == 0 or i == n_ops - 1 or CHECK_ALL:
                assert _rows(new.cfb) == _rows(ref.cfb), (seed, i)
                q = qrng.randrange(lo, hi)
                for cfb_a, cfb_b in ((new.cfb, ref.cfb),):
                    for reverse in (False, True):
                        assert [_row(*x) for x in cfb_a.floor_items(q, reverse=reverse)][:40] == [
                            _row(*x) for x in cfb_b.floor_items(q, reverse=reverse)
                        ][:40]
                        assert [_row(*x) for x in cfb_a.ceiling_items(q, reverse=reverse)][-40:] == [
                            _row(*x) for x in cfb_b.ceiling_items(q, reverse=reverse)
                        ][-40:]
                    assert [_row(*x) for x in cfb_a.ceiling_items(q, include_first=False)][-5:] == [
                        _row(*x) for x in cfb_b.ceiling_items(q, include_first=False)
                    ][-5:]
                    for f in ("floor_addr", "ceiling_addr"):
                        try:
                            va = getattr(cfb_a, f)(q)
                        except KeyError:
                            va = None
                        try:
                            vb = getattr(cfb_b, f)(q)
                        except KeyError:
                            vb = None
                        assert va == vb
        assert new.removed == ref.removed
        assert [_row(a, o) for a, o in new.events] == [_row(a, o) for a, o in ref.events], seed
        # an event object is the stored object for as long as it is current
        ident_new = [new.cfb._blanket.get(a) is o for a, o in new.events]
        ident_ref = [ref.cfb._blanket.get(a) is o for a, o in ref.events]
        assert ident_new == ident_ref, seed
        return proj, new.cfb, ref.cfb

    def test_fuzz_fresh_kb(self):
        for seed in range(4):
            self._fuzz("x86_64/fauxware", seed, 300, batch=bool(seed & 1), with_cfg=False)

    def test_fuzz_with_memory_data(self):
        # MemoryData records of the CFG model, their trims and code-reference skipping
        for seed in range(4):
            self._fuzz("x86_64/fauxware", 100 + seed, 300, batch=bool(seed & 1), with_cfg=True)

    def test_fuzz_thumb(self):
        # seed 202 trims a Block trim at an odd key, which materializes as Thumb whatever its flag says
        for seed in (202, 203, 204):
            self._fuzz("armel/fauxware", seed, 300, batch=seed == 203, with_cfg=seed != 204)

    def test_pickle(self):
        _, new, ref = self._fuzz("x86_64/fauxware", 7, 120, batch=False, with_cfg=True)
        new._on_object_added_callback = None
        new._on_object_removed_callback = None
        loaded = pickle.loads(pickle.dumps(new))
        assert _rows(loaded) != [] and [r[:4] for r in _rows(loaded)] == [r[:4] for r in _rows(ref)]
        # a state pickled by the SortedDict implementation
        state = ref.__dict__.copy()
        state["_on_object_added_callback"] = state["_on_object_removed_callback"] = None
        old = CFBlanket.__new__(CFBlanket)
        old.__setstate__(state)
        assert _rows(old) == _rows(ref)
        old.add_obj(0x400600, Block(0x400600, project=old.project, size=4))
        ref.add_obj(0x400600, Block(0x400600, project=ref.project, size=4))
        assert [r[:4] for r in _rows(old)] == [r[:4] for r in _rows(ref)]

    def test_intervals_and_view(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = p.analyses.CFGFast(normalize=True)
        cfb = p.analyses.CFB(kb=cfg.kb)
        items = cfb._blanket.items()
        assert len(cfb._blanket) == len(items)
        classes = {Block: CFBlanket.CLASS_BLOCK, MemoryData: CFBlanket.CLASS_MD, Unknown: CFBlanket.CLASS_UNKNOWN}
        assert cfb.intervals() == [
            (a, o.size, classes[type(o)], o.sort if isinstance(o, MemoryData) else None) for a, o in items
        ]
        # MemoryData records are the model's views
        for a, o in items:
            if isinstance(o, MemoryData):
                assert o is cfg.model.memory_data[a]
        # objects of native records keep their identity while referenced
        a, u = next((a, o) for a, o in items if isinstance(o, Unknown))
        assert cfb[a] is u and cfb.floor_item(a)[1] is u
        assert next(iter(cfb._blanket.irange(maximum=a, reverse=True))) == a
        assert cfb._blanket.get(-1) is None and -1 not in cfb._blanket


if __name__ == "__main__":
    unittest.main()


def _brief(addr, obj) -> tuple:
    # comparable across projects
    return addr, type(obj).__name__, obj.size, getattr(obj, "thumb", None), obj.addr


class TestCfbScan(unittest.TestCase):
    """The CFG scan feeds the store directly; on_objects_added gets lazy batches."""

    def _run(self, binary: str, batch: bool, patch: bool = False):
        proj = angr.Project(os.path.join(test_location, binary), auto_load_libs=False)
        if patch:
            proj.kb.patches.add_patch(proj.entry & ~1, b"\x00")
        events: list = []
        if batch:
            cfb = proj.analyses[CFBlanket].prep(kb=KnowledgeBase(proj))(
                exclude_region_types={"kernel", "tls"}, on_objects_added=events.append
            )
        else:
            cfb = proj.analyses[CFBlanket].prep(kb=KnowledgeBase(proj))(
                exclude_region_types={"kernel", "tls"}, on_object_added=lambda a, o: events.append((a, o))
            )
        cfg = proj.analyses.CFGFast(normalize=True, cfb=cfb)
        return proj, cfg, cfb, events

    def test_scan_is_native(self):
        from angr.analyses.cfg.cfg_fast import CFGFast
        from angr.rustylib.cfb import KIND_BLOCK

        calls = []
        orig_rust, orig_block = CFGFast._cfb_add_rust_blocks, CFGFast._cfb_block
        CFGFast._cfb_add_rust_blocks = lambda self, blocks: calls.append("rust")
        CFGFast._cfb_block = lambda self, addr, size: calls.append("block")
        try:
            for binary in ("x86_64/fauxware", "armel/fauxware"):
                for batch in (False, True):
                    _, cfg, cfb, _ = self._run(binary, batch)
                    assert cfg._cfb_native_blocks
                    # scan blocks are records with a lift profile
                    assert any(kind == KIND_BLOCK and payload for _, kind, _, _, payload, _, _ in cfb._store.state()[0])
            assert not calls
        finally:
            CFGFast._cfb_add_rust_blocks, CFGFast._cfb_block = orig_rust, orig_block

    def test_scan_blocks_lift_like_cfb_block(self):
        for binary in ("x86_64/fauxware", "armel/fauxware"):
            _, cfg, cfb, _ = self._run(binary, True)
            for a, o in cfb._blanket.items():
                if isinstance(o, Block) and o._opt_level == 1:
                    ref = cfg._cfb_block(o.addr, o.size)
                    assert (a & ~1 if binary.startswith("armel") else a) == a
                    assert (o.addr, o.size, o.thumb, o._collect_data_refs, o._const_prop) == (
                        ref.addr,
                        ref.size,
                        ref.thumb,
                        ref._collect_data_refs,
                        ref._const_prop,
                    )
                    assert o._extra_stop_points is cfg._known_thunk_addrs

    def test_patches_keep_eager_scan_blocks(self):
        from angr.rustylib.cfb import KIND_BLOCK

        _, cfg, cfb, _ = self._run("x86_64/fauxware", True, patch=True)
        assert not cfg._cfb_native_blocks
        assert not any(kind == KIND_BLOCK and payload for _, kind, _, _, payload, _, _ in cfb._store.state()[0])

    def test_batches(self):
        for binary in ("x86_64/fauxware", "armel/fauxware"):
            _, _, _, single = self._run(binary, False)
            _, _, cfb_b, batches = self._run(binary, True)
            flat = [e for b in batches for e in b]
            assert [_brief(*e) for e in flat] == [_brief(*e) for e in single], binary
            assert [i for b in batches for i in b.intervals()] == [CFBlanket._interval(a, o) for a, o in flat]
            big = max(batches, key=len)
            assert big[-1] is big[len(big) - 1] and big[0] is next(iter(big))
            assert [_row(*e) for e in big[1:5]] == [_row(*e) for e in list(big)[1:5]]
            with self.assertRaises(IndexError):
                _ = big[len(big)]
            # a current event object is the blanket's object
            blanket = cfb_b._blanket
            assert any(blanket.get(a) is o for a, o in big)
