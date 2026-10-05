# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import random
import unittest

import archinfo

from angr.analyses.decompiler.ssailification.traversal_state import TraversalState
from angr.utils.cow_interval_map import IntervalMapCOW


def _as_dict(m: IntervalMapCOW, lo: int = -100, hi: int = 100) -> dict:
    return {k: m.get(k) for k in range(lo, hi) if k in m}


class TestIntervalMapCOW(unittest.TestCase):
    def test_assign_overlap_and_nesting(self):
        m = IntervalMapCOW()
        a, b, c = {"a"}, {"b"}, {"c"}
        m.assign(0, 10, a)
        m.assign(5, 15, b)  # overlaps the tail of a
        m.assign(2, 4, c)  # nested inside a
        assert list(m.segments()) == [(0, 2, a), (2, 4, c), (4, 5, a), (5, 15, b)]
        assert m.get(3) is c and m.get(4) is a and m.get(14) is b
        assert m.get(15) is None and -1 not in m and 0 in m
        assert len(m) == 15

    def test_adjacency_coalescing(self):
        a = {"a"}
        m = IntervalMapCOW()
        m.assign(0, 4, a)
        m.assign(4, 8, a)
        m.assign(8, 12, {"a"})  # equal but not identical: kept separate
        assert list(m.segments()) == [(0, 8, a), (8, 12, {"a"})]

        t = IntervalMapCOW(coalesce_equal=True)
        t.assign(0, 4, (0, 8))
        t.assign(4, 8, (0, 8))
        t.assign(8, 9, (8, 1))
        assert list(t.segments()) == [(0, 8, (0, 8)), (8, 9, (8, 1))]
        t.assign(8, 9, (0, 8))
        assert list(t.segments()) == [(0, 9, (0, 8))]

    def test_pop_and_pop_range(self):
        a, b = {"a"}, {"b"}
        m = IntervalMapCOW()
        m.assign(0, 8, a)
        m.assign(8, 12, b)
        assert m.pop(3) is a
        assert m.pop(3, None) is None
        with self.assertRaises(KeyError):
            m.pop(3)
        # the byte is split out; the rest of the segment keeps the same object
        assert list(m.segments()) == [(0, 3, a), (4, 8, a), (8, 12, b)]
        assert m.pop_range(6, 10) == [(6, 8, a), (8, 10, b)]
        assert list(m.segments()) == [(0, 3, a), (4, 6, a), (10, 12, b)]
        assert not m.pop_range(20, 30)
        del m[0]
        with self.assertRaises(KeyError):
            del m[0]
        assert _as_dict(m) == {1: a, 2: a, 4: a, 5: a, 10: b, 11: b}

    def test_overlapping(self):
        m = IntervalMapCOW()
        m.assign(0, 4, 1)
        m.assign(6, 8, 2)
        m.assign(10, 20, 3)
        assert list(m.overlapping(3, 11)) == [(0, 4, 1), (6, 8, 2), (10, 20, 3)]
        assert not list(m.overlapping(4, 6))
        assert not list(m.overlapping(5, 5))
        assert list(m.overlapping(-5, 1)) == [(0, 4, 1)]

    def test_next_key(self):
        m = IntervalMapCOW()
        assert m.next_key(0) is None
        m.assign(0, 4, 1)
        m.assign(10, 12, 2)
        assert m.next_key(-3) == 0
        assert m.next_key(2) == 2
        assert m.next_key(4) == 10
        assert m.next_key(12) is None

    def test_copy_on_write(self):
        parent = IntervalMapCOW()
        parent.assign(0, 16, "p")
        child = parent.copy()
        child.pop_range(4, 8)  # deletion in the child must not show through to the parent
        child.assign(12, 20, "c")
        assert _as_dict(parent) == dict.fromkeys(range(16), "p")
        assert 5 not in child and child.get(13) == "c" and child.get(3) == "p"
        # writes to the parent do not leak into the child either
        parent.assign(4, 8, "q")
        assert 5 not in child and parent.get(5) == "q"
        grandchild = child.copy()
        grandchild[5] = "g"
        assert 5 not in child and grandchild.get(5) == "g"

    def test_unshared_segments(self):
        IntervalMapCOW.CHUNK_SIZE, old = 4, IntervalMapCOW.CHUNK_SIZE
        try:
            base = IntervalMapCOW()
            for i in range(40):
                base.assign(i * 2, i * 2 + 1, i)
            a = base.copy()
            b = base.copy()
            assert not list(a.unshared_segments(b))
            b.assign(70, 71, "x")
            b.pop_range(10, 11)
            uns = list(a.unshared_segments(b))
            assert (70, 71, "x") in uns
            assert len(uns) < 40
            # every binding of b outside the unshared segments is identical in a
            covered = {k for s, e, _ in uns for k in range(s, e)}
            for s, e, v in b.segments():
                for k in range(s, e):
                    if k not in covered:
                        assert a.get(k) == v
        finally:
            IntervalMapCOW.CHUNK_SIZE = old

    def test_random_against_dict(self):
        IntervalMapCOW.CHUNK_SIZE, old = 8, IntervalMapCOW.CHUNK_SIZE
        try:
            rnd = random.Random(0)
            vals = [object() for _ in range(3)]
            maps = [(IntervalMapCOW(), {})]
            for _ in range(2000):
                m, d = rnd.choice(maps)
                lo = rnd.randrange(-50, 50)
                hi = lo + rnd.randrange(1, 12)
                op = rnd.random()
                if op < 0.05 and len(maps) < 5:
                    maps.append((m.copy(), dict(d)))
                elif op < 0.6:
                    v = rnd.choice(vals)
                    m.assign(lo, hi, v)
                    d.update(dict.fromkeys(range(lo, hi), v))
                elif op < 0.65:
                    assert m.next_key(lo) == min((k for k in d if k >= lo), default=None)
                else:
                    got = {k: v for s, e, v in m.pop_range(lo, hi) for k in range(s, e)}
                    assert got == {k: d.pop(k) for k in range(lo, hi) if k in d}
            for m, d in maps:
                assert _as_dict(m, -60, 70) == d
                segs = list(m.segments())
                assert all(s < e for s, e, _ in segs)
                assert all(e0 <= s1 for (_, e0, _), (s1, _, _) in zip(segs, segs[1:]))
        finally:
            IntervalMapCOW.CHUNK_SIZE = old


class TestTraversalStateStackMerge(unittest.TestCase):
    def _state(self):
        return TraversalState(archinfo.ArchAMD64(), None)

    def test_stackvar_unify(self):
        st = self._state()
        assert st.stackvar_unify(-16, 4) == (-16, 4, set())
        assert st.stackvar_unify(-14, 4) == (-16, 6, {-16})
        assert st.stackvar_unify(-20, 2) == (-20, 2, set())
        # bridging two variables pulls in both
        assert st.stackvar_unify(-19, 4) == (-20, 10, {-20, -16})
        assert list(st.stackvar_bases.segments()) == [(-20, -10, (-20, 10))]

    def test_merge_bases(self):
        a = self._state()
        a.stackvar_unify(0, 4)
        b = a.copy()
        assert not a.merge(b)
        b.stackvar_unify(2, 4)  # b: [0, 6) -> (0, 6)
        b.stackvar_unify(10, 2)
        assert a.merge(b)
        assert _as_dict(a.stackvar_bases) == {
            **dict.fromkeys(range(6), (0, 6)),
            10: (10, 2),
            11: (10, 2),
        }
        assert not a.merge(b)

    def test_merge_bases_partial_overlap(self):
        # per byte: bytes covered by both get the hull, bytes covered by one keep their own value
        a = self._state()
        a.stackvar_unify(0, 4)
        b = self._state()
        b.stackvar_unify(2, 4)
        assert a.merge(b)
        assert _as_dict(a.stackvar_bases) == {0: (0, 4), 1: (0, 4), 2: (0, 6), 3: (0, 6), 4: (2, 4), 5: (2, 4)}

    def test_merge_defs_updates_shared_sets_in_place(self):
        d1, d2 = {"d1"}, {"d2"}
        a = self._state()
        a.stackvar_defs.assign(0, 8, d1)  # type: ignore
        b = a.copy()
        b.stackvar_defs.assign(4, 12, d2)  # type: ignore
        merged = a.copy()
        assert merged.merge(b)
        # [0, 8) shares d1, so it is updated in place for every byte (and every state) holding it
        assert d1 == {"d1", "d2"}
        assert a.stackvar_defs.get(0) is d1
        # [8, 12) was unbound and gets a fresh set
        gap = merged.stackvar_defs.get(9)
        assert gap == {"d2"} and gap is not d2
        assert 9 not in a.stackvar_defs
        assert not merged.merge(b)


if __name__ == "__main__":
    unittest.main()
