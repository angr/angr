# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

import random
from unittest import TestCase, main

from angr.utils.vvar_set import VVarSet


class TestVVarSet(TestCase):
    def test_matches_builtin_set(self):
        rng = random.Random(0)
        for _ in range(300):
            a = {rng.randrange(0, 5000) for _ in range(rng.randrange(0, 60))}
            b = {rng.randrange(0, 5000) for _ in range(rng.randrange(0, 60))}
            va, vb = VVarSet(a), VVarSet(b)
            assert va == a and set(va) == a and len(va) == len(a) and bool(va) == bool(a)
            assert (va | vb) == (a | b) and (va & vb) == (a & b) and (va - vb) == (a - b) and (va ^ vb) == (a ^ b)
            assert (va | b) == (a | b) and (va & b) == (a & b) and (va - b) == (a - b)
            # a plain set on the left stays a plain set
            assert (a - vb) == (a - b) and isinstance(a - vb, set)
            assert (a | vb) == (a | b) and (a & vb) == (a & b)
            assert (va <= vb) == (a <= b) and (va < vb) == (a < b) and (va >= vb) == (a >= b) and (va > vb) == (a > b)
            assert va.isdisjoint(vb) == a.isdisjoint(b) and va.isdisjoint(b) == a.isdisjoint(b)
            assert (va != vb) == (a != b)
            for v in list(a)[:5]:
                assert v in va
            assert -1 not in va and 100000 not in va

    def test_mutation(self):
        s, v = set(), VVarSet()
        for x in [3, 70, 3, 1000]:
            s.add(x)
            v.add(x)
        assert v == s
        v.discard(70)
        s.discard(70)
        v.discard(999)
        assert v == s
        v.update({5, 6})
        s.update({5, 6})
        v.difference_update([3, 5])
        s.difference_update([3, 5])
        assert v == s
        c = v.copy()
        c.add(42)
        assert 42 in c and 42 not in v
        v |= {8}
        s |= {8}
        v -= {6}
        s -= {6}
        v &= {8, 1000, 77}
        s &= {8, 1000, 77}
        assert v == s and sorted(v) == sorted(s)
        with self.assertRaises(KeyError):
            v.remove(12345)


if __name__ == "__main__":
    main()
