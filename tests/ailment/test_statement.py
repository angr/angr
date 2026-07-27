# pylint: disable=missing-class-docstring,no-self-use
"""Structural-comparison tests for ``angr.ailment.statement``.

These lock in that every field of a statement variant participates in
``likes`` / ``matches`` / ``__eq__`` / ``__hash__``. ``Store.guard`` used
to be silently elided, which let a rewriting pass land a real change and
then report "unchanged": ``replace`` does rewrite ``Store.guard``, so a
propagated guard compared ``likes``-equal to the statement it replaced.
"""

from __future__ import annotations

import unittest

from archinfo import Endness

from angr.ailment.expression import BinaryOp, Const, Register
from angr.ailment.manager import Manager
from angr.ailment.statement import Store


class TestStatementLikes(unittest.TestCase):
    """``Store.guard`` participates in structural comparison."""

    def setUp(self):
        self.m = Manager(arch=None)
        self.tags = {"ins_addr": 0x400000}

    def _guard(self, reg_offset: int):
        reg = Register(self.m.next_atom(), reg_offset, 32, **self.tags)
        return BinaryOp(
            self.m.next_atom(),
            "CmpEQ",
            [reg, Const(self.m.next_atom(), 0, 32, **self.tags)],
            False,
            bits=1,
            **self.tags,
        )

    def test_store_guard_is_compared(self):
        addr = Register(self.m.next_atom(), 16, 32, **self.tags)
        data = Register(self.m.next_atom(), 24, 32, **self.tags)
        guard_a = self._guard(32)
        guard_b = self._guard(40)
        assert not guard_a.likes(guard_b)

        # Same idx on every statement, so ``__eq__``'s idx-first
        # short-circuit cannot mask a difference in the guard.
        idx = self.m.next_atom()
        a = Store(idx, addr, data, 4, Endness.LE, guard=guard_a, **self.tags)
        b = Store(idx, addr, data, 4, Endness.LE, guard=guard_b, **self.tags)
        unguarded = Store(idx, addr, data, 4, Endness.LE, guard=None, **self.tags)

        # Differing guards.
        assert not a.likes(b)
        assert not a.matches(b)
        assert a != b

        # Guard present vs. absent.
        assert not a.likes(unguarded)
        assert not unguarded.likes(a)
        assert not a.matches(unguarded)
        assert a != unguarded

        # The guard is compared structurally, not by identity: a fresh but
        # structurally identical guard still compares ``likes``/``matches``.
        # ``__eq__`` is recursively idx-aware, so it legitimately separates
        # these two -- their guards carry different idx.
        same_shape = Store(idx, addr, data, 4, Endness.LE, guard=self._guard(32), **self.tags)
        assert a.likes(same_shape)
        assert a.matches(same_shape)

        # Sharing the guard object removes that idx difference, so here both
        # ``__eq__`` and the hash must agree.
        same_guard = Store(idx, addr, data, 4, Endness.LE, guard=guard_a, **self.tags)
        assert a == same_guard
        assert hash(a) == hash(same_guard)

        # ``__hash__`` stays as discriminating as ``__eq__``: three
        # mutually-unequal statements must not collapse in a set. Before the
        # fix the guard was hashed by neither, so this set collapsed to 1.
        assert len({a, b, unguarded}) == 3

    def test_store_guard_replace_reports_change(self):
        """``replace`` rewrites the guard, so the result must not ``likes`` the original."""
        addr = Register(self.m.next_atom(), 16, 32, **self.tags)
        data = Register(self.m.next_atom(), 24, 32, **self.tags)
        old = Register(self.m.next_atom(), 32, 32, **self.tags)
        new = Register(self.m.next_atom(), 40, 32, **self.tags)
        guard = BinaryOp(
            self.m.next_atom(),
            "CmpEQ",
            [old, Const(self.m.next_atom(), 0, 32, **self.tags)],
            False,
            bits=1,
            **self.tags,
        )
        stmt = Store(self.m.next_atom(), addr, data, 4, Endness.LE, guard=guard, **self.tags)

        replaced, rewritten = stmt.replace(old, new)
        assert replaced
        assert not rewritten.likes(stmt)


if __name__ == "__main__":
    unittest.main()
