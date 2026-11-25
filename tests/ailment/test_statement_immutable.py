# pylint:disable=missing-class-docstring,no-self-use
"""AIL statements are immutable from Python: a changed statement is a copy made by copy_with()."""

from __future__ import annotations

import unittest

import pytest

from angr.ailment.expression import Const, Tmp
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Label, Store


class TestStatementImmutable(unittest.TestCase):
    def test_fields_and_tags_are_read_only(self):
        stmt = Assignment(1, Tmp(2, 0, 64), Const(3, 1, 64), ins_addr=0x1000)
        with pytest.raises(AttributeError):
            stmt.src = Const(4, 2, 64)
        with pytest.raises(AttributeError):
            stmt.tags = {}
        for mutate in (
            lambda tags: tags.__setitem__("ins_addr", 0x2000),
            lambda tags: tags.__delitem__("ins_addr"),
            lambda tags: tags.update({"ins_addr": 0x2000}),
            lambda tags: tags.pop("ins_addr"),
            lambda tags: tags.setdefault("x", 1),
        ):
            with pytest.raises(TypeError):
                mutate(stmt.tags)
        assert stmt.tags == {"ins_addr": 0x1000}
        # a copy of the tags is an ordinary writable mapping
        tags = stmt.tags.copy()
        tags["x"] = 1
        assert stmt.tags == {"ins_addr": 0x1000}

    def test_copy_with(self):
        stmt = Assignment(1, Tmp(2, 0, 64), Const(3, 1, 64), ins_addr=0x1000)
        new_stmt = stmt.copy_with(src=Const(4, 2, 64), tags={**stmt.tags, "ins_addr": 0x2000})
        assert new_stmt is not stmt
        assert new_stmt.idx == stmt.idx
        assert new_stmt.src.value == 2
        assert new_stmt.tags == {"ins_addr": 0x2000}
        assert stmt.src.value == 1
        assert stmt.tags == {"ins_addr": 0x1000}
        assert stmt.copy_with() == stmt

        jump = Jump(5, Const(6, 0x1000, 64), ins_addr=0x1000)
        assert jump.copy_with(target=Const(7, 0x2000, 64), target_idx=3).target_idx == 3
        cjump = ConditionalJump(8, Const(9, 1, 1), Const(10, 0x1000, 64), Const(11, 0x2000, 64))
        assert cjump.copy_with(false_target=Const(12, 0x3000, 64)).false_target.value == 0x3000

    def test_copy_with_takes_every_constructor_field(self):
        store = Store(1, Const(2, 0x1000, 64), Const(3, 1, 32), 4, "Iend_LE")
        new_store = store.copy_with(idx=9, addr=Const(4, 0x2000, 64), size=8, endness="Iend_BE", guard=Const(5, 1, 1))
        assert (new_store.idx, new_store.addr.value, new_store.size, new_store.endness) == (9, 0x2000, 8, "Iend_BE")
        assert new_store.guard.value == 1
        assert new_store.copy_with(guard=None).guard is None
        assert (store.idx, store.addr.value, store.size, store.guard) == (1, 0x1000, 4, None)
        assert Label(1, "a").copy_with(name="b").name == "b"

    def test_copy_with_rejects_unknown_and_foreign_fields(self):
        stmt = Assignment(1, Tmp(2, 0, 64), Const(3, 1, 64))
        with pytest.raises(TypeError):
            stmt.copy_with(bogus=1)
        with pytest.raises(AttributeError):
            stmt.copy_with(condition=Const(4, 1, 1))


if __name__ == "__main__":
    unittest.main()
