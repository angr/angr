"""
Tests for angr.state_plugins.globals (SimStateGlobals).

Coverage gap: The SimStateGlobals plugin provides per-state global variable storage.
Despite being used extensively (e.g., by exploration techniques like Bucketizer),
it had NO direct test coverage. This file tests:
- Construction with default and custom backer
- Dictionary-like operations: get, set, delete, contains, iter, keys, values, items
- pop operation
- copy independence
- merge behavior
- Integration with SimState
"""

from __future__ import annotations

import unittest

from angr import SimState
from angr.state_plugins.globals import SimStateGlobals


class TestSimStateGlobalsBasic(unittest.TestCase):
    """Test basic construction and dict operations."""

    def test_default_construction(self):
        g = SimStateGlobals()
        assert len(list(g)) == 0

    def test_custom_backer(self):
        g = SimStateGlobals(backer={"a": 1, "b": 2})
        assert g["a"] == 1
        assert g["b"] == 2

    def test_setitem_getitem(self):
        g = SimStateGlobals()
        g["key"] = "value"
        assert g["key"] == "value"

    def test_delitem(self):
        g = SimStateGlobals(backer={"key": "value"})
        del g["key"]
        assert "key" not in g

    def test_contains(self):
        g = SimStateGlobals(backer={"x": 1})
        assert "x" in g
        assert "y" not in g

    def test_iter(self):
        g = SimStateGlobals(backer={"a": 1, "b": 2, "c": 3})
        keys = list(g)
        assert sorted(keys) == ["a", "b", "c"]

    def test_keys(self):
        g = SimStateGlobals(backer={"a": 1, "b": 2})
        assert set(g.keys()) == {"a", "b"}

    def test_values(self):
        g = SimStateGlobals(backer={"a": 1, "b": 2})
        assert sorted(g.values()) == [1, 2]

    def test_items(self):
        g = SimStateGlobals(backer={"a": 1, "b": 2})
        assert set(g.items()) == {("a", 1), ("b", 2)}

    def test_get_existing(self):
        g = SimStateGlobals(backer={"x": 42})
        assert g.get("x") == 42

    def test_get_missing_default(self):
        g = SimStateGlobals()
        assert g.get("missing") is None
        assert g.get("missing", "default") == "default"

    def test_pop_existing(self):
        g = SimStateGlobals(backer={"x": 42})
        val = g.pop("x")
        assert val == 42
        assert "x" not in g

    def test_pop_missing_default(self):
        g = SimStateGlobals()
        assert g.pop("missing") is None
        assert g.pop("missing", "fallback") == "fallback"

    def test_keyerror_on_missing(self):
        g = SimStateGlobals()
        with self.assertRaises(KeyError):
            _ = g["nonexistent"]


class TestSimStateGlobalsCopy(unittest.TestCase):
    """Test copy independence."""

    def test_copy_preserves_data(self):
        g = SimStateGlobals(backer={"a": 1, "b": 2})
        c = g.copy({})
        assert c["a"] == 1
        assert c["b"] == 2

    def test_copy_independence(self):
        g = SimStateGlobals(backer={"a": 1})
        c = g.copy({})
        c["a"] = 999
        assert g["a"] == 1

    def test_copy_new_keys_independent(self):
        g = SimStateGlobals(backer={"a": 1})
        c = g.copy({})
        c["new_key"] = "new_value"
        assert "new_key" not in g


class TestSimStateGlobalsMerge(unittest.TestCase):
    """Test merge behavior."""

    def test_merge_adds_missing_keys(self):
        g1 = SimStateGlobals(backer={"a": 1})
        g2 = SimStateGlobals(backer={"b": 2})
        g1.merge([g2], merge_conditions=None)
        assert g1["a"] == 1
        assert g1["b"] == 2

    def test_merge_does_not_overwrite(self):
        g1 = SimStateGlobals(backer={"a": 1})
        g2 = SimStateGlobals(backer={"a": 999})
        g1.merge([g2], merge_conditions=None)
        # Original value should be preserved
        assert g1["a"] == 1

    def test_merge_multiple_others(self):
        g1 = SimStateGlobals(backer={"a": 1})
        g2 = SimStateGlobals(backer={"b": 2})
        g3 = SimStateGlobals(backer={"c": 3})
        g1.merge([g2, g3], merge_conditions=None)
        assert g1["a"] == 1
        assert g1["b"] == 2
        assert g1["c"] == 3


class TestSimStateGlobalsIntegration(unittest.TestCase):
    """Test integration with SimState."""

    def test_state_globals_access(self):
        state = SimState(arch="AMD64")
        state.globals["my_key"] = "my_value"
        assert state.globals["my_key"] == "my_value"

    def test_state_copy_globals_independence(self):
        state = SimState(arch="AMD64")
        state.globals["counter"] = 0

        state2 = state.copy()
        state2.globals["counter"] = 42

        assert state.globals["counter"] == 0
        assert state2.globals["counter"] == 42

    def test_globals_iteration_via_state(self):
        state = SimState(arch="AMD64")
        state.globals["x"] = 1
        state.globals["y"] = 2
        keys = list(state.globals)
        assert "x" in keys
        assert "y" in keys


if __name__ == "__main__":
    unittest.main()
