"""
Tests for angr.state_plugins.inspect (SimInspector, BP).

Coverage gap: The inspect plugin (375 lines) provides the breakpoint interface used
to instrument execution. It had NO direct test coverage. This file tests:
- BP construction and validation
- BP.check() with various conditions
- BP.fire() with action callbacks
- SimInspector construction and event type coverage
- add_breakpoint / remove_breakpoint
- make_breakpoint convenience method
- copy preserves breakpoints
- downsize clears attributes
- merge / widen combine breakpoints
- _set_inspect_attrs validation
"""

from __future__ import annotations

import unittest

import claripy

from angr import SimState
from angr.state_plugins.inspect import (
    BP,
    BP_BEFORE,
    BP_AFTER,
    BP_BOTH,
    SimInspector,
    event_types,
    inspect_attributes,
)


class TestBPConstruction(unittest.TestCase):
    """Test BP (breakpoint) construction."""

    def test_default_construction(self):
        bp = BP()
        assert bp.enabled is True
        assert bp.condition is None
        assert bp.action is None
        assert bp.when == BP_BEFORE

    def test_custom_when(self):
        bp = BP(when=BP_AFTER)
        assert bp.when == BP_AFTER

    def test_when_both(self):
        bp = BP(when=BP_BOTH)
        assert bp.when == BP_BOTH

    def test_disabled(self):
        bp = BP(enabled=False)
        assert bp.enabled is False

    def test_with_action_callback(self):
        called = []
        bp = BP(action=lambda s: called.append(True))
        assert bp.action is not None

    def test_invalid_kwargs_raises(self):
        with self.assertRaises(ValueError):
            BP(invalid_attribute=42)

    def test_valid_kwargs(self):
        bp = BP(mem_read_address=0x1000)
        assert bp.kwargs["mem_read_address"] == 0x1000

    def test_repr(self):
        bp = BP(when=BP_BEFORE, mem_read_address=0x1000)
        r = repr(bp)
        assert "BP" in r
        assert "before" in r


class TestBPCheck(unittest.TestCase):
    """Test BP.check() logic."""

    def test_check_disabled_returns_false(self):
        bp = BP(enabled=False)
        state = SimState(arch="AMD64")
        assert bp.check(state, BP_BEFORE) is False

    def test_check_wrong_when_returns_false(self):
        bp = BP(when=BP_BEFORE)
        state = SimState(arch="AMD64")
        assert bp.check(state, BP_AFTER) is False

    def test_check_matching_when(self):
        bp = BP(when=BP_BEFORE)
        state = SimState(arch="AMD64")
        assert bp.check(state, BP_BEFORE) is True

    def test_check_both_matches_before(self):
        bp = BP(when=BP_BOTH)
        state = SimState(arch="AMD64")
        assert bp.check(state, BP_BEFORE) is True

    def test_check_both_matches_after(self):
        bp = BP(when=BP_BOTH)
        state = SimState(arch="AMD64")
        assert bp.check(state, BP_AFTER) is True

    def test_check_with_condition_true(self):
        bp = BP(when=BP_BEFORE, condition=lambda s: True)
        state = SimState(arch="AMD64")
        assert bp.check(state, BP_BEFORE) is True

    def test_check_with_condition_false(self):
        bp = BP(when=BP_BEFORE, condition=lambda s: False)
        state = SimState(arch="AMD64")
        assert bp.check(state, BP_BEFORE) is False


class TestBPFire(unittest.TestCase):
    """Test BP.fire() with action callbacks."""

    def test_fire_with_callback(self):
        fired = []
        bp = BP(action=lambda s: fired.append(s))
        state = SimState(arch="AMD64")
        bp.fire(state)
        assert len(fired) == 1
        assert fired[0] is state


class TestSimInspectorConstruction(unittest.TestCase):
    """Test SimInspector construction."""

    def test_default_construction(self):
        inspector = SimInspector()
        # Should have breakpoint lists for all event types
        for et in event_types:
            assert et in inspector._breakpoints
            assert inspector._breakpoints[et] == []

    def test_attributes_initialized_to_none(self):
        inspector = SimInspector()
        for attr in inspect_attributes:
            assert getattr(inspector, attr) is None


class TestSimInspectorBreakpoints(unittest.TestCase):
    """Test adding and removing breakpoints."""

    def test_add_breakpoint(self):
        inspector = SimInspector()
        bp = BP(when=BP_BEFORE)
        inspector.add_breakpoint("mem_read", bp)
        assert bp in inspector._breakpoints["mem_read"]

    def test_add_breakpoint_invalid_event_raises(self):
        inspector = SimInspector()
        bp = BP()
        with self.assertRaises(ValueError):
            inspector.add_breakpoint("invalid_event", bp)

    def test_remove_breakpoint(self):
        inspector = SimInspector()
        bp = BP()
        inspector.add_breakpoint("mem_write", bp)
        inspector.remove_breakpoint("mem_write", bp=bp)
        assert bp not in inspector._breakpoints["mem_write"]

    def test_remove_breakpoint_not_found(self):
        """Removing a non-existent breakpoint should log error but not raise."""
        inspector = SimInspector()
        bp = BP()
        # Should not raise
        inspector.remove_breakpoint("mem_write", bp=bp)

    def test_remove_with_filter_func(self):
        inspector = SimInspector()
        bp1 = BP(when=BP_BEFORE)
        bp2 = BP(when=BP_AFTER)
        inspector.add_breakpoint("mem_read", bp1)
        inspector.add_breakpoint("mem_read", bp2)

        inspector.remove_breakpoint("mem_read", filter_func=lambda b: b.when == BP_BEFORE)
        assert bp1 not in inspector._breakpoints["mem_read"]
        assert bp2 in inspector._breakpoints["mem_read"]

    def test_remove_requires_bp_or_filter(self):
        inspector = SimInspector()
        with self.assertRaises(ValueError):
            inspector.remove_breakpoint("mem_read")

    def test_make_breakpoint(self):
        inspector = SimInspector()
        bp = inspector.make_breakpoint("mem_read", when=BP_AFTER)
        assert bp in inspector._breakpoints["mem_read"]
        assert bp.when == BP_AFTER

    def test_shortcut_b(self):
        """Test the 'b' alias for make_breakpoint."""
        inspector = SimInspector()
        bp = inspector.b("mem_write", when=BP_BEFORE)
        assert bp in inspector._breakpoints["mem_write"]


class TestSimInspectorAction(unittest.TestCase):
    """Test the action method that fires breakpoints."""

    def test_action_fires_matching_bp(self):
        state = SimState(arch="AMD64")
        fired = []
        bp = BP(when=BP_BEFORE, action=lambda s: fired.append(True))
        state.inspect.add_breakpoint("mem_read", bp)

        state.inspect.action("mem_read", BP_BEFORE, mem_read_address=0x1000)
        assert len(fired) == 1

    def test_action_does_not_fire_non_matching(self):
        state = SimState(arch="AMD64")
        fired = []
        bp = BP(when=BP_AFTER, action=lambda s: fired.append(True))
        state.inspect.add_breakpoint("mem_read", bp)

        state.inspect.action("mem_read", BP_BEFORE, mem_read_address=0x1000)
        assert len(fired) == 0

    def test_action_sets_attributes(self):
        state = SimState(arch="AMD64")

        def check_attr(s):
            assert s.inspect.mem_read_address == 0x1000

        bp = BP(when=BP_BEFORE, action=check_attr)
        state.inspect.add_breakpoint("mem_read", bp)
        state.inspect.action("mem_read", BP_BEFORE, mem_read_address=0x1000)


class TestSimInspectorCopy(unittest.TestCase):
    """Test copy preserves breakpoints."""

    def test_copy_preserves_breakpoints(self):
        inspector = SimInspector()
        bp = BP(when=BP_BEFORE)
        inspector.add_breakpoint("mem_read", bp)

        copied = inspector.copy({})
        assert bp in copied._breakpoints["mem_read"]


class TestSimInspectorDownsize(unittest.TestCase):
    """Test downsize clears attributes."""

    def test_downsize_clears_all_attrs(self):
        inspector = SimInspector()
        inspector.mem_read_address = 0x1000
        inspector.mem_write_expr = claripy.BVV(42, 64)

        inspector.downsize()
        assert inspector.mem_read_address is None
        assert inspector.mem_write_expr is None


class TestSimInspectorMerge(unittest.TestCase):
    """Test merge and widen combine breakpoints."""

    def test_merge_combines_unique_bps(self):
        i1 = SimInspector()
        i2 = SimInspector()

        bp1 = BP(when=BP_BEFORE)
        bp2 = BP(when=BP_AFTER)

        i1.add_breakpoint("mem_read", bp1)
        i2.add_breakpoint("mem_read", bp2)

        state = SimState(arch="AMD64")
        i1.set_state(state)
        i1.merge([i2], merge_conditions=None)

        assert bp1 in i1._breakpoints["mem_read"]
        assert bp2 in i1._breakpoints["mem_read"]

    def test_merge_no_duplicates(self):
        i1 = SimInspector()
        i2 = SimInspector()

        bp = BP(when=BP_BEFORE)
        i1.add_breakpoint("mem_read", bp)
        i2.add_breakpoint("mem_read", bp)

        state = SimState(arch="AMD64")
        i1.set_state(state)
        i1.merge([i2], merge_conditions=None)

        # Should not duplicate the same breakpoint
        assert i1._breakpoints["mem_read"].count(bp) == 1

    def test_widen_combines_bps(self):
        i1 = SimInspector()
        i2 = SimInspector()

        bp = BP(when=BP_AFTER)
        i2.add_breakpoint("mem_write", bp)

        state = SimState(arch="AMD64")
        i1.set_state(state)
        i1.widen([i2])

        assert bp in i1._breakpoints["mem_write"]


class TestSimInspectorSetState(unittest.TestCase):
    """Test set_state enables supports_inspect."""

    def test_set_state_enables_inspect(self):
        state = SimState(arch="AMD64")
        # Access the inspect plugin to trigger registration and set_state
        _ = state.inspect
        assert state.supports_inspect is True


class TestSetInspectAttrs(unittest.TestCase):
    """Test _set_inspect_attrs validation."""

    def test_valid_attrs(self):
        inspector = SimInspector()
        inspector._set_inspect_attrs(mem_read_address=0x1000)
        assert inspector.mem_read_address == 0x1000

    def test_invalid_attrs_raises(self):
        inspector = SimInspector()
        with self.assertRaises(ValueError):
            inspector._set_inspect_attrs(completely_invalid=42)


if __name__ == "__main__":
    unittest.main()
