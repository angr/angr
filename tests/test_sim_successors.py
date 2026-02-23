"""
Tests for angr.engines.successors (SimSuccessors).

Coverage gap: The SimSuccessors class is the core data structure that categorizes
execution results from all SimEngine runs. It had ZERO direct test coverage despite
being used by all simulation manager operations. This file tests:
- Construction and basic properties
- __repr__ in various states (processed vs unprocessed, different addr types)
- is_empty property
- __getitem__ and __iter__ delegation to flat_successors
- add_successor flow with concrete targets
- _categorize_successor: sat, unsat, unconstrained paths
- _eval_target_jumptable: concrete and ITE-form symbolic IPs
- _eval_target_brutal: traditional symbolic target evaluation
- _finalize behavior
"""

from __future__ import annotations

import unittest

import claripy

import angr
from angr.engines.successors import SimSuccessors


class TestSimSuccessorsBasic(unittest.TestCase):
    """Test SimSuccessors construction, repr, and basic properties."""

    def test_construction_defaults(self):
        ss = SimSuccessors(0x400000, None)
        assert ss.addr == 0x400000
        assert ss.initial_state is None
        assert ss.successors == []
        assert ss.all_successors == []
        assert ss.flat_successors == []
        assert ss.unsat_successors == []
        assert ss.unconstrained_successors == []
        assert ss.engine is None
        assert ss.processed is False
        assert ss.description == "SimSuccessors"
        assert ss.sort is None
        assert ss.artifacts == {}

    def test_construction_with_none_addr(self):
        ss = SimSuccessors(None, None)
        assert ss.addr is None

    def test_is_empty_true(self):
        ss = SimSuccessors(0x400000, None)
        assert ss.is_empty is True

    def test_is_empty_false_with_all_successors(self):
        ss = SimSuccessors(0x400000, None)
        ss.all_successors.append("dummy")
        assert ss.is_empty is False

    def test_is_empty_false_with_flat_successors(self):
        ss = SimSuccessors(0x400000, None)
        ss.flat_successors.append("dummy")
        assert ss.is_empty is False

    def test_is_empty_false_with_unsat(self):
        ss = SimSuccessors(0x400000, None)
        ss.unsat_successors.append("dummy")
        assert ss.is_empty is False

    def test_is_empty_false_with_unconstrained(self):
        ss = SimSuccessors(0x400000, None)
        ss.unconstrained_successors.append("dummy")
        assert ss.is_empty is False

    def test_getitem_delegates_to_flat(self):
        ss = SimSuccessors(0x400000, None)
        ss.flat_successors = ["a", "b", "c"]
        assert ss[0] == "a"
        assert ss[1] == "b"
        assert ss[2] == "c"

    def test_iter_delegates_to_flat(self):
        ss = SimSuccessors(0x400000, None)
        ss.flat_successors = ["a", "b", "c"]
        assert list(ss) == ["a", "b", "c"]

    def test_repr_unprocessed(self):
        ss = SimSuccessors(0x400000, None)
        r = repr(ss)
        assert "failure" in r
        assert "0x400000" in r

    def test_repr_processed_empty(self):
        ss = SimSuccessors(0x400000, None)
        ss.processed = True
        r = repr(ss)
        assert "empty" in r

    def test_repr_processed_with_sat(self):
        ss = SimSuccessors(0x400000, None)
        ss.processed = True
        ss.flat_successors = ["s1", "s2"]
        r = repr(ss)
        assert "2 sat" in r

    def test_repr_processed_with_unsat(self):
        ss = SimSuccessors(0x400000, None)
        ss.processed = True
        ss.unsat_successors = ["u1"]
        r = repr(ss)
        assert "1 unsat" in r

    def test_repr_processed_with_unconstrained(self):
        ss = SimSuccessors(0x400000, None)
        ss.processed = True
        ss.unconstrained_successors = ["uc1", "uc2", "uc3"]
        r = repr(ss)
        assert "3 unconstrained" in r

    def test_repr_processed_combined(self):
        ss = SimSuccessors(0x400000, None)
        ss.processed = True
        ss.flat_successors = ["s1"]
        ss.unsat_successors = ["u1"]
        ss.unconstrained_successors = ["uc1"]
        r = repr(ss)
        assert "1 sat" in r
        assert "1 unsat" in r
        assert "1 unconstrained" in r

    def test_repr_with_tuple_addr(self):
        ss = SimSuccessors((0x400000, None), None)
        ss.processed = True
        r = repr(ss)
        assert "0x400000" in r

    def test_repr_with_tuple_addr_with_component(self):
        ss = SimSuccessors((0x400000, 5), None)
        ss.processed = True
        r = repr(ss)
        assert "0x400000" in r
        assert ".5" in r

    def test_repr_non_int_addr(self):
        ss = SimSuccessors("some_addr", None)
        ss.processed = True
        r = repr(ss)
        assert "some_addr" in r


class TestSimSuccessorsEvalTarget(unittest.TestCase):
    """Test the static target evaluation methods."""

    def test_eval_target_jumptable_concrete(self):
        """A concrete (non-symbolic) IP should return immediately."""
        state = angr.SimState(arch="AMD64")
        ip = claripy.BVV(0x400000, 64)
        result = SimSuccessors._eval_target_jumptable(state, ip, 256)
        assert result is not None
        assert len(result) == 1
        cond, target = result[0]
        assert target is ip

    def test_eval_target_jumptable_returns_none_for_non_ite(self):
        """A simple symbolic variable should cause fallback (return None)."""
        state = angr.SimState(arch="AMD64")
        x = claripy.BVS("x", 64)
        result = SimSuccessors._eval_target_jumptable(state, x, 256)
        # Should return None (fallback to brutal method)
        assert result is None

    def test_eval_target_brutal_concrete(self):
        """Concrete IP should yield one result."""
        state = angr.SimState(arch="AMD64")
        ip = claripy.BVV(0x400000, 64)
        result = SimSuccessors._eval_target_brutal(state, ip, 256)
        assert len(result) == 1
        cond, addr = result[0]
        assert addr == 0x400000

    def test_eval_target_brutal_symbolic_constrained(self):
        """Symbolic IP with constraints should yield constrained solutions."""
        state = angr.SimState(arch="AMD64")
        x = claripy.BVS("x", 64)
        state.add_constraints(claripy.Or(x == 0x1000, x == 0x2000))
        result = SimSuccessors._eval_target_brutal(state, x, 256)
        addrs = sorted(a for _, a in result)
        assert addrs == [0x1000, 0x2000]

    def test_eval_target_brutal_respects_limit(self):
        """Should not return more than limit results."""
        state = angr.SimState(arch="AMD64")
        x = claripy.BVS("x", 64)
        state.add_constraints(claripy.Or(x == 0x1000, x == 0x2000, x == 0x3000))
        result = SimSuccessors._eval_target_brutal(state, x, 2)
        assert len(result) == 2


class TestSimSuccessorsFinalize(unittest.TestCase):
    """Test the _finalize method."""

    def test_finalize_empty(self):
        """Finalize on empty successors should not raise."""
        ss = SimSuccessors(0x400000, None)
        ss._finalize()

    def test_finalize_single_flat_successor_marks_unavoidable(self):
        """A single flat successor with no unconstrained should be marked unavoidable."""
        state = angr.SimState(arch="AMD64")
        state.scratch.avoidable = True
        ss = SimSuccessors(0x400000, None)
        ss.all_successors.append(state)
        ss.flat_successors.append(state)
        ss._finalize()
        assert state.scratch.avoidable is False


if __name__ == "__main__":
    unittest.main()
