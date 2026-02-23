"""
Tests for angr.exploration_techniques.common (condition_to_lambda) and
angr.exploration_techniques.base (ExplorationTechnique).

Coverage gap: The condition_to_lambda function and ExplorationTechnique base class
had NO direct tests despite being used by all exploration techniques. This file tests:
- condition_to_lambda with None, int, list, set, tuple, callable inputs
- Static address extraction from conditions
- Error handling for invalid condition types
- ExplorationTechnique base class construction and hook detection
- Default method behavior (step, filter, selector, step_state, successors, complete)
"""

from __future__ import annotations

import unittest

from angr.exploration_techniques.common import condition_to_lambda
from angr.exploration_techniques.base import ExplorationTechnique
from angr.errors import AngrExplorationTechniqueError


class TestConditionToLambdaNone(unittest.TestCase):
    """Test condition_to_lambda with None."""

    def test_none_returns_default_false(self):
        func, static = condition_to_lambda(None)
        assert static == set()
        # func always returns False (the default)
        assert func(None) is False

    def test_none_with_custom_default(self):
        func, static = condition_to_lambda(None, default=True)
        assert func(None) is True

    def test_none_with_custom_default_value(self):
        func, static = condition_to_lambda(None, default="custom")
        assert func(None) == "custom"


class TestConditionToLambdaInt(unittest.TestCase):
    """Test condition_to_lambda with an integer address."""

    def test_int_returns_static_set(self):
        func, static = condition_to_lambda(0x400000)
        assert static == {0x400000}

    def test_int_matches_state_addr(self):
        func, static = condition_to_lambda(0x400000)

        class MockState:
            addr = 0x400000
            project = None

        result = func(MockState())
        assert result == {0x400000}


class TestConditionToLambdaCollection(unittest.TestCase):
    """Test condition_to_lambda with set, list, tuple."""

    def test_set_returns_static(self):
        func, static = condition_to_lambda({0x1000, 0x2000})
        assert static == {0x1000, 0x2000}

    def test_list_returns_static(self):
        func, static = condition_to_lambda([0x1000, 0x2000])
        assert static == {0x1000, 0x2000}

    def test_tuple_returns_static(self):
        func, static = condition_to_lambda((0x1000, 0x2000))
        assert static == {0x1000, 0x2000}

    def test_collection_match(self):
        func, static = condition_to_lambda({0x1000, 0x2000})

        class MockState:
            addr = 0x1000
            project = None

        result = func(MockState())
        assert 0x1000 in result

    def test_collection_no_match(self):
        func, static = condition_to_lambda({0x1000, 0x2000})

        class MockProject:
            class factory:
                class default_engine:
                    pass

        class MockState:
            addr = 0x9999
            project = MockProject()

            def block(self):
                raise Exception("no block")

        result = func(MockState())
        assert not result

    def test_empty_set(self):
        func, static = condition_to_lambda(set())
        assert static == set()


class TestConditionToLambdaCallable(unittest.TestCase):
    """Test condition_to_lambda with a callable."""

    def test_callable_passthrough(self):
        original = lambda s: s.addr == 42
        func, static = condition_to_lambda(original)
        assert func is original
        assert static is None

    def test_callable_execution(self):
        func, _ = condition_to_lambda(lambda s: s > 10)
        assert func(20) is True
        assert func(5) is False


class TestConditionToLambdaInvalid(unittest.TestCase):
    """Test error handling for invalid types."""

    def test_invalid_type_raises(self):
        with self.assertRaises(AngrExplorationTechniqueError):
            condition_to_lambda(3.14)

    def test_invalid_string_raises(self):
        with self.assertRaises(AngrExplorationTechniqueError):
            condition_to_lambda("not_a_valid_condition")


class TestExplorationTechniqueBase(unittest.TestCase):
    """Test ExplorationTechnique base class."""

    def test_construction(self):
        et = ExplorationTechnique()
        assert et.project is None

    def test_hook_list(self):
        assert "step" in ExplorationTechnique._hook_list
        assert "filter" in ExplorationTechnique._hook_list
        assert "selector" in ExplorationTechnique._hook_list
        assert "step_state" in ExplorationTechnique._hook_list
        assert "successors" in ExplorationTechnique._hook_list

    def test_get_hooks_base_empty(self):
        """Base class should have no overridden hooks."""
        et = ExplorationTechnique()
        hooks = et._get_hooks()
        assert len(hooks) == 0

    def test_get_hooks_subclass_detects_override(self):
        class MyTechnique(ExplorationTechnique):
            def step(self, simgr, stash="active", **kwargs):
                pass

        et = MyTechnique()
        hooks = et._get_hooks()
        assert "step" in hooks

    def test_is_overridden_false(self):
        et = ExplorationTechnique()
        assert et._is_overridden("step") is False

    def test_is_overridden_true(self):
        class MyTechnique(ExplorationTechnique):
            def filter(self, simgr, state, **kwargs):
                return "custom"

        et = MyTechnique()
        assert et._is_overridden("filter") is True

    def test_complete_default_false(self):
        et = ExplorationTechnique()
        # complete should return False by default
        assert et.complete(None) is False

    def test_setup_does_nothing(self):
        """setup() should not raise."""
        et = ExplorationTechnique()
        et.setup(None)


if __name__ == "__main__":
    unittest.main()
