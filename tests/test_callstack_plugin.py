"""
Tests for angr.state_plugins.callstack (CallStack, CallStackAction).

Coverage gap: The CallStack plugin (479 lines) is used by all symbolic execution
for tracking function call frames, but had only minimal incidental test coverage.
This file tests:
- Construction and defaults
- Iteration (__iter__, __len__, __getitem__)
- Equality and hashing
- __repr__ and __str__
- Push and pop operations
- call() and ret() high-level methods
- stack_suffix generation
- _find_return_target
- copy and copy_without_tail
- CallStackAction validation
- stack_suffix_to_string
"""

from __future__ import annotations

import unittest

from angr import SimState
from angr.errors import SimEmptyCallStackError, AngrError
from angr.state_plugins.callstack import CallStack, CallStackAction


class TestCallStackBasic(unittest.TestCase):
    """Test CallStack construction and basic properties."""

    def test_default_construction(self):
        cs = CallStack()
        assert cs.call_site_addr == 0
        assert cs.func_addr == 0
        assert cs.stack_ptr == 0
        assert cs.ret_addr == 0
        assert cs.jumpkind == "Ijk_Call"
        assert cs.next is None
        assert cs.invoke_return_variable is None
        assert len(cs.block_counter) == 0
        assert cs.procedure_data is None
        assert cs.locals == {}

    def test_construction_with_args(self):
        cs = CallStack(
            call_site_addr=0x1000,
            func_addr=0x2000,
            stack_ptr=0x7FFF0000,
            ret_addr=0x1004,
            jumpkind="Ijk_Call",
        )
        assert cs.call_site_addr == 0x1000
        assert cs.func_addr == 0x2000
        assert cs.stack_ptr == 0x7FFF0000
        assert cs.ret_addr == 0x1004

    def test_current_function_address(self):
        cs = CallStack(func_addr=0xDEAD)
        assert cs.current_function_address == 0xDEAD
        cs.current_function_address = 0xBEEF
        assert cs.func_addr == 0xBEEF

    def test_current_stack_pointer(self):
        cs = CallStack(stack_ptr=0x7FFF0000)
        assert cs.current_stack_pointer == 0x7FFF0000

    def test_current_return_target(self):
        cs = CallStack(ret_addr=0x400100)
        assert cs.current_return_target == 0x400100

    def test_top(self):
        cs = CallStack(func_addr=0x1000)
        assert cs.top is cs


class TestCallStackIteration(unittest.TestCase):
    """Test iteration over call frames."""

    def test_single_frame_len(self):
        cs = CallStack()
        assert len(cs) == 1

    def test_single_frame_iter(self):
        cs = CallStack(func_addr=0x1000)
        frames = list(cs)
        assert len(frames) == 1
        assert frames[0].func_addr == 0x1000

    def test_multi_frame_iteration(self):
        f1 = CallStack(func_addr=0x1000, stack_ptr=0x7FFF0000, ret_addr=0)
        f2 = CallStack(func_addr=0x2000, stack_ptr=0x7FFEF000, ret_addr=0x1004, next_frame=f1)
        f3 = CallStack(func_addr=0x3000, stack_ptr=0x7FFEE000, ret_addr=0x2004, next_frame=f2)

        frames = list(f3)
        assert len(frames) == 3
        assert frames[0].func_addr == 0x3000
        assert frames[1].func_addr == 0x2000
        assert frames[2].func_addr == 0x1000

    def test_getitem(self):
        f1 = CallStack(func_addr=0x1000)
        f2 = CallStack(func_addr=0x2000, next_frame=f1)
        assert f2[0].func_addr == 0x2000
        assert f2[1].func_addr == 0x1000

    def test_getitem_out_of_range(self):
        cs = CallStack()
        with self.assertRaises(IndexError):
            _ = cs[5]


class TestCallStackEquality(unittest.TestCase):
    """Test equality and hashing."""

    def test_equal_single_frames(self):
        a = CallStack(func_addr=0x1000, stack_ptr=0x7000, ret_addr=0x500)
        b = CallStack(func_addr=0x1000, stack_ptr=0x7000, ret_addr=0x500)
        assert a == b

    def test_not_equal_different_func(self):
        a = CallStack(func_addr=0x1000, stack_ptr=0x7000, ret_addr=0x500)
        b = CallStack(func_addr=0x2000, stack_ptr=0x7000, ret_addr=0x500)
        assert a != b

    def test_not_equal_different_sp(self):
        a = CallStack(func_addr=0x1000, stack_ptr=0x7000, ret_addr=0x500)
        b = CallStack(func_addr=0x1000, stack_ptr=0x8000, ret_addr=0x500)
        assert a != b

    def test_not_equal_non_callstack(self):
        cs = CallStack()
        assert cs != "not a callstack"

    def test_hash_consistency(self):
        a = CallStack(func_addr=0x1000, stack_ptr=0x7000, ret_addr=0x500)
        b = CallStack(func_addr=0x1000, stack_ptr=0x7000, ret_addr=0x500)
        assert hash(a) == hash(b)

    def test_hash_in_set(self):
        a = CallStack(func_addr=0x1000, stack_ptr=0x7000, ret_addr=0x500)
        b = CallStack(func_addr=0x1000, stack_ptr=0x7000, ret_addr=0x500)
        s = {a}
        assert b in s


class TestCallStackRepr(unittest.TestCase):
    """Test string representations."""

    def test_repr(self):
        cs = CallStack()
        assert "CallStack" in repr(cs)
        assert "depth 1" in repr(cs)

    def test_str_backtrace(self):
        f1 = CallStack(func_addr=0x1000, call_site_addr=0, stack_ptr=0x7000)
        f2 = CallStack(func_addr=0x2000, call_site_addr=0x1000, stack_ptr=0x6000, next_frame=f1)
        s = str(f2)
        assert "Backtrace" in s
        assert "Frame 0" in s
        assert "Frame 1" in s

    def test_dbg_repr(self):
        cs = CallStack(func_addr=0x1000, call_site_addr=0x500, ret_addr=0x504)
        dbg = cs.dbg_repr()
        assert "0x500" in dbg
        assert "0x1000" in dbg


class TestCallStackPushPop(unittest.TestCase):
    """Test push and pop operations."""

    def test_push_increases_depth(self):
        cs = CallStack(func_addr=0x1000)
        new_frame = CallStack(func_addr=0x2000)
        result = cs.push(new_frame)
        assert len(result) == 2
        assert result.func_addr == 0x2000

    def test_pop_decreases_depth(self):
        f1 = CallStack(func_addr=0x1000)
        f2 = CallStack(func_addr=0x2000, next_frame=f1)
        result = f2.pop()
        assert len(result) == 1
        assert result.func_addr == 0x1000

    def test_pop_empty_raises(self):
        cs = CallStack(func_addr=0x1000)
        cs.next = None  # Ensure it's the only frame
        with self.assertRaises(SimEmptyCallStackError):
            cs.pop()

    def test_call(self):
        cs = CallStack(func_addr=0x1000, stack_ptr=0x7000)
        result = cs.call(
            callsite_addr=0x1050,
            addr=0x2000,
            retn_target=0x1054,
            stack_pointer=0x6FF0,
        )
        assert len(result) == 2
        assert result.func_addr == 0x2000
        assert result.call_site_addr == 0x1050
        assert result.ret_addr == 0x1054
        assert result.stack_ptr == 0x6FF0

    def test_ret_simple(self):
        f1 = CallStack(func_addr=0x1000, ret_addr=0)
        f2 = CallStack(func_addr=0x2000, ret_addr=0x1004, next_frame=f1)
        result = f2.ret()
        assert result.func_addr == 0x1000

    def test_ret_to_target(self):
        f1 = CallStack(func_addr=0x1000, ret_addr=0)
        f2 = CallStack(func_addr=0x2000, ret_addr=0x1004, next_frame=f1)
        f3 = CallStack(func_addr=0x3000, ret_addr=0x2004, next_frame=f2)

        # Return to f1's level by targeting f2's ret_addr
        result = f3.ret(retn_target=0x2004)
        # This should pop f3 (whose ret_addr matches 0x2004)
        assert result.func_addr == 0x2000


class TestCallStackSuffix(unittest.TestCase):
    """Test stack_suffix and stack_suffix_to_string."""

    def test_suffix_single_frame(self):
        cs = CallStack(call_site_addr=0x100, func_addr=0x200)
        suffix = cs.stack_suffix(1)
        assert len(suffix) == 2
        assert suffix == (0x100, 0x200)

    def test_suffix_padding(self):
        cs = CallStack(call_site_addr=0x100, func_addr=0x200)
        suffix = cs.stack_suffix(3)
        assert len(suffix) == 6
        # Should be padded with Nones at the beginning
        assert suffix[:4] == (None, None, None, None)
        assert suffix[4:] == (0x100, 0x200)

    def test_suffix_to_string(self):
        result = CallStack.stack_suffix_to_string((0x100, 0x200, None))
        assert "0x100" in result
        assert "0x200" in result
        assert "Unspecified" in result


class TestCallStackCopy(unittest.TestCase):
    """Test copy operations."""

    def test_copy_preserves_fields(self):
        cs = CallStack(func_addr=0x1000, stack_ptr=0x7000, ret_addr=0x500)
        cs.block_counter[0x1000] = 5
        cs.locals["x"] = 42

        copied = cs.copy({})
        assert copied.func_addr == 0x1000
        assert copied.stack_ptr == 0x7000
        assert copied.block_counter[0x1000] == 5
        assert copied.locals["x"] == 42

    def test_copy_independence(self):
        cs = CallStack(func_addr=0x1000)
        cs.locals["x"] = 42
        copied = cs.copy({})
        copied.locals["x"] = 99
        assert cs.locals["x"] == 42

    def test_copy_without_tail(self):
        f1 = CallStack(func_addr=0x1000)
        f2 = CallStack(func_addr=0x2000, next_frame=f1)
        copied = f2.copy_without_tail({})
        assert copied.func_addr == 0x2000
        assert copied.next is None


class TestCallStackAction(unittest.TestCase):
    """Test CallStackAction construction and validation."""

    def test_push_action(self):
        frame = CallStack(func_addr=0x1000)
        action = CallStackAction(
            callstack_hash=123,
            callstack_depth=2,
            action="push",
            callframe=frame,
        )
        assert action.action == "push"
        assert action.callframe is frame
        assert "push" in repr(action)

    def test_pop_action(self):
        action = CallStackAction(
            callstack_hash=456,
            callstack_depth=1,
            action="pop",
            ret_site_addr=0x1004,
        )
        assert action.action == "pop"
        assert action.ret_site_addr == 0x1004
        assert "pop" in repr(action)

    def test_invalid_action_raises(self):
        with self.assertRaises(AngrError):
            CallStackAction(callstack_hash=0, callstack_depth=0, action="invalid")

    def test_push_without_callframe_raises(self):
        with self.assertRaises(AngrError):
            CallStackAction(callstack_hash=0, callstack_depth=0, action="push")

    def test_pop_with_callframe_raises(self):
        frame = CallStack()
        with self.assertRaises(AngrError):
            CallStackAction(callstack_hash=0, callstack_depth=0, action="pop", callframe=frame)


class TestCallStackSetState(unittest.TestCase):
    """Test set_state behavior with stack pointer initialization."""

    def test_set_state_initializes_sp(self):
        state = SimState(arch="AMD64")
        cs = CallStack()
        # stack_ptr should be 0 before set_state
        assert cs.stack_ptr == 0
        cs.set_state(state)
        # After set_state with a 0 stack_ptr, it should be set to max value
        assert cs.stack_ptr == 2**64 - 1


if __name__ == "__main__":
    unittest.main()
