"""
Tests for angr.knowledge_plugins.cfg.cfg_node (CFGNode, CFGENode, CFGNodeCreationFailure).

Coverage gap: CFGNode (554 lines) is the fundamental building block of Control Flow
Graphs in angr with NO direct test coverage. This file tests:
- CFGNode construction and defaults
- Properties: is_simprocedure, name, callstack_key
- __eq__ and __hash__
- __repr__
- copy()
- merge()
- to_codenode()
- Serialization (getstate/setstate)
- CFGENode construction and specific properties
- CFGNodeCreationFailure
"""

from __future__ import annotations

import unittest

from angr.knowledge_plugins.cfg.cfg_node import CFGNode, CFGENode, CFGNodeCreationFailure
from angr.codenode import BlockNode, HookNode


class MockCFGModel:
    """Minimal mock of CFGModel for testing CFGNode."""

    def __init__(self, project=None, ident="CFGFast"):
        self.project = project
        self.ident = ident
        self._iropt_level = None
        self._graph = {}

    def get_successors(self, node):
        return self._graph.get(id(node), {}).get("successors", [])

    def get_predecessors(self, node):
        return self._graph.get(id(node), {}).get("predecessors", [])

    def get_successors_and_jumpkinds(self, node, excluding_fakeret=True):
        return []

    def get_predecessors_and_jumpkinds(self, node, excluding_fakeret=True):
        return []


class TestCFGNodeConstruction(unittest.TestCase):
    """Test CFGNode construction and basic properties."""

    def test_basic_construction(self):
        cfg = MockCFGModel()
        node = CFGNode(0x400000, 16, cfg, block_id=0x400000)
        assert node.addr == 0x400000
        assert node.size == 16
        assert node.block_id == 0x400000
        assert node.no_ret is False
        assert node.thumb is False
        assert node.has_return is False
        assert node.instruction_addrs == []

    def test_construction_with_instructions(self):
        cfg = MockCFGModel()
        instrs = [0x400000, 0x400004, 0x400008]
        node = CFGNode(0x400000, 12, cfg, block_id=0x400000, instruction_addrs=instrs)
        assert node.instruction_addrs == instrs

    def test_construction_with_simprocedure(self):
        cfg = MockCFGModel()
        node = CFGNode(0x400000, 0, cfg, simprocedure_name="puts", block_id=0x400000)
        assert node.simprocedure_name == "puts"
        assert node.is_simprocedure is True

    def test_not_simprocedure(self):
        cfg = MockCFGModel()
        node = CFGNode(0x400000, 16, cfg, block_id=0x400000)
        assert node.is_simprocedure is False

    def test_callstack_key_is_none(self):
        cfg = MockCFGModel()
        node = CFGNode(0x400000, 16, cfg, block_id=0x400000)
        assert node.callstack_key is None

    def test_byte_string(self):
        cfg = MockCFGModel()
        node = CFGNode(0x400000, 4, cfg, block_id=0x400000, byte_string=b"\x90\x90\x90\x90")
        assert node.byte_string == b"\x90\x90\x90\x90"

    def test_name_from_simprocedure(self):
        cfg = MockCFGModel()
        node = CFGNode(0x400000, 0, cfg, simprocedure_name="malloc", block_id=0x400000)
        assert node.name == "malloc"

    def test_name_explicit(self):
        cfg = MockCFGModel()
        node = CFGNode(0x400000, 16, cfg, block_id=0x400000, name="my_func")
        assert node.name == "my_func"

    def test_block_id_defaults_to_addr_when_none(self):
        """When block_id is None, it should default to addr with a warning."""
        cfg = MockCFGModel()
        node = CFGNode(0x400000, 16, cfg)
        assert node.block_id == 0x400000


class TestCFGNodeEquality(unittest.TestCase):
    """Test __eq__ and __hash__."""

    def test_equal_nodes(self):
        cfg = MockCFGModel()
        a = CFGNode(0x400000, 16, cfg, block_id=0x400000)
        b = CFGNode(0x400000, 16, cfg, block_id=0x400000)
        assert a == b

    def test_not_equal_different_addr(self):
        cfg = MockCFGModel()
        a = CFGNode(0x400000, 16, cfg, block_id=0x400000)
        b = CFGNode(0x400010, 16, cfg, block_id=0x400010)
        assert a != b

    def test_not_equal_different_size(self):
        cfg = MockCFGModel()
        a = CFGNode(0x400000, 16, cfg, block_id=0x400000)
        b = CFGNode(0x400000, 32, cfg, block_id=0x400000)
        assert a != b

    def test_not_equal_different_type(self):
        cfg = MockCFGModel()
        a = CFGNode(0x400000, 16, cfg, block_id=0x400000)
        assert a != "not a node"

    def test_hash_equal_nodes(self):
        cfg = MockCFGModel()
        a = CFGNode(0x400000, 16, cfg, block_id=0x400000)
        b = CFGNode(0x400000, 16, cfg, block_id=0x400000)
        assert hash(a) == hash(b)

    def test_hash_in_set(self):
        cfg = MockCFGModel()
        a = CFGNode(0x400000, 16, cfg, block_id=0x400000)
        b = CFGNode(0x400000, 16, cfg, block_id=0x400000)
        s = {a}
        assert b in s

    def test_eq_with_simsuccessors_raises(self):
        """Comparing with SimSuccessors should raise ValueError."""
        from angr.engines.successors import SimSuccessors

        cfg = MockCFGModel()
        node = CFGNode(0x400000, 16, cfg, block_id=0x400000)
        ss = SimSuccessors(0x400000, None)
        with self.assertRaises(ValueError):
            _ = node == ss


class TestCFGNodeRepr(unittest.TestCase):
    """Test __repr__."""

    def test_repr_basic(self):
        cfg = MockCFGModel()
        node = CFGNode(0x400000, 16, cfg, block_id=0x400000)
        r = repr(node)
        assert "<CFGNode" in r
        assert "0x400000" in r
        assert "[16]" in r

    def test_repr_with_name(self):
        cfg = MockCFGModel()
        node = CFGNode(0x400000, 16, cfg, block_id=0x400000, name="main")
        r = repr(node)
        assert "main" in r

    def test_repr_simprocedure(self):
        cfg = MockCFGModel()
        node = CFGNode(0x400000, 0, cfg, simprocedure_name="puts", block_id=0x400000)
        r = repr(node)
        assert "puts" in r


class TestCFGNodeCopy(unittest.TestCase):
    """Test copy."""

    def test_copy_preserves_fields(self):
        cfg = MockCFGModel()
        node = CFGNode(
            0x400000, 16, cfg,
            block_id=0x400000,
            simprocedure_name=None,
            no_ret=True,
            function_address=0x400000,
            thumb=True,
            byte_string=b"\x90" * 16,
            instruction_addrs=[0x400000, 0x400004],
            name="test",
        )
        copied = node.copy()
        assert copied.addr == node.addr
        assert copied.size == node.size
        assert copied.no_ret == node.no_ret
        assert copied.thumb == node.thumb
        assert copied.byte_string == node.byte_string
        assert copied.instruction_addrs == node.instruction_addrs

    def test_copy_independence(self):
        cfg = MockCFGModel()
        node = CFGNode(0x400000, 16, cfg, block_id=0x400000, instruction_addrs=[0x400000])
        copied = node.copy()
        copied.instruction_addrs.append(0x400004)
        assert len(node.instruction_addrs) == 1


class TestCFGNodeMerge(unittest.TestCase):
    """Test merge (combining consecutive blocks)."""

    def test_merge_adds_sizes(self):
        cfg = MockCFGModel()
        a = CFGNode(0x400000, 16, cfg, block_id=0x400000, byte_string=b"\x90" * 16,
                     instruction_addrs=[0x400000, 0x400004])
        b = CFGNode(0x400010, 8, cfg, block_id=0x400010, byte_string=b"\xcc" * 8,
                     instruction_addrs=[0x400010])

        merged = a.merge(b)
        assert merged.addr == 0x400000
        assert merged.size == 24
        assert merged.byte_string == b"\x90" * 16 + b"\xcc" * 8
        assert merged.instruction_addrs == [0x400000, 0x400004, 0x400010]

    def test_merge_with_none_byte_string(self):
        cfg = MockCFGModel()
        a = CFGNode(0x400000, 16, cfg, block_id=0x400000, byte_string=None)
        b = CFGNode(0x400010, 8, cfg, block_id=0x400010, byte_string=b"\xcc" * 8)

        merged = a.merge(b)
        assert merged.byte_string is None


class TestCFGNodeCodenode(unittest.TestCase):
    """Test to_codenode."""

    def test_block_node(self):
        cfg = MockCFGModel()
        node = CFGNode(0x400000, 16, cfg, block_id=0x400000)
        cn = node.to_codenode()
        assert isinstance(cn, BlockNode)
        assert cn.addr == 0x400000
        assert cn.size == 16

    def test_hook_node(self):
        cfg = MockCFGModel()
        node = CFGNode(0x400000, 0, cfg, simprocedure_name="puts", block_id=0x400000)
        cn = node.to_codenode()
        assert isinstance(cn, HookNode)


class TestCFGNodePickle(unittest.TestCase):
    """Test getstate/setstate."""

    def test_getstate(self):
        cfg = MockCFGModel()
        node = CFGNode(0x400000, 16, cfg, block_id=0x400000, name="test", no_ret=True)
        state = node.__getstate__()
        assert state["addr"] == 0x400000
        assert state["size"] == 16
        assert state["no_ret"] is True
        assert state["_name"] == "test"

    def test_setstate_roundtrip(self):
        cfg = MockCFGModel()
        node = CFGNode(0x400000, 16, cfg, block_id=0x400000, name="test",
                       instruction_addrs=[0x400000, 0x400004])
        state = node.__getstate__()

        restored = CFGNode.__new__(CFGNode)
        restored.__setstate__(state)
        assert restored.addr == 0x400000
        assert restored.size == 16
        assert restored._name == "test"
        assert restored.instruction_addrs == [0x400000, 0x400004]


class TestCFGENode(unittest.TestCase):
    """Test CFGENode (CFGEmulated-specific node)."""

    def test_construction(self):
        cfg = MockCFGModel()
        node = CFGENode(
            0x400000, 16, cfg,
            block_id=0x400000,
            looping_times=2,
            depth=5,
            callstack_key=("key",),
        )
        assert node.looping_times == 2
        assert node.depth == 5
        assert node.callstack_key == ("key",)
        assert node.final_states == []
        assert node.return_target is None

    def test_creation_failed(self):
        cfg = MockCFGModel()
        node = CFGENode(0x400000, 16, cfg, block_id=0x400000)
        assert node.creation_failed is False

    def test_downsize(self):
        cfg = MockCFGModel()
        node = CFGENode(0x400000, 16, cfg, block_id=0x400000)
        node.input_state = "some_state"
        node.final_states = ["s1", "s2"]
        node.downsize()
        assert node.input_state is None
        assert node.final_states == []

    def test_repr(self):
        cfg = MockCFGModel()
        node = CFGENode(0x400000, 16, cfg, block_id=0x400000, looping_times=3)
        r = repr(node)
        assert "CFGENode" in r
        assert "0x400000" in r
        assert "3" in r

    def test_eq_enode(self):
        cfg = MockCFGModel()
        a = CFGENode(0x400000, 16, cfg, block_id=0x400000, callstack_key=("k",))
        b = CFGENode(0x400000, 16, cfg, block_id=0x400000, callstack_key=("k",))
        assert a == b

    def test_not_eq_different_callstack(self):
        cfg = MockCFGModel()
        a = CFGENode(0x400000, 16, cfg, block_id=0x400000, callstack_key=("k1",))
        b = CFGENode(0x400000, 16, cfg, block_id=0x400000, callstack_key=("k2",))
        assert a != b

    def test_enode_copy(self):
        cfg = MockCFGModel()
        node = CFGENode(
            0x400000, 16, cfg,
            block_id=0x400000,
            looping_times=2,
            depth=3,
            callstack_key=("k",),
        )
        copied = node.copy()
        assert copied.addr == node.addr
        assert copied.looping_times == node.looping_times
        assert copied.depth == node.depth
        assert copied.callstack_key == node.callstack_key

    def test_enode_getstate_setstate(self):
        cfg = MockCFGModel()
        node = CFGENode(
            0x400000, 16, cfg,
            block_id=0x400000,
            looping_times=2,
            depth=3,
            callstack_key=("k",),
            name="test_enode",
        )
        state = node.__getstate__()
        restored = CFGENode.__new__(CFGENode)
        restored.__setstate__(state)
        assert restored.looping_times == 2
        assert restored.depth == 3
        assert restored.callstack_key == ("k",)


class TestCFGNodeCreationFailure(unittest.TestCase):
    """Test CFGNodeCreationFailure."""

    def test_from_exception(self):
        try:
            raise ValueError("test error")
        except ValueError:
            import sys
            failure = CFGNodeCreationFailure(exc_info=sys.exc_info())

        assert "ValueError" in failure.short_reason
        assert "test error" in failure.long_reason
        assert len(failure.traceback) > 0

    def test_copy(self):
        try:
            raise TypeError("copy test")
        except TypeError:
            import sys
            original = CFGNodeCreationFailure(exc_info=sys.exc_info())

        copied = CFGNodeCreationFailure(to_copy=original)
        assert copied.short_reason == original.short_reason
        assert copied.long_reason == original.long_reason


if __name__ == "__main__":
    unittest.main()
