"""Tests for variable unification with interference checking."""

from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins"  # pylint:disable=redefined-builtin

import unittest

import networkx

import angr
from angr.sim_variable import SimStackVariable


def _make_vm(func_addr=0x400000):
    """Create a minimal VariableManagerInternal for testing."""
    proj = angr.load_shellcode(b"\xc3", "amd64")
    return proj.kb.variables.get_function_manager(func_addr)


def _add_stack_var(vm, offset, size, ident, vvar_id):
    """Add a stack variable to the manager and map it to a VVar ID."""
    var = SimStackVariable(offset, size, ident=ident, region=vm.func_addr, base="bp")
    vm._variables.add(var)
    vm._variable_to_vvarids[var] = {vvar_id}


def _unify_and_check(vm, interference):
    """Run unification and return {ident: unified_ident} mapping."""
    vm.unify_variables(interference)
    result = {}
    for var in vm._variables:
        if isinstance(var, SimStackVariable):
            unified = vm.unified_variable(var)
            result[var.ident] = unified.ident if unified else None
    return result


class TestVariableUnification(unittest.TestCase):
    """Tests for unify_variables interference-aware congruence classes."""

    def test_non_interfering_same_offset_unified(self):
        """Two non-interfering variables at the same offset should be unified."""
        vm = _make_vm()
        _add_stack_var(vm, -8, 8, "is_0", vvar_id=10)
        _add_stack_var(vm, -8, 8, "is_1", vvar_id=11)

        interference = networkx.Graph()
        interference.add_nodes_from([10, 11])

        result = _unify_and_check(vm, interference)
        assert result["is_0"] == result["is_1"], f"Should be unified: {result}"

    def test_interfering_same_offset_not_unified(self):
        """Two interfering variables at the same offset should NOT be unified."""
        vm = _make_vm()
        _add_stack_var(vm, -8, 8, "is_0", vvar_id=10)
        _add_stack_var(vm, -8, 8, "is_1", vvar_id=11)

        interference = networkx.Graph()
        interference.add_edge(10, 11)

        result = _unify_and_check(vm, interference)
        assert result["is_0"] != result["is_1"], f"Should NOT be unified: {result}"

    def test_transitive_merge_blocked_by_interference(self):
        """a<->b interfere, but both non-interfering with c.
        a and b must NOT end up in the same class via c."""
        vm = _make_vm()
        _add_stack_var(vm, -8, 8, "is_0", vvar_id=10)
        _add_stack_var(vm, -8, 8, "is_1", vvar_id=11)
        _add_stack_var(vm, -8, 8, "is_2", vvar_id=12)

        interference = networkx.Graph()
        interference.add_nodes_from([10, 11, 12])
        interference.add_edge(10, 11)  # a <-> b

        result = _unify_and_check(vm, interference)
        assert result["is_0"] != result["is_1"], f"a and b interfere -- must not share a class: {result}"
        # c should be unified with one of them (whichever it merged with first)
        assert result["is_2"] == result["is_0"] or result["is_2"] == result["is_1"], (
            f"c should be unified with either a or b: {result}"
        )

    def test_diamond_interference(self):
        """a<->b and c<->d, all other pairs non-interfering.
        Should produce two classes, never merge interfering pairs."""
        vm = _make_vm()
        _add_stack_var(vm, -8, 8, "is_0", vvar_id=10)
        _add_stack_var(vm, -8, 8, "is_1", vvar_id=11)
        _add_stack_var(vm, -8, 8, "is_2", vvar_id=12)
        _add_stack_var(vm, -8, 8, "is_3", vvar_id=13)

        interference = networkx.Graph()
        interference.add_nodes_from([10, 11, 12, 13])
        interference.add_edge(10, 11)  # a <-> b
        interference.add_edge(12, 13)  # c <-> d

        result = _unify_and_check(vm, interference)
        assert result["is_0"] != result["is_1"], f"a<->b must differ: {result}"
        assert result["is_2"] != result["is_3"], f"c<->d must differ: {result}"

    def test_chain_no_interference(self):
        """a, b, c all non-interfering -- should all unify."""
        vm = _make_vm()
        _add_stack_var(vm, -8, 8, "is_0", vvar_id=10)
        _add_stack_var(vm, -8, 8, "is_1", vvar_id=11)
        _add_stack_var(vm, -8, 8, "is_2", vvar_id=12)

        interference = networkx.Graph()
        interference.add_nodes_from([10, 11, 12])

        result = _unify_and_check(vm, interference)
        assert result["is_0"] == result["is_1"] == result["is_2"], f"All should be unified: {result}"

    def test_different_offsets_not_unified(self):
        """Variables at different stack offsets should never be unified."""
        vm = _make_vm()
        _add_stack_var(vm, -8, 8, "is_0", vvar_id=10)
        _add_stack_var(vm, -16, 8, "is_1", vvar_id=11)

        interference = networkx.Graph()
        interference.add_nodes_from([10, 11])

        result = _unify_and_check(vm, interference)
        assert result["is_0"] != result["is_1"], f"Different offsets must differ: {result}"

    def test_full_clique_all_interfering(self):
        """Three mutually interfering variables -- none should be unified."""
        vm = _make_vm()
        _add_stack_var(vm, -8, 8, "is_0", vvar_id=10)
        _add_stack_var(vm, -8, 8, "is_1", vvar_id=11)
        _add_stack_var(vm, -8, 8, "is_2", vvar_id=12)

        interference = networkx.Graph()
        interference.add_edge(10, 11)
        interference.add_edge(11, 12)
        interference.add_edge(10, 12)

        result = _unify_and_check(vm, interference)
        assert len(set(result.values())) == 3, f"All should be separate: {result}"


if __name__ == "__main__":
    unittest.main()
