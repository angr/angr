"""Tests for variable unification with interference checking."""

from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins"  # pylint:disable=redefined-builtin

import random
import unittest
from collections import defaultdict

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


def _reference_classes(vm, interference):
    """The pairwise algorithm unify_variables() used before class-level interference sets."""
    classes = {v: {v} for v in list(vm._variables) + list(vm._phi_variables)}

    def unify(v1, v2):
        c1, c2 = classes[v1], classes[v2]
        if c1 is not c2:
            c1.update(c2)
            for v in c2:
                classes[v] = c1

    def interfere(c1, c2):
        return any(
            interference.has_edge(a, b)
            for m1 in c1
            for m2 in c2
            for a in vm._variable_to_vvarids.get(m1, ())
            for b in vm._variable_to_vvarids.get(m2, ())
        )

    for v, subvs in vm._phi_variables.items():
        for subv in subvs:
            unify(subv, v)
    by_offset = defaultdict(set)
    for v in sorted(classes, key=lambda v: v.ident or ""):
        by_offset[v.offset].add(v)
    for vs in by_offset.values():
        for v1 in sorted(vs, key=lambda v: v.ident or ""):
            for v2 in sorted(vs - classes[v1], key=lambda v: v.ident or ""):
                c1, c2 = classes[v1], classes[v2]
                if c1 is not c2 and interfere(c1, c2):
                    continue
                unify(v1, v2)
    return {frozenset(c) for c in map(frozenset, classes.values())}


def _classes(vm):
    groups = defaultdict(set)
    for var in list(vm._variables) + list(vm._phi_variables):
        groups[id(vm.unified_variable(var))].add(var)
    return {frozenset(g) for g in groups.values()}


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

    def test_matches_pairwise_reference(self):
        """Random offsets, multi-vvar variables, phi variables and duplicate idents give the pairwise result."""
        for seed in range(30):
            rng = random.Random(seed)
            vm = _make_vm()
            n = rng.randint(5, 60)
            variables = []
            for i in range(n):
                ident = f"is_{rng.randrange(n // 2) if seed % 3 == 0 else i}"
                var = SimStackVariable(-8 * rng.randint(1, 3), 8, ident=ident, region=vm.func_addr, base="bp")
                vm._variables.add(var)
                vm._variable_to_vvarids[var] = {rng.randrange(3 * n) for _ in range(rng.randint(0, 3))}
                variables.append(var)
            for j in range(rng.randint(0, 4)):
                phi = SimStackVariable(-8 * rng.randint(1, 3), 8, ident=f"phi_{j}", region=vm.func_addr, base="bp")
                vm._phi_variables[phi] = {v for v in rng.sample(variables, 2) if v.offset == phi.offset}
            interference = networkx.Graph()
            interference.add_nodes_from(range(3 * n))
            for _ in range(rng.randint(0, 4 * n)):
                interference.add_edge(rng.randrange(3 * n), rng.randrange(3 * n))
            expected = _reference_classes(vm, interference)
            vm.unify_variables(interference)
            assert _classes(vm) == expected, f"seed {seed}"


if __name__ == "__main__":
    unittest.main()
