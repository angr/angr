# pylint:disable=protected-access
from __future__ import annotations

import random
from collections.abc import Collection, Iterator
from unittest.mock import patch

from angr.analyses.typehoon.simple_solver import SimpleSolver
from angr.analyses.typehoon.typeconsts import Float32, Int8, Int32, TypeConstant
from angr.analyses.typehoon.typevars import (
    DerivedTypeVariable,
    Existence,
    Load,
    Store,
    Subtype,
    TypeConstraint,
    TypeVariable,
)


def _reference_generate_constraint_subset(
    constraints: Collection[TypeConstraint],
    typevars: Collection[TypeVariable | TypeConstant],
) -> tuple[set[TypeConstraint], set[TypeVariable | TypeConstant]]:
    """The scan-to-fixpoint implementation that the indexed traversal replaces."""
    subset: set[TypeConstraint] = set()
    related_typevars = set(typevars)
    while True:
        new: set[TypeConstraint] = set()
        for constraint in constraints:
            if constraint in subset or not isinstance(constraint, Subtype):
                continue
            if isinstance(constraint.sub_type, DerivedTypeVariable):
                subtype = constraint.sub_type.type_var
            elif isinstance(constraint.sub_type, TypeVariable):
                subtype = constraint.sub_type
            else:
                subtype = None
            if isinstance(constraint.super_type, DerivedTypeVariable):
                supertype = constraint.super_type.type_var
            elif isinstance(constraint.super_type, TypeVariable):
                supertype = constraint.super_type
            else:
                supertype = None
            if subtype in related_typevars or supertype in related_typevars:
                new.add(constraint)
                if subtype is not None:
                    related_typevars.add(subtype)
                if supertype is not None:
                    related_typevars.add(supertype)
        if not new:
            break
        subset |= new
    return subset, related_typevars


class _IterationCountingSet(set[TypeConstraint]):
    def __init__(self, values: Collection[TypeConstraint]):
        super().__init__(values)
        self.iterations = 0

    def __iter__(self) -> Iterator[TypeConstraint]:
        self.iterations += 1
        return super().__iter__()


def test_constraint_subset_preserves_endpoint_semantics():
    root = TypeVariable(name="root")
    connected = TypeVariable(name="connected")
    out_of_scope_bridge = TypeVariable(name="out_of_scope_bridge")
    through_bridge = TypeVariable(name="through_bridge")
    through_derived_constant = TypeVariable(name="through_derived_constant")
    plain_constant_neighbor = TypeVariable(name="plain_constant_neighbor")
    disconnected_a = TypeVariable(name="disconnected_a")
    disconnected_b = TypeVariable(name="disconnected_b")

    derived_root = Subtype(DerivedTypeVariable(root, Load()), connected)
    bridge_in = Subtype(connected, out_of_scope_bridge)
    bridge_out = Subtype(DerivedTypeVariable(out_of_scope_bridge, Store()), through_bridge)
    derived_constant_in = Subtype(through_bridge, DerivedTypeVariable(Int32(), Load()))
    derived_constant_out = Subtype(DerivedTypeVariable(Int32(), Store()), through_derived_constant)
    plain_constant_in = Subtype(through_derived_constant, Float32())
    plain_constant_out = Subtype(Float32(), plain_constant_neighbor)
    constant_only = Subtype(Int8(), Float32())
    ignored_non_subtype = Existence(DerivedTypeVariable(root, Store()))
    disconnected = Subtype(disconnected_a, disconnected_b)
    constraints: set[TypeConstraint] = {
        derived_root,
        bridge_in,
        bridge_out,
        derived_constant_in,
        derived_constant_out,
        plain_constant_in,
        plain_constant_out,
        constant_only,
        ignored_non_subtype,
        disconnected,
    }

    index = SimpleSolver._index_subtype_constraints(constraints)
    subset, related = SimpleSolver._generate_constraint_subset(constraints, {root}, endpoint_to_constraints=index)

    assert subset == {
        derived_root,
        bridge_in,
        bridge_out,
        derived_constant_in,
        derived_constant_out,
        plain_constant_in,
    }
    assert related == {
        root,
        connected,
        out_of_scope_bridge,
        through_bridge,
        Int32(),
        through_derived_constant,
    }
    assert plain_constant_neighbor not in related
    assert disconnected_a not in related


def test_constraint_subset_matches_reference_on_randomized_graphs():
    rng = random.Random(0x5EED)

    for trial in range(200):
        typevars = [TypeVariable(idx=(trial, idx)) for idx in range(12)]
        constants: list[TypeConstant] = [Int8(), Int32(), Float32()]
        endpoints: list[TypeVariable | TypeConstant] = [*typevars, *constants]
        endpoints += [
            DerivedTypeVariable(typevar, Load() if idx % 2 == 0 else Store())
            for idx, typevar in enumerate([*typevars, *constants])
        ]

        constraints: set[TypeConstraint] = {Subtype(rng.choice(endpoints), rng.choice(endpoints)) for _ in range(48)}
        constraints.update(Existence(rng.choice(endpoints)) for _ in range(8))
        seeds = set(rng.sample(typevars, rng.randint(1, 4)))

        expected = _reference_generate_constraint_subset(constraints, seeds)
        index = SimpleSolver._index_subtype_constraints(constraints)
        indexed = SimpleSolver._generate_constraint_subset(constraints, seeds, endpoint_to_constraints=index)
        on_demand = SimpleSolver._generate_constraint_subset(constraints, seeds)

        assert indexed == expected
        assert on_demand == expected


def test_constraint_subset_unions_disconnected_seeds_and_preserves_orphans():
    left_a = TypeVariable(name="left_a")
    left_b = TypeVariable(name="left_b")
    right_a = TypeVariable(name="right_a")
    right_b = TypeVariable(name="right_b")
    orphan = TypeVariable(name="orphan")
    left = Subtype(left_a, left_b)
    right = Subtype(right_a, right_b)
    constraints: set[TypeConstraint] = {left, right}

    subset, related = SimpleSolver._generate_constraint_subset(constraints, {left_a, right_a, orphan})

    assert subset == constraints
    assert related == {left_a, left_b, right_a, right_b, orphan}


def test_constraint_index_is_reused_across_many_components():
    typevars = [TypeVariable(idx=(0x400000, idx)) for idx in range(1024)]
    constraints = _IterationCountingSet(
        [Subtype(typevars[idx], typevars[idx + 1]) for idx in range(0, len(typevars), 2)]
    )

    index = SimpleSolver._index_subtype_constraints(constraints)
    assert constraints.iterations == 1

    for idx in range(0, len(typevars), 2):
        subset, related = SimpleSolver._generate_constraint_subset(
            constraints, {typevars[idx]}, endpoint_to_constraints=index
        )
        assert subset == {Subtype(typevars[idx], typevars[idx + 1])}
        assert related == {typevars[idx], typevars[idx + 1]}

    assert constraints.iterations == 1


def test_simple_solver_builds_one_constraint_index_per_solve():
    function_typevar = TypeVariable(name="function")
    lower = TypeVariable(name="lower")
    upper = TypeVariable(name="upper")
    constraints = {function_typevar: {Subtype(lower, upper), Subtype(upper, Int32())}}
    typevars = {function_typevar: {lower, upper}}

    original_indexer = SimpleSolver._index_subtype_constraints
    with patch.object(SimpleSolver, "_index_subtype_constraints", wraps=original_indexer) as indexer:
        solver = SimpleSolver(64, constraints, typevars)

    assert indexer.call_count == 1
    assert solver.eqclass_constraints_count == [2]
    assert solver.solution[lower] == Int32()
    assert solver.solution[upper] == Int32()

    unconstrained_function = TypeVariable(name="unconstrained_function")
    unconstrained = TypeVariable(name="unconstrained")
    with patch.object(SimpleSolver, "_index_subtype_constraints", wraps=original_indexer) as indexer:
        SimpleSolver(64, {unconstrained_function: set()}, {unconstrained_function: {unconstrained}})

    assert indexer.call_count == 0
