import pytest
import claripy


def test_unsat_core_simple():
    """Test basic unsat core functionality"""
    # Create a solver with unsat_core enabled
    s = claripy.Solver(track=True)

    x = claripy.BVS("x", 8)

    # Add contradictory constraints
    s.add(x > 10)  # constraint 0
    s.add(x < 5)  # constraint 1
    s.add(x > 0)  # constraint 2 (not part of unsat core)

    # Should be unsat
    assert not s.satisfiable()

    # Get unsat core
    core = s.unsat_core()

    # Core should contain the contradictory constraints
    assert len(core) > 0
    assert 0 in core
    assert 1 in core
    # constraint 2 should not be necessary for unsat


def test_unsat_core_bool():
    """Test unsat core with boolean constraints"""
    s = claripy.Solver(track=True)

    a = claripy.BoolS("a")
    b = claripy.BoolS("b")

    # Add contradictory constraints
    s.add(a == b)  # constraint 0
    s.add(a)  # constraint 1: a is true
    s.add(claripy.Not(b))  # constraint 2: b is false

    # Should be unsat
    assert not s.satisfiable()

    # Get unsat core - all three constraints are necessary
    core = s.unsat_core()
    assert len(core) > 0


def test_unsat_core_not_enabled():
    """Test that unsat_core raises error when not enabled"""
    s = claripy.Solver()  # unsat_core not enabled

    x = claripy.BVS("x", 8)
    s.add(x > 10)
    s.add(x < 5)

    assert not s.satisfiable()

    # Should raise an error
    with pytest.raises(Exception):
        s.unsat_core()


def test_unsat_core_on_sat():
    """Test that unsat_core raises error on SAT result"""
    s = claripy.Solver(track=True)

    x = claripy.BVS("x", 8)
    s.add(x > 5)

    # Should be sat
    assert s.satisfiable()

    # Should raise an error because it's SAT
    with pytest.raises(Exception):
        s.unsat_core()


def test_unsat_core_complex():
    """Test unsat core with more complex constraints"""
    s = claripy.Solver(track=True)

    x = claripy.BVS("x", 32)
    y = claripy.BVS("y", 32)

    # Add various constraints
    s.add(x + y == 100)  # constraint 0
    s.add(x > 60)  # constraint 1
    s.add(y > 50)  # constraint 2 - makes it unsat with 0 and 1
    s.add(x < 200)  # constraint 3 - not relevant
    s.add(y < 200)  # constraint 4 - not relevant

    # Should be unsat (x > 60 and y > 50 means x + y > 110)
    assert not s.satisfiable()

    # Get unsat core
    core = s.unsat_core()
    assert len(core) > 0
    # Core should contain 0, 1, and 2
    assert 0 in core
    assert 1 in core
    assert 2 in core


def test_unsat_core_composite():
    """SolverComposite returns the core of whichever independent child is unsat."""
    s = claripy.SolverComposite(track=True)

    x = claripy.BVS("x", 8)
    y = claripy.BVS("y", 8)

    # Contradictory group on x (constraints 0, 1) plus an independent,
    # satisfiable group on y (constraint 2).
    s.add(x > 10)
    s.add(x < 5)
    s.add(y == 3)

    assert not s.satisfiable()

    core = s.unsat_core()
    assert len(core) > 0
    assert 0 in core
    assert 1 in core
    # The independent, satisfiable constraint is not part of the core.
    assert 2 not in core


def test_unsat_core_composite_on_sat():
    """A satisfiable composite solver has an empty unsat core."""
    s = claripy.SolverComposite(track=True)
    x = claripy.BVS("x", 8)
    y = claripy.BVS("y", 8)
    s.add(x > 1)
    s.add(y < 10)
    assert s.satisfiable()
    assert s.unsat_core() == []


if __name__ == "__main__":
    test_unsat_core_simple()
    test_unsat_core_bool()
    test_unsat_core_not_enabled()
    test_unsat_core_on_sat()
    test_unsat_core_complex()
    test_unsat_core_composite()
    test_unsat_core_composite_on_sat()
    print("All tests passed!")
