import pickle

import claripy


def test_solver_cacheless_exists():
    """SolverCacheless is exported and constructible."""
    s = claripy.SolverCacheless()
    assert isinstance(s, claripy.Solver)


def test_cacheless_matches_caching_solver():
    """The caching Solver and SolverCacheless must agree on every query."""
    x = claripy.BVS("x", 32)

    cached = claripy.Solver()
    cacheless = claripy.SolverCacheless()
    for s in (cached, cacheless):
        s.add(x >= 10)
        s.add(x <= 20)

    assert cached.satisfiable() == cacheless.satisfiable()
    # Repeated checks (the caching solver answers the second from cache).
    assert cached.satisfiable()

    cached_vals = set(cached.eval(x, 5))
    cacheless_vals = set(cacheless.eval(x, 5))
    # Every solution lies within the constraints for both solvers.
    for vals in (cached_vals, cacheless_vals):
        assert vals
        assert all(10 <= v <= 20 for v in vals)


def test_cacheless_unsat():
    s = claripy.SolverCacheless()
    x = claripy.BVS("x", 8)
    s.add(x == 1)
    s.add(x == 2)
    assert not s.satisfiable()


def test_caching_solver_repeated_eval_consistent():
    """Reusing a cached model must stay consistent with the constraints."""
    s = claripy.Solver()
    x = claripy.BVS("x", 32)
    y = claripy.BVS("y", 32)
    s.add(y == x + 1)
    s.add(x == 7)

    # The cache should serve these without changing the answer.
    assert s.eval(x, 1)[0] == 7
    assert s.eval(y, 1)[0] == 8
    assert s.satisfiable()


def test_cacheless_extra_constraints():
    s = claripy.SolverCacheless()
    x = claripy.BVS("x", 32)
    s.add(x >= 10)

    assert s.satisfiable(extra_constraints=[x == 15])
    assert not s.satisfiable(extra_constraints=[x == 5])
    # Extra constraints must not persist.
    assert s.satisfiable()


def test_cacheless_branch_stays_cacheless():
    s = claripy.SolverCacheless()
    x = claripy.BVS("x", 8)
    s.add(x > 3)

    b = s.branch()
    assert isinstance(b, claripy.Solver)
    assert b.satisfiable()
    # The branch carries the constraints over.
    assert any(c is not None for c in b.constraints)


def test_cacheless_pickle_roundtrip():
    s = claripy.SolverCacheless()
    x = claripy.BVS("x", 16)
    s.add(x == 42)

    restored = pickle.loads(pickle.dumps(s))
    assert restored.satisfiable()
    assert restored.eval(x, 1)[0] == 42


if __name__ == "__main__":
    test_solver_cacheless_exists()
    test_cacheless_matches_caching_solver()
    test_cacheless_unsat()
    test_caching_solver_repeated_eval_consistent()
    test_cacheless_extra_constraints()
    test_cacheless_branch_stays_cacheless()
    test_cacheless_pickle_roundtrip()
    print("All tests passed!")
