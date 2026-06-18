import claripy


def test_batch_eval_joint_model():
    # Each tuple must be drawn from a single model: x + y == 10 has to hold for
    # every returned (x, y) pair, which evaluating the expressions independently
    # would not guarantee.
    s = claripy.Solver()
    x = claripy.BVS("x", 8)
    y = claripy.BVS("y", 8)
    s.add(x + y == 10)

    results = s.batch_eval([x, y], 50)
    assert results
    assert all(isinstance(t, tuple) and len(t) == 2 for t in results)
    for xv, yv in results:
        assert (xv + yv) % 256 == 10
    # Tuples are distinct.
    assert len(set(results)) == len(results)


def test_batch_eval_mixed_types():
    s = claripy.Solver()
    x = claripy.BVS("x", 8)
    s.add(x == 7)
    flag = claripy.BVS("flag", 8)
    s.add(flag == 1)
    cond = flag == 1  # a Bool expression
    f = claripy.FPS("f", claripy.FSORT_DOUBLE)
    s.add(f == claripy.FPV(2.5, claripy.FSORT_DOUBLE))

    (row,) = s.batch_eval([x, cond, f], 1)
    xv, cv, fv = row
    assert xv == 7
    assert cv is True
    assert fv == 2.5


def test_batch_eval_string():
    s = claripy.Solver()
    st = claripy.StringS("s")
    s.add(st == claripy.StringV("hi"))
    assert s.batch_eval([st], 1) == [("hi",)]


def test_batch_eval_empty():
    s = claripy.Solver()
    assert s.batch_eval([], 5) == []
