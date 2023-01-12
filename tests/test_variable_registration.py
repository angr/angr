import angr


def test_registration():
    s = angr.SimState(arch="AMD64")

    a1 = s.solver.BVS("a", 64, key=(1,), eternal=True)
    a2 = s.solver.BVS("a", 64, key=(1,), eternal=True)
    assert a1 is a2

    b1 = s.solver.BVS("b", 64, key=(2,), eternal=False)
    s1 = s.copy()
    s2 = s.copy()

    b2 = s1.solver.BVS("b", 64, key=(2,), eternal=False)
    b3 = s2.solver.BVS("b", 64, key=(2,), eternal=False)
    assert b1 is not b2
    assert b2 is not b3
    assert b1 is not b3

    a3 = s1.solver.BVS("a", 64, key=(1,), eternal=True)
    a4 = s2.solver.BVS("a", 64, key=(1,), eternal=True)
    assert a2 is a3
    assert a3 is a4

    assert len(list(s.solver.get_variables(1))) == 1
    assert len(list(s1.solver.get_variables(1))) == 1
    assert len(list(s2.solver.get_variables(1))) == 1

    assert len(list(s.solver.get_variables(2))) == 1
    assert len(list(s1.solver.get_variables(2))) == 2
    assert len(list(s2.solver.get_variables(2))) == 2

    assert list(s.solver.describe_variables(a1)) == [(1,)]
    assert list(s.solver.describe_variables(b1)) == [(2, 1)]
    assert sorted(list(s.solver.describe_variables(a1 + b1))) == [(1,), (2, 1)]
