import angr
import nose

def test_registration():
    s = angr.SimState(arch='AMD64')

    a1 = s.solver.BVS('a', 64, key=(1,), eternal=True)
    a2 = s.solver.BVS('a', 64, key=(1,), eternal=True)
    nose.tools.assert_is(a1, a2)

    b1 = s.solver.BVS('b', 64, key=(2,), eternal=False)
    s1 = s.copy()
    s2 = s.copy()

    b2 = s1.solver.BVS('b', 64, key=(2,), eternal=False)
    b3 = s2.solver.BVS('b', 64, key=(2,), eternal=False)
    nose.tools.assert_is_not(b1, b2)
    nose.tools.assert_is_not(b2, b3)
    nose.tools.assert_is_not(b1, b3)

    a3 = s1.solver.BVS('a', 64, key=(1,), eternal=True)
    a4 = s2.solver.BVS('a', 64, key=(1,), eternal=True)
    nose.tools.assert_is(a2, a3)
    nose.tools.assert_is(a3, a4)

    nose.tools.assert_equal(len(list(s.solver.get_variables(1))), 1)
    nose.tools.assert_equal(len(list(s1.solver.get_variables(1))), 1)
    nose.tools.assert_equal(len(list(s2.solver.get_variables(1))), 1)

    nose.tools.assert_equal(len(list(s.solver.get_variables(2))), 1)
    nose.tools.assert_equal(len(list(s1.solver.get_variables(2))), 2)
    nose.tools.assert_equal(len(list(s2.solver.get_variables(2))), 2)

    nose.tools.assert_equal(list(s.solver.describe_variables(a1)), [(1,)])
    nose.tools.assert_equal(list(s.solver.describe_variables(b1)), [(2, 1)])
    nose.tools.assert_equal(sorted(list(s.solver.describe_variables(a1 + b1))), [(1,), (2, 1)])
