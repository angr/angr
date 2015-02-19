import angr
import nose

def test_xpl():
    p = angr.Project("blob/x86_64/all")
    b = angr.surveyors.Explorer(p, find=(0x600cd0,), num_find=4)
    a = angr.surveyors.Explorer(p, find=(0x400560,), num_find=4)

    a.run()
    b.run()

    nose.tools.assert_equal(len(a.found), 4)
    nose.tools.assert_equal(len(b.found), 4)


if __name__ == '__main__':
    test_xpl()
