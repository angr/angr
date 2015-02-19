import angr
import nose

def test_xpl():
    p = angr.Project("blob/x86_64/all")
    a = p.surveyors.Explorer(p, find=0x600cd0)
    b = p.surveyors.Explorer(p, find=0x400560)

    a.run()
    b.run()

    nose.tools.assert_equal(len(a.found), 4)
    nose.tools.assert_equal(len(b.found), 4)


if __name__ == '__main__':
    test_xpl()
