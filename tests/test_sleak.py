import angr
import os
import nose

def test_xpl(p):
    a = p.analyses.XSleak(num_leaks=3)
    a.run()
    nose.tools.assert_equal(len(a.leaks), 3)

def test_slice(p):
    a = p.analyses.Sleakslice()
    a.run()
    nose.tools.assert_equal(len(a.leaks), 3)

if __name__ == '__main__':

    test_location = str(os.path.dirname(os.path.realpath(__file__)))
    bin64 = os.path.join(test_location, "blob/x86_64/all")
    bin32 = os.path.join(test_location, "blob/i386/all")

    p32 = angr.Project(bin64)
    p64 = angr.Project(bin32)

    test_xpl(p64)
    test_xpl(p32)
    test_slice(p64)
    test_slice(p32)
