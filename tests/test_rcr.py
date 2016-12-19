import nose
import os
import claripy
import angr

def test_rcr():
    p = angr.Project(os.path.join(os.path.dirname(__file__), '../../binaries/tests/i386/rcr_test'))
    path = p.factory.path()
    path.step()
    nose.tools.assert_true(claripy.is_true(path.successors[0].state.regs.cl == 8))

if __name__ == '__main__':
    test_rcr()
