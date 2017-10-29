import nose
import angr

import os
location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_looplimiter():
    p = angr.Project(os.path.join(location, "x86_64/test_loops"))
    pg = p.factory.simgr()
    tech = angr.exploration_techniques.LoopLimiter(count = 5)
    pg.use_technique(tech) 
    pg.explore()
    nose.tools.assert_equal(len(pg.stashes['spinning']), 1)

if __name__ == '__main__':
    test_looplimiter()
