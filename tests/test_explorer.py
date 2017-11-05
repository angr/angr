import nose
import angr

import os
location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_xpl():
    p = angr.Project(os.path.join(location, "x86_64/all"))
    pltaddr = p.loader.main_object.plt["printf"]

    nose.tools.assert_equal(pltaddr, 0x400560)
    a = p.surveyors.Explorer(find=(0x400560,), num_find=4)
    a.run()
    nose.tools.assert_equal(len(a.found), 4)

if __name__ == '__main__':
    test_xpl()
