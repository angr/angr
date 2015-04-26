import angr
import nose
import os

location = str(os.path.dirname(os.path.realpath(__file__)))

def test_xpl():
    p = angr.Project(os.path.join(location, "blob/x86_64/all"))
    pltaddr = p.main_binary.get_call_stub_addr("printf")

    nose.tools.assert_equal(pltaddr, 0x400560)
    a = angr.surveyors.Explorer(p, find=(0x400560,), num_find=4)
    a.run()
    nose.tools.assert_equal(len(a.found), 4)


if __name__ == '__main__':
    test_xpl()
