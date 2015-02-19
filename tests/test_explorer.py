import angr
import nose

def test_xpl():
    p = angr.Project("blob/x86_64/all")
    pltaddr = p.main_binary.get_plt_stub_addr("printf")

    nose.tools.assert_equal(pltaddr, 0x400560)
    a = angr.surveyors.Explorer(p, find=(0x400560,), num_find=4)
    a.run()
    nose.tools.assert_equal(len(a.found), 4)


if __name__ == '__main__':
    test_xpl()
