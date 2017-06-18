import angr
import nose
import os

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_adc_i386():
    proj = angr.Project(test_location + "/i386/test_adc", load_options={'auto_load_libs':False})

    start = 0x804840b
    end = 0x804842e

    state = proj.factory.blank_state(addr=start, remove_options={angr.options.LAZY_SOLVES,}, add_options={angr.options.SYMBOLIC_WRITE_ADDRESSES})

    pg = proj.factory.simgr(state, veritesting=False)
    pg.explore(find=end)

    found_state = pg.found[0]
    result = found_state.se.any_int(found_state.regs.eax)
    nose.tools.assert_equal(result, 0x1)

def test_all():
    test_adc_i386()

if __name__ == "__main__":
    test_all()
