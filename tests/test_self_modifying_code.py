import angr
from simuvex import o
import claripy
import nose
import os

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_self_modifying_code():
    p = angr.Project(os.path.join(test_location, 'i386/stuff'))
    pg = p.factory.path_group(p.factory.entry_state(add_options={o.STRICT_PAGE_ACCESS}))
    pg.step(until=lambda lpg: len(lpg.active) != 1)
    retval = pg.one_deadended.state.regs.ebx
    nose.tools.assert_true(claripy.is_true(retval == 65))

if __name__ == '__main__':
    test_self_modifying_code()
