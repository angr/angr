import angr
import claripy
import nose
import os

from nose.plugins.attrib import attr
from angr import options as o

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

@attr(speed='slow')
def test_self_modifying_code():
    p = angr.Project(os.path.join(test_location, 'cgc', 'stuff'))
    pg = p.factory.simulation_manager(p.factory.entry_state(add_options={o.STRICT_PAGE_ACCESS}))
    pg.step(until=lambda lpg: len(lpg.active) != 1)
    retval = pg.one_deadended.regs.ebx
    nose.tools.assert_true(claripy.is_true(retval == 65))

    pgu = p.factory.simulation_manager(p.factory.entry_state(add_options={o.STRICT_PAGE_ACCESS} | o.unicorn))
    pgu.step(until=lambda lpg: len(lpg.active) != 1)
    retval = pgu.one_deadended.regs.ebx
    nose.tools.assert_true(claripy.is_true(retval == 65))

    nose.tools.assert_true(pg.one_deadended.history.bbl_addrs.hardcopy == pgu.one_deadended.history.bbl_addrs.hardcopy)


if __name__ == '__main__':
    test_self_modifying_code()
