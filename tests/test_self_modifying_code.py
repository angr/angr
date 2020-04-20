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

    # small issue: the program is bugged and uses illegal stack allocation patterns, bypassing the red page
    # hack around this here
    for offs in range(0, 0x6000, 0x1000):
        pg.one_active.memory.load(pg.one_active.regs.sp - offs, size=1)

    pg.run(until=lambda lpg: len(lpg.active) != 1)
    retval = pg.one_deadended.regs.ebx
    nose.tools.assert_true(claripy.is_true(retval == 65))

    pgu = p.factory.simulation_manager(p.factory.entry_state(add_options={o.STRICT_PAGE_ACCESS} | o.unicorn))
    pgu.run(until=lambda lpg: len(lpg.active) != 1)
    retval = pgu.one_deadended.regs.ebx
    nose.tools.assert_true(claripy.is_true(retval == 65))

    nose.tools.assert_true(pg.one_deadended.history.bbl_addrs.hardcopy == pgu.one_deadended.history.bbl_addrs.hardcopy)


if __name__ == '__main__':
    test_self_modifying_code()
