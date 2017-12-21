import nose
import angr

import logging
l = logging.getLogger("angr_tests.managers")

import os
location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_cacher():
    p = angr.Project(os.path.join(location, 'x86_64', 'fauxware'), load_options={'auto_load_libs': False})

    pg = p.factory.simgr(immutable=False)
    pg.use_technique(angr.exploration_techniques.Cacher(when=0x4006ee))
    pg.run()

    pg2 = p.factory.simgr(immutable=False)
    pg2.use_technique(angr.exploration_techniques.Cacher())
    nose.tools.assert_equal(pg2.active[0].addr, 0x4006ed)

    pg2.run()

    nose.tools.assert_equal(len(pg2.deadended), len(pg.deadended))
    nose.tools.assert_true(pg2.deadended[0].addr in [s.addr for s in pg.deadended])
    nose.tools.assert_true(pg2.deadended[1].addr in [s.addr for s in pg.deadended])
    nose.tools.assert_true(pg2.deadended[2].addr in [s.addr for s in pg.deadended])

if __name__ == "__main__":
    test_cacher()
