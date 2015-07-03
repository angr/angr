#!/usr/bin/env python

import nose
import logging
l = logging.getLogger("angr_tests.path_groups")

try:
    # pylint: disable=W0611,F0401
    import standard_logging
    import angr_debug
except ImportError:
    pass


addresses_fauxware = {
    'armel': 0x8524,
    'armhf': 0x104c9,   # addr+1 to force thumb
    #'i386': 0x8048524, # commenting out because of the freaking stack check
    'mips': 0x400710,
    'mipsel': 0x4006d0,
    'ppc': 0x1000054c,
    'ppc64': 0x10000698,
    'x86_64': 0x400664
}

import angr

import os
location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def run_fauxware(arch):
    p = angr.Project(location + '/' + arch + '/fauxware')

    pg = p.path_group()
    nose.tools.assert_equal(len(pg.active), 1)
    nose.tools.assert_equal(len(pg.active[0].backtrace), 0)

    # step until the backdoor split occurs
    pg2 = pg.step(until=lambda lpg: len(lpg.active) > 1, step_func=lambda lpg: lpg.prune())
    nose.tools.assert_equal(len(pg2.active), 2)
    nose.tools.assert_true(any("SOSNEAKY" in s for s in pg2.mp_active.state.posix.dumps(0).mp_items))
    nose.tools.assert_false(all("SOSNEAKY" in s for s in pg2.mp_active.state.posix.dumps(0).mp_items))

    # separate out the backdoor and normal paths
    pg3 = pg2.stash(lambda path: "SOSNEAKY" in path.state.posix.dumps(0), to_stash="backdoor").stash_all(to_stash="auth")
    nose.tools.assert_equal(len(pg3.active), 0)
    nose.tools.assert_equal(len(pg3.backdoor), 1)
    nose.tools.assert_equal(len(pg3.auth), 1)

    # step the backdoor path until it returns to main
    pg4 = pg3.step(until=lambda lpg: lpg.backdoor[0].jumpkinds[-1] == 'Ijk_Ret', stash='backdoor')
    main_addr = pg4.backdoor[0].addr

    nose.tools.assert_equal(len(pg4.active), 0)
    nose.tools.assert_equal(len(pg4.backdoor), 1)
    nose.tools.assert_equal(len(pg4.auth), 1)

    # now step the real path until the real authentication paths return to the same place
    pg5 = pg4.explore(find=main_addr, num_find=2, stash='auth').unstash_all(from_stash='found', to_stash='auth')

    nose.tools.assert_equal(len(pg5.active), 0)
    nose.tools.assert_equal(len(pg5.backdoor), 1)
    nose.tools.assert_equal(len(pg5.auth), 2)

    # now unstash everything
    pg6 = pg5.unstash_all(from_stash='backdoor').unstash_all(from_stash='auth')
    nose.tools.assert_equal(len(pg6.active), 3)
    nose.tools.assert_equal(len(pg6.backdoor), 0)
    nose.tools.assert_equal(len(pg6.auth), 0)

    nose.tools.assert_equal(len(set(pg6.mp_active.addr.mp_items)), 1)

    # now merge them!
    pg7 = pg6.merge()
    nose.tools.assert_equal(len(pg7.active), 1)
    nose.tools.assert_equal(len(pg7.backdoor), 0)
    nose.tools.assert_equal(len(pg7.auth), 0)

    #import ipdb; ipdb.set_trace()
    #print pg2.mp_active.addr.mp_map(hex).mp_items

def test_fauxware():
    for arch in addresses_fauxware:
        yield run_fauxware, arch

if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1:
        for func, march in test_fauxware():
            print 'testing ' + march
            func(march)
    else:
        run_fauxware(sys.argv[1])
