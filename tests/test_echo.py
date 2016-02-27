import angr

import logging
l = logging.getLogger("angr.tests")

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

target_arches = {
    #'i386',
    'x86_64',
    #'ppc',
    #'armel',
    #'mips',
}

def run_echo_haha(arch):
    p = angr.Project(os.path.join(test_location, arch, 'echo'), use_sim_procedures=False)
    s = p.factory.full_init_state(mode='symbolic_approximating', args=['echo', 'haha'])
    pg = p.factory.path_group(s)
    pg.step(until=lambda lpg: len(lpg.active) != 1)

    assert len(pg.deadended) == 1
    assert len(pg.active) == 0
    assert pg.deadended[0].state.posix.dumps(1) == 'haha\n'

def test_echo_haha():
    for arch in target_arches:
        yield run_echo_haha, arch

if __name__ == "__main__":
    for r,a in test_echo_haha():
        r(a)
