import os
import sys
import logging

import angr
import nose

from common import bin_location
from test_tracer import tracer_cgc

def test_cgc():
    binary = os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01")
    simgr, tracer = tracer_cgc(binary, 'driller_core_cgc', b'AAAA')
    simgr.use_technique(angr.exploration_techniques.DrillerCore(tracer._trace))
    simgr.run()

    nose.tools.assert_true('diverted' in simgr.stashes)
    nose.tools.assert_equal(len(simgr.diverted), 3)

def test_simprocs():
    binary = os.path.join(bin_location, "tests/i386/driller_simproc")
    memcmp = angr.SIM_PROCEDURES['libc']['memcmp']()

    simgr, tracer = tracer_cgc(binary, 'driller_core_simprocs', b'A'*128)
    p = simgr._project
    p.hook(0x8048200, memcmp)

    d = angr.exploration_techniques.DrillerCore(tracer._trace)
    simgr.use_technique(d)

    simgr.run()
    nose.tools.assert_in('diverted', simgr.stashes)
    nose.tools.assert_greater(len(simgr.diverted), 0)


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()


if __name__ == "__main__":
    logging.getLogger("angr.exploration_techniques.driller_core").setLevel('DEBUG')
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
