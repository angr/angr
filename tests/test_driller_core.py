import os
import sys
import logging

import angr
import nose

from common import bin_location, do_trace


def test_cgc():
    binary = os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01")
    input_str = 'AAAA'

    # Initialize the tracer.
    p = angr.Project(binary)
    trace, magic, crash_mode, crash_addr = do_trace(p, 'driller_core_cgc', input_str)

    p.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])
    s = p.factory.tracer_state(input_content=input_str, magic_content=magic)

    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=crash_mode)

    t = angr.exploration_techniques.Tracer(trace=trace)
    c = angr.exploration_techniques.CrashMonitor(trace=trace, crash_mode=crash_mode, crash_addr=crash_addr)
    d = angr.exploration_techniques.DrillerCore(trace)

    simgr.use_technique(c)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())
    simgr.use_technique(d)

    simgr.run()

    nose.tools.assert_true('diverted' in simgr.stashes)


def test_simprocs():
    binary = os.path.join(bin_location, "tests/i386/driller_simproc")
    memcmp = angr.SIM_PROCEDURES['libc']['memcmp']()
    input_str = 'A' * 0x80

    p = angr.Project(binary)
    trace, magic, crash_mode, crash_addr = do_trace(p, 'driller_core_simprocs', input_str)

    p.hook(0x8048200, memcmp)
    p.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])
    s = p.factory.tracer_state(input_content=input_str, magic_content=magic)

    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=crash_mode)

    t = angr.exploration_techniques.Tracer(trace=trace)
    c = angr.exploration_techniques.CrashMonitor(trace=trace, crash_mode=crash_mode, crash_addr=crash_addr)
    d = angr.exploration_techniques.DrillerCore(trace)

    simgr.use_technique(c)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())
    simgr.use_technique(d)

    simgr.run()

    nose.tools.assert_true('diverted' in simgr.stashes)


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()


if __name__ == "__main__":
    logging.getLogger("angr.exploration_techniques.driller_core").setLevel('DEBUG')
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
