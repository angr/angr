import os
import nose
import logging

import angr
import tracer


l = logging.getLogger("angr.exploration_techniques.driller").setLevel('DEBUG')


bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))


def test_drilling_cgc():
    """
    Test drilling on the cgc binary, palindrome.
    """

    binary = os.path.join(bin_location, "tests/cgc/sc1_0b32aa01_01")
    input_str = 'AAAA'

    # Initialize the tracer.
    r = tracer.qemu_runner.QEMURunner(binary, input_str)
    p = angr.misc.tracer.make_tracer_project(binary)
    s = p.factory.tracer_state(input_content=input_str, magic_content=r.magic)

    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)

    t = angr.exploration_techniques.Tracer(trace=r.trace)
    c = angr.exploration_techniques.CrashMonitor(trace=r.trace, crash_mode=r.crash_mode, crash_addr=r.crash_addr)
    d = angr.exploration_techniques.DrillerCore(r.trace)

    simgr.use_technique(c)
    simgr.use_technique(t)
    simgr.use_technique(angr.exploration_techniques.Oppologist())
    simgr.use_technique(d)

    simgr.run()

    nose.tools.assert_true('diverted' in simgr.stashes)


def test_simproc_drilling():
    """
    Test drilling on the cgc binary palindrome with simprocedures.
    """

    binary = os.path.join(bin_location, "tests/i386/driller_simproc")
    memcmp = angr.SIM_PROCEDURES['libc']['memcmp']()
    simprocs = {0x8048200: memcmp}
    input_str = 'A' * 0x80

    # Initialize the tracer.
    r = tracer.qemu_runner.QEMURunner(binary, input_str)
    p = angr.misc.tracer.make_tracer_project(binary, hooks=simprocs)
    s = p.factory.tracer_state(input_content=input_str, magic_content=r.magic)

    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)

    t = angr.exploration_techniques.Tracer(trace=r.trace)
    c = angr.exploration_techniques.CrashMonitor(trace=r.trace, crash_mode=r.crash_mode, crash_addr=r.crash_addr)
    d = angr.exploration_techniques.DrillerCore(r.trace)

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
    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
