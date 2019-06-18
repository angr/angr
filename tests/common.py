import os
import pickle

from nose.plugins.attrib import attr

try:
    import tracer
except ImportError:
    tracer = None

bin_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries')
if not os.path.isdir(bin_location):
    raise Exception("Can't find the angr/binaries repo for holding testcases. It should be cloned into the same folder as the rest of your angr modules.")

slow_test = attr(speed='slow')

TRACE_VERSION = 1

def do_trace(proj, test_name, input_data, **kwargs):
    """
    trace, magic, crash_mode, crash_addr = load_cached_trace(proj, "test_blurble")
    """
    fname = os.path.join(bin_location, 'tests_data', 'runner_traces', '%s_%s_%s.p' % (test_name, os.path.basename(proj.filename), proj.arch.name))

    if os.path.isfile(fname):
        try:
            with open(fname, 'rb') as f:
                r = pickle.load(f)
                if type(r) is tuple and len(r) == 2 and r[1] == TRACE_VERSION:
                    return r[0]
        except (pickle.UnpicklingError, UnicodeDecodeError):
            print("Can't unpickle trace - rerunning")

    if tracer is None:
        raise Exception("Tracer is not installed and cached data is not present - cannot run test")

    runner = tracer.QEMURunner(project=proj, input=input_data, **kwargs)
    r = (runner.trace, runner.magic, runner.crash_mode, runner.crash_addr)
    with open(fname, 'wb') as f:
        pickle.dump((r, TRACE_VERSION), f, -1)
    return r
