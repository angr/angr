import os
import pickle
import sys

from unittest import skipIf, skipUnless, skip

try:
    import tracer
except ImportError:
    tracer = None

bin_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries')
bin_priv_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries-private')

if not os.path.isdir(bin_location):
    raise Exception(
        "Can't find the angr/binaries repo for holding testcases. It should be cloned into the same folder as the rest of your angr modules."
    )


def broken(func):
    return skip("Broken test method")(func)


def slow_test(func):
    func.slow = True
    slow_test_env = os.environ['SKIP_SLOW_TESTS'].lower() if 'SKIP_SLOW_TESTS' in os.environ else str()
    return skipIf(slow_test_env == "true" or slow_test_env == "1", 'Skipping slow test')(func)


def skip_if_not_linux(func):
    return skipUnless(sys.platform.startswith("linux"), "Skipping Linux Test Cases")(func)


TRACE_VERSION = 1


def do_trace(proj, test_name, input_data, **kwargs):
    """
    trace, magic, crash_mode, crash_addr = load_cached_trace(proj, "test_blurble")
    """
    fname = os.path.join(bin_location, 'tests_data', 'runner_traces',
                         '%s_%s_%s.p' % (test_name, os.path.basename(proj.filename), proj.arch.name))

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


def load_cgc_pov(pov_file: str) -> "tracer.TracerPoV":
    if tracer is None:
        raise Exception("Cannot load PoV because tracer is not installed")

    return tracer.TracerPoV(pov_file)
