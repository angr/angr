import nose
import angr
import subprocess
import sys

import logging
l = logging.getLogger('angr.tests.strtol')

import os
test_location = str(os.path.dirname(os.path.realpath(__file__)))


def run_strtol(threads):
    if not sys.platform.startswith('linux'):
        raise nose.SkipTest()

    test_bin = os.path.join(test_location, "../../binaries/tests/x86_64/strtol_test")
    b = angr.Project(test_bin)

    initial_state = b.factory.entry_state(remove_options={angr.options.LAZY_SOLVES})
    pg = b.factory.simgr(thing=initial_state, immutable=False, threads=threads)

    # find the end of main
    expected_outputs = {"base 8 worked\n", "base +8 worked\n", "0x worked\n", "+0x worked\n", "base +10 worked\n",
                        "base 10 worked\n", "base -8 worked\n", "-0x worked\n", "base -10 worked\n", "Nope\n"}
    pg.explore(find=0x400804, num_find=len(expected_outputs))
    nose.tools.assert_equal(len(pg.found), len(expected_outputs))

    # check the outputs
    pipe = subprocess.PIPE
    for f in pg.found:
        test_input = f.posix.dumps(0)
        test_output = f.posix.dumps(1)
        expected_outputs.remove(test_output)

        # check the output works as expected
        p = subprocess.Popen(test_bin, stdout=pipe, stderr=pipe, stdin=pipe)
        ret = p.communicate(test_input)[0]
        nose.tools.assert_equal(ret, test_output)

    # check that all of the outputs were seen
    nose.tools.assert_equal(len(expected_outputs), 0)

def test_strtol():
    yield run_strtol, None
    # yield run_strtol, 8

if __name__ == "__main__":
    run_strtol(4)
