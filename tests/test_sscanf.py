import nose
import angr
import subprocess
import sys

import logging
l = logging.getLogger('angr.tests.sscanf')

import os
test_location = str(os.path.dirname(os.path.realpath(__file__)))


def run_sscanf(threads):
    if not sys.platform.startswith('linux'):
        raise nose.SkipTest()

    test_bin = os.path.join(test_location, "../../binaries/tests/x86_64/sscanf_test")
    b = angr.Project(test_bin)

    pg = b.factory.simgr(immutable=False, threads=threads)

    # find the end of main
    expected_outputs = {
        "0x worked\n", "+0x worked\n", "base +16 worked\n", "base 16 worked\n",
        "-0x worked\n", "base -16 worked\n", "Nope x\n",
        "base 8 worked\n", "base +8 worked\n", "base +10 worked\n", "base 10 worked\n",
        "base -8 worked\n", "base -10 worked\n", "Nope u\n",
        "No switch\n",
    }
    pg.explore(find=0x400939, num_find=len(expected_outputs))
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

def test_sscanf():
    yield run_sscanf, None
    # yield run_sscanf, 8

if __name__ == "__main__":
    run_sscanf(4)
