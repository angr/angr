import nose
import angr
import subprocess
import sys

import logging
l = logging.getLogger('angr.tests.test_signed_div')

import os
test_location = str(os.path.dirname(os.path.realpath(__file__)))


def test_signed_div():
    if not sys.platform.startswith('linux'):
        raise nose.SkipTest()   # this is not technically required, the run result could just be inlined
    test_bin = os.path.join(test_location, "../../binaries/tests/x86_64/test_signed_div")
    b = angr.Project(test_bin)

    pg = b.factory.simgr()
    pg.explore()
    out_angr = pg.deadended[0].posix.dumps(1)
    proc = subprocess.Popen(test_bin, stdout=subprocess.PIPE)
    stdout_real, _ = proc.communicate()

    nose.tools.assert_equal(out_angr, stdout_real)

if __name__ == "__main__":
    test_signed_div()
