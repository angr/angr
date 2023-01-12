import angr
import subprocess
import sys

import logging

l = logging.getLogger("angr.tests.test_signed_div")

from unittest import skipUnless

import os

test_location = os.path.dirname(os.path.realpath(__file__))


@skipUnless(sys.platform.startswith("linux"), "linux only")
def test_signed_div():
    test_bin = os.path.join(test_location, "..", "..", "binaries", "tests", "x86_64", "test_signed_div")
    b = angr.Project(test_bin, auto_load_libs=False)

    pg = b.factory.simulation_manager()
    pg.explore()
    out_angr = pg.deadended[0].posix.dumps(1)
    proc = subprocess.Popen(test_bin, stdout=subprocess.PIPE)
    stdout_real, _ = proc.communicate()

    assert out_angr == stdout_real


if __name__ == "__main__":
    test_signed_div()
