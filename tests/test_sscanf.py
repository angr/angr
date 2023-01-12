import angr
import subprocess
import sys

import unittest

import logging

l = logging.getLogger("angr.tests.sscanf")

import os

test_location = os.path.dirname(os.path.realpath(__file__))


class TestSscanf(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "linux only")
    def test_sscanf(self):
        test_bin = os.path.join(test_location, "..", "..", "binaries", "tests", "x86_64", "sscanf_test")
        b = angr.Project(test_bin, auto_load_libs=False)
        pg = b.factory.simulation_manager()
        # find the end of main
        expected_outputs = {
            b"0x worked\n",
            b"+0x worked\n",
            b"base +16 worked\n",
            b"base 16 worked\n",
            b"-0x worked\n",
            b"base -16 worked\n",
            b"base 16 length 2 worked\n",
            b"Nope x\n",
            b"base 8 worked\n",
            b"base +8 worked\n",
            b"base +10 worked\n",
            b"base 10 worked\n",
            b"base -8 worked\n",
            b"base -10 worked\n",
            b"Nope u\n",
            b"No switch\n",
        }
        pg.run()
        assert len(pg.deadended) == len(expected_outputs)
        assert len(pg.active) == 0
        assert len(pg.errored) == 0

        # check the outputs
        pipe = subprocess.PIPE
        for f in pg.deadended:
            test_input = f.posix.dumps(0)
            test_output = f.posix.dumps(1)
            expected_outputs.remove(test_output)

            # check the output works as expected
            p = subprocess.Popen(test_bin, stdout=pipe, stderr=pipe, stdin=pipe)
            ret = p.communicate(test_input)[0]
            assert ret == test_output

        # check that all of the outputs were seen
        assert len(expected_outputs) == 0


if __name__ == "__main__":
    unittest.main()
