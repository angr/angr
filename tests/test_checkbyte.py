import logging
import unittest

import angr

l = logging.getLogger("angr.tests")

import os

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


# TODO: arches += ( "armhf", )


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestCheckbyte(unittest.TestCase):
    def _run_checkbyte(self, arch):
        p = angr.Project(os.path.join(test_location, arch, "checkbyte"), auto_load_libs=False)
        results = p.factory.simulation_manager().run(n=100)  # , until=lambda lpg: len(lpg.active) > 1)

        assert len(results.deadended) == 2
        one = results.deadended[0].posix.dumps(1)
        two = results.deadended[1].posix.dumps(1)
        assert {one, two} == {b"First letter good\n", b"First letter bad\n"}

    def test_checkbyte_armel(self):
        self._run_checkbyte("armel")

    def test_checkbyte_i386(self):
        self._run_checkbyte("i386")

    def test_checkbyte_mips(self):
        self._run_checkbyte("mips")

    def test_checkbyte_mipsel(self):
        self._run_checkbyte("mipsel")

    def test_checkbyte_ppc64(self):
        self._run_checkbyte("ppc64")

    def test_checkbyte_ppc(self):
        self._run_checkbyte("ppc")

    def test_checkbyte_x86_64(self):
        self._run_checkbyte("x86_64")


if __name__ == "__main__":
    unittest.main()
