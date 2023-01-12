import logging
import os
import unittest

import angr

l = logging.getLogger("angr.tests")

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


class TestRelro(unittest.TestCase):
    def _run_fauxware_relro(self, arch):
        p = angr.Project(os.path.join(test_location, arch, "fauxware"), use_sim_procedures=False)
        s = p.factory.full_init_state(add_options={angr.options.STRICT_PAGE_ACCESS})

        relro_segment = next((s for s in p.loader.main_object.segments if s.relro), None)
        if relro_segment is None:
            # No relro on this arch
            return

        assert not relro_segment.is_writable, "The RELRO segment should not be writable"

        try:
            s.memory.store(relro_segment.min_addr, b"\x42")
            assert False, "The RELRO segment should not be writable"
        except angr.errors.SimSegfaultException:
            pass

    def test_fauxware_i386(self):
        self._run_fauxware_relro("i386")

    def test_fauxware_x86_64(self):
        self._run_fauxware_relro("x86_64")

    def test_fauxware_ppc(self):
        self._run_fauxware_relro("ppc")

    def test_fauxware_armel(self):
        self._run_fauxware_relro("armel")

    def test_fauxware_mips(self):
        self._run_fauxware_relro("mips")


if __name__ == "__main__":
    unittest.main()
