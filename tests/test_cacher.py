import tempfile
import os
import logging
import unittest

from common import broken

import angr

l = logging.getLogger("angr_tests.managers")

location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestCacher(unittest.TestCase):
    @broken
    def test_cacher(self):
        p = angr.Project(os.path.join(location, "x86_64", "fauxware"), load_options={"auto_load_libs": False})

        tmp_dir = tempfile.mkdtemp(prefix="test_cacher_container")
        container = os.path.join(tmp_dir, "%s.cache" % os.path.basename(p.filename))

        pg = p.factory.simulation_manager()
        pg.use_technique(angr.exploration_techniques.Cacher(when=0x4006EE, container=container))
        pg.run()

        pg2 = p.factory.simulation_manager()
        pg2.use_technique(angr.exploration_techniques.Cacher(container=container))
        assert pg2.active[0].addr == 0x4006ED

        pg2.run()

        assert len(pg2.deadended) == len(pg.deadended)
        assert pg2.deadended[0].addr in [s.addr for s in pg.deadended]
        assert pg2.deadended[1].addr in [s.addr for s in pg.deadended]
        assert pg2.deadended[2].addr in [s.addr for s in pg.deadended]


if __name__ == "__main__":
    unittest.main()
