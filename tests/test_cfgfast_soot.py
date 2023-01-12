import os
import unittest

import angr

try:
    import pysoot
except ModuleNotFoundError:
    pysoot = None

test_location = os.path.join(os.path.dirname(os.path.realpath(str(__file__))), "..", "..", "binaries", "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
@unittest.skipUnless(pysoot, "pysoot not available")
class TestCfgfastSoot(unittest.TestCase):
    def test_simple1(self):
        binary_path = os.path.join(test_location, "java", "simple1.jar")
        p = angr.Project(binary_path, main_opts={"entry_point": "simple1.Class1.main"}, auto_load_libs=False)
        cfg = p.analyses.CFGFastSoot()
        assert cfg.graph.nodes()

    def test_simple2(self):
        binary_path = os.path.join(test_location, "java", "simple2.jar")
        p = angr.Project(binary_path, main_opts={"entry_point": "simple2.Class1.main"}, auto_load_libs=False)
        cfg = p.analyses.CFGFastSoot()
        assert cfg.graph.nodes()


if __name__ == "__main__":
    unittest.main()
