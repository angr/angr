import os
import unittest

from angr.project import Project


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestCfgManager(unittest.TestCase):
    def test_cfg_manager_copies_cfg_graphs(self):
        binary_path = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests", "x86_64", "all"
        )
        project = Project(binary_path, auto_load_libs=False)
        _ = project.analyses.CFGFast()

        original_cfgs = project.kb.cfgs
        new_cfgs = project.kb.cfgs.copy()

        original_graph = original_cfgs.cfgs["CFGFast"].graph
        new_graph = new_cfgs.cfgs["CFGFast"].graph

        assert original_graph.edges() == new_graph.edges()
        assert original_graph.nodes() == new_graph.nodes()
        assert original_graph is not new_graph


if __name__ == "__main__":
    unittest.main()
