import os

import nose

from angr.project import Project


def test_cfg_manager_copies_cfg_graphs():
    binary_path = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        '..', '..', 'binaries', 'tests', 'x86_64',
        'all'
    )
    project = Project(binary_path, auto_load_libs=False)
    _ = project.analyses.CFGFast()

    original_cfgs = project.kb.cfgs
    new_cfgs = project.kb.cfgs.copy()

    original_graph = original_cfgs.cfgs['CFGFast'].graph
    new_graph = new_cfgs.cfgs['CFGFast'].graph

    nose.tools.assert_equals(original_graph.edges(), new_graph.edges())
    nose.tools.assert_equals(original_graph.nodes(), new_graph.nodes())
    nose.tools.assert_false(original_graph is new_graph)
