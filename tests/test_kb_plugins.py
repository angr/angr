import nose
import angr
import networkx

import os
location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_kb_plugins():
    p = angr.Project(os.path.join(location, 'x86_64', 'fauxware'))

    nose.tools.assert_is_instance(p.kb.data, angr.knowledge_plugins.Data)
    nose.tools.assert_is_instance(p.kb.functions, angr.knowledge_plugins.FunctionManager)
    nose.tools.assert_is_instance(p.kb.variables, angr.knowledge_plugins.VariableManager)
    nose.tools.assert_is_instance(p.kb.labels, angr.knowledge_plugins.Labels)
    nose.tools.assert_is_instance(p.kb.comments, angr.knowledge_plugins.Comments)

    nose.tools.assert_is_instance(p.kb.callgraph, networkx.Graph)
    nose.tools.assert_is_instance(p.kb.resolved_indirect_jumps, dict)
    nose.tools.assert_is_instance(p.kb.unresolved_indirect_jumps, set)

    nose.tools.assert_is_not_none(dir(p.kb))
    for plugin in ['data', 'functions', 'variables', 'labels', 'comments', 'callgraph', 'resolved_indirect_jumps', 'unresolved_indirect_jumps']:
        nose.tools.assert_in(plugin, dir(p.kb))


if __name__ == '__main__':
    test_kb_plugins()
