import nose
import angr
import networkx

import os
location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))


def test_kb_plugins():
    p = angr.Project(location + "/x86_64/fauxware")

    nose.tools.assert_is_instance(p.kb.data, angr.knowledge_plugins.Data)
    nose.tools.assert_is_instance(p.kb.functions, angr.knowledge_plugins.FunctionManager)
    nose.tools.assert_is_instance(p.kb.variables, angr.knowledge_plugins.VariableManager)
    nose.tools.assert_is_instance(p.kb.labels, angr.knowledge_plugins.Labels)
    nose.tools.assert_is_instance(p.kb.comments, angr.knowledge_plugins.Comments)

    nose.tools.assert_is_instance(p.kb.callgraph, networkx.Graph)
    nose.tools.assert_is_instance(p.kb.resolved_indirect_jumps, set)
    nose.tools.assert_is_instance(p.kb.unresolved_indirect_jumps, set)


if __name__ == '__main__':
    test_kb_plugins()
