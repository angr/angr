import angr
import networkx

import os
location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_kb_plugins():
    p = angr.Project(os.path.join(location, 'x86_64', 'fauxware'))

    assert isinstance(p.kb.data, angr.knowledge_plugins.Data)
    assert isinstance(p.kb.functions, angr.knowledge_plugins.FunctionManager)
    assert isinstance(p.kb.variables, angr.knowledge_plugins.VariableManager)
    assert isinstance(p.kb.labels, angr.knowledge_plugins.Labels)
    assert isinstance(p.kb.comments, angr.knowledge_plugins.Comments)

    assert isinstance(p.kb.callgraph, networkx.Graph)
    assert isinstance(p.kb.resolved_indirect_jumps, dict)
    assert isinstance(p.kb.unresolved_indirect_jumps, set)

    assert dir(p.kb) is not None
    for plugin in ['data', 'functions', 'variables', 'labels', 'comments', 'callgraph', 'resolved_indirect_jumps', 'unresolved_indirect_jumps']:
        assert plugin in dir(p.kb)


if __name__ == '__main__':
    test_kb_plugins()
