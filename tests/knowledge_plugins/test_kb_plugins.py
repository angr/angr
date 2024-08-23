#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins"  # pylint:disable=redefined-builtin

import os
import unittest

import networkx

import angr

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestKbPlugins(unittest.TestCase):
    def test_kb_plugins(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)

        assert isinstance(p.kb.data, angr.knowledge_plugins.Data)
        assert isinstance(p.kb.functions, angr.knowledge_plugins.FunctionManager)
        assert isinstance(p.kb.variables, angr.knowledge_plugins.VariableManager)
        assert isinstance(p.kb.labels, angr.knowledge_plugins.Labels)
        assert isinstance(p.kb.comments, angr.knowledge_plugins.Comments)

        assert isinstance(p.kb.callgraph, networkx.Graph)
        assert isinstance(p.kb.resolved_indirect_jumps, dict)
        assert isinstance(p.kb.unresolved_indirect_jumps, set)

        assert dir(p.kb) is not None
        for plugin in [
            "data",
            "functions",
            "variables",
            "labels",
            "comments",
            "callgraph",
            "resolved_indirect_jumps",
            "unresolved_indirect_jumps",
        ]:
            assert plugin in dir(p.kb)

    def test_kb_plugins_typed(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)

        for plugin in [
            angr.knowledge_plugins.Data,
            angr.knowledge_plugins.FunctionManager,
            angr.knowledge_plugins.VariableManager,
            angr.knowledge_plugins.Labels,
            angr.knowledge_plugins.Comments,
        ]:
            assert p.kb.get_knowledge(plugin) is None

        for plugin in [
            angr.knowledge_plugins.Data,
            angr.knowledge_plugins.FunctionManager,
            angr.knowledge_plugins.VariableManager,
            angr.knowledge_plugins.Labels,
            angr.knowledge_plugins.Comments,
        ]:
            assert isinstance(p.kb.request_knowledge(plugin), plugin)

        # The default plugins should have been instantiated by `request_knowledge`, and should now be available
        for plugin in [
            angr.knowledge_plugins.Data,
            angr.knowledge_plugins.FunctionManager,
            angr.knowledge_plugins.VariableManager,
            angr.knowledge_plugins.Labels,
            angr.knowledge_plugins.Comments,
        ]:
            assert isinstance(p.kb.request_knowledge(plugin), plugin)

        # Check that explicitly creating and registering new kind of plugin also works
        class TestPlugin(angr.knowledge_plugins.KnowledgeBasePlugin):
            pass

        # Assert that unknown plugins return None when using "get_knowledge"
        assert p.kb.get_knowledge(TestPlugin) is None

        t = TestPlugin(p.kb)
        p.kb.register_plugin("test_plugin", t)

        assert p.kb.get_knowledge(TestPlugin) == t


if __name__ == "__main__":
    unittest.main()
