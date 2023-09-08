#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long

import os
import unittest

import angr


location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


class TestKbPluginsDwarf(unittest.TestCase):
    def test_kb_plugins_dwarf(self):
        p = angr.Project(
            os.path.join(location, "x86_64", "state_merge_0"),
            load_options={
                "load_debug_info": True,
                "auto_load_libs": False,
            },
        )
        assert isinstance(p.kb.variables, angr.knowledge_plugins.VariableManager)
        p.kb.variables.load_from_dwarf()

        ret = p.kb.variables.global_manager.get_global_variables(6295620)
        assert len(ret) == 1

        v = ret.pop()
        assert v.name == "buf"


if __name__ == "__main__":
    unittest.main()
