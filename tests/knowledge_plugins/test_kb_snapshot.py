#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

import os
import unittest

import angr
from angr.knowledge_base import KnowledgeBaseSnapshot
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestKnowledgeBaseSnapshot(unittest.TestCase):
    def test_restore_rolls_back_a_decompilation(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        func = proj.kb.functions["authenticate"]
        proj.kb.variables.get_function_manager(func.addr)
        proj.kb.comments[func.addr] = "kept"
        assert func.prototype is None

        snapshot = KnowledgeBaseSnapshot(proj.kb)
        plugins_before = dict(proj.kb._plugins)  # pylint:disable=protected-access
        variables_before = proj.kb.variables

        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert proj.kb.has_plugin("decompilations") and proj.kb.has_plugin("dec_variables")
        assert func.prototype is not None
        # in-place writes to plugins that are restored by value
        proj.kb.variables.get_function_manager(0x1234)
        proj.kb.comments[func.addr] = "overwritten"
        proj.kb.comments[func.addr + 1] = "new"

        snapshot.restore()

        assert set(proj.kb._plugins) == set(plugins_before)  # pylint:disable=protected-access
        assert func.prototype is None
        assert proj.kb.variables is not variables_before  # a fresh copy, so the snapshot stays pristine
        assert proj.kb.variables.has_function_manager(func.addr)
        assert not proj.kb.variables.has_function_manager(0x1234)
        assert proj.kb.comments[func.addr] == "kept"
        assert func.addr + 1 not in proj.kb.comments
        # plugins kept by reference are the same objects
        assert proj.kb.functions is plugins_before["functions"]
        assert proj.kb.cfgs is plugins_before["cfgs"]

        # the second run starts from the same state, so it reproduces the first run
        dec2 = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec2.codegen is not None and dec2.codegen.text == dec.codegen.text

        # restoring again is fine and hands out another fresh copy
        variables_after_first_restore = proj.kb.variables
        snapshot.restore()
        assert proj.kb.variables is not variables_after_first_restore
        assert func.prototype is None

    def test_included_plugins_keeps_the_rest_by_reference(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        variables = proj.kb.variables
        comments = proj.kb.comments
        proj.kb.comments[proj.entry] = "kept"

        snapshot = KnowledgeBaseSnapshot(proj.kb, included_plugins=("comments",))
        proj.kb.variables.get_function_manager(0x1234)
        proj.kb.comments[proj.entry] = "overwritten"
        snapshot.restore()

        assert proj.kb.variables is variables
        assert proj.kb.variables.has_function_manager(0x1234)
        assert proj.kb.comments is not comments
        assert proj.kb.comments[proj.entry] == "kept"


if __name__ == "__main__":
    unittest.main()
