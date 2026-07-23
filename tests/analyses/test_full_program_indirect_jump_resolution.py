#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestFullProgramIndirectJumpResolution(unittest.TestCase):
    @staticmethod
    def _run(binary_name):
        binary_path = os.path.join(test_location, "x86_64", binary_name)
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions()
        fpijr = proj.analyses.FullProgramIndirectJumpResolution()
        return proj, cfg, fpijr

    @staticmethod
    def _union_of_resolutions(fpijr, func):
        """Return the union of all resolved target sets inside the given function,
        asserting there is at least one resolved site."""
        resolutions = fpijr.get_resolutions(func)
        assert resolutions, f"No resolved indirect jump/call sites in function {func.name}"
        targets: set[int] = set()
        for target_set in resolutions.values():
            targets |= target_set
        return targets

    def test_global_table(self):
        _, cfg, fpijr = self._run("fpijr_global_table")
        dispatch = cfg.kb.functions["dispatch"]
        expected = {cfg.kb.functions[name].addr for name in ("f0", "f1", "f2", "f3")}
        targets = self._union_of_resolutions(fpijr, dispatch)
        assert targets == expected

    def test_struct_array(self):
        _, cfg, fpijr = self._run("fpijr_struct_array")
        dispatch = cfg.kb.functions["dispatch"]
        expected = {cfg.kb.functions[name].addr for name in ("e0", "e1", "e2")}
        targets = self._union_of_resolutions(fpijr, dispatch)
        assert targets == expected

    def test_interproc(self):
        _, cfg, fpijr = self._run("fpijr_interproc")
        run_ops = cfg.kb.functions["run_ops"]
        expected = {cfg.kb.functions[name].addr for name in ("h1", "h2")}
        targets = self._union_of_resolutions(fpijr, run_ops)
        assert targets == expected

    def test_local_cond(self):
        _, cfg, fpijr = self._run("fpijr_local_cond")
        dispatch = cfg.kb.functions["dispatch"]
        expected = {cfg.kb.functions[name].addr for name in ("h1", "h2")}
        targets = self._union_of_resolutions(fpijr, dispatch)
        assert targets == expected


if __name__ == "__main__":
    unittest.main()
