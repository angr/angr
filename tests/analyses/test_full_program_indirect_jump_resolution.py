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

    def test_progress_callback(self):
        binary_path = os.path.join(test_location, "x86_64", "fpijr_global_table")
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions()

        updates = []

        def callback(percentage, text=None, **kwargs):
            updates.append((percentage, text, kwargs.get("analysis")))

        fpijr = proj.analyses.FullProgramIndirectJumpResolution(progress_callback=callback)

        # progress must be reported, be monotonically non-decreasing, end at 100%, and expose the running instance
        assert updates
        percentages = [p for p, _, _ in updates]
        assert percentages == sorted(percentages)
        assert percentages[-1] == 100.0
        assert any(inst is fpijr for _, _, inst in updates)

        # low_priority must not change the result
        dispatch = cfg.kb.functions["dispatch"]
        expected = {cfg.kb.functions[name].addr for name in ("f0", "f1", "f2", "f3")}
        assert self._union_of_resolutions(fpijr, dispatch) == expected

    def test_low_priority(self):
        binary_path = os.path.join(test_location, "x86_64", "fpijr_global_table")
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions()

        fpijr = proj.analyses.FullProgramIndirectJumpResolution(low_priority=True)

        dispatch = cfg.kb.functions["dispatch"]
        expected = {cfg.kb.functions[name].addr for name in ("f0", "f1", "f2", "f3")}
        assert self._union_of_resolutions(fpijr, dispatch) == expected

    def test_abort(self):
        binary_path = os.path.join(test_location, "x86_64", "fpijr_global_table")
        proj = angr.Project(binary_path, auto_load_libs=False)
        proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions()

        # abort from within the progress callback (as a host GUI would, via the passed-in analysis instance), after the
        # very first per-function update. The run must stop early yet still finalize a valid resolved_indirect_jumps.
        state = {"instance": None, "aborted_after": None}

        def callback(percentage, text=None, **kwargs):
            inst = kwargs.get("analysis")
            if inst is not None and state["instance"] is None:
                state["instance"] = inst
                inst.abort()
                state["aborted_after"] = percentage

        fpijr = proj.analyses.FullProgramIndirectJumpResolution(progress_callback=callback)

        assert fpijr.should_abort
        assert state["instance"] is fpijr
        # aborting on the first tick means far fewer functions were analyzed than were selected
        assert len(fpijr._func_facts) < len(fpijr._selected_funcs)  # pylint:disable=protected-access
        # partial results must still be a valid dict
        assert isinstance(fpijr.resolved_indirect_jumps, dict)

    def test_abort_before_run_is_idempotent(self):
        _, _, fpijr = self._run("fpijr_global_table")
        # aborting a finished analysis is a harmless no-op and does not invalidate results
        fpijr.abort()
        assert fpijr.should_abort
        assert isinstance(fpijr.resolved_indirect_jumps, dict)


if __name__ == "__main__":
    unittest.main()
