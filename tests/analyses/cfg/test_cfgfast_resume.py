#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses.cfg.cfg_base import CFGBase
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

RESUME_ONLY_KWARGS = {
    "start_at_entry": False,
    "symbols": False,
    "function_prologues": False,
    "eh_frame": False,
    "force_smart_scan": False,
    "force_complete_scan": False,
}


def make_abort_callback(after_percentage: float = 0.0):
    """
    Create a progress callback that aborts the CFG recovery at the first notification at or after the given
    percentage.
    """

    def callback(percentage, text=None, cfg=None, **kwargs):  # pylint:disable=unused-argument
        if cfg is not None and percentage >= after_percentage:
            cfg.abort()

    return callback


class TestCfgfastAbortResume(unittest.TestCase):
    def _aborted_cfg(self, proj: angr.Project, after_percentage: float = 0.0, **kwargs):
        cfg = proj.analyses.CFGFast(normalize=True, progress_callback=make_abort_callback(after_percentage), **kwargs)
        assert cfg.should_abort
        return cfg

    def test_abort_from_progress_callback(self):
        path = os.path.join(test_location, "x86_64", "fauxware")

        proj_full = angr.Project(path, auto_load_libs=False)
        cfg_full = proj_full.analyses.CFGFast(normalize=True)
        full_node_count = len(cfg_full.model.graph)

        proj = angr.Project(path, auto_load_libs=False)
        cfg = self._aborted_cfg(proj)

        # the constructor returned normally with a partial model
        assert 0 < len(cfg.model.graph) < full_node_count
        assert cfg.model in proj.kb.cfgs.cfgs.values()
        assert len(proj.kb.functions) > 0
        # unprocessed jobs were captured for resuming
        assert len(cfg.unprocessed_job_addrs) > 0
        # truncated functions must not be forced to returning=False; they stay undetermined
        assert any(func.returning is None for func in proj.kb.functions.values())

    def test_abort_leaves_finalized_model(self):
        path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(path, auto_load_libs=False)
        cfg = self._aborted_cfg(proj)

        # post-analysis ran: the partial model is normalized and functions are well-formed
        assert cfg.model.normalized
        for func in proj.kb.functions.values():
            if func.is_simprocedure or func.is_syscall or func.is_alignment:
                continue
            assert func.startpoint is not None

    def test_resume_from_address(self):
        path = os.path.join(test_location, "x86_64", "fauxware")

        proj_full = angr.Project(path, auto_load_libs=False)
        proj_full.analyses.CFGFast(normalize=True)
        full_func_addrs = set(proj_full.kb.functions)

        proj = angr.Project(path, auto_load_libs=False)
        cfg_partial = self._aborted_cfg(proj)
        partial_node_count = len(cfg_partial.model.graph)
        partial_func_addrs = set(proj.kb.functions)

        missing = sorted(addr for addr in full_func_addrs if addr not in partial_func_addrs)
        assert missing, "the aborted run unexpectedly recovered every function"
        seed = missing[0]

        cfg_resumed = proj.analyses.CFGFast(
            model=cfg_partial.model,
            function_starts=[seed],
            normalize=True,
            **RESUME_ONLY_KWARGS,
        )

        # recovery resumed on top of the partial model
        assert cfg_resumed.model is cfg_partial.model
        assert len(cfg_resumed.model.graph) > partial_node_count
        # the seeded function was recovered
        assert seed in proj.kb.functions
        # functions recovered before the abort survived the resume
        assert partial_func_addrs.issubset(set(proj.kb.functions))

    def test_global_resume_converges(self):
        path = os.path.join(test_location, "x86_64", "fauxware")

        proj = angr.Project(path, auto_load_libs=False)
        cfg_partial = self._aborted_cfg(proj)

        # resume global scanning: reuse the model, re-seed the aborted frontier, and keep symbol/prologue/eh_frame
        # seeding enabled
        proj.analyses.CFGFast(
            model=cfg_partial.model,
            start_at_entry=False,
            function_starts=sorted(cfg_partial.unprocessed_job_addrs),
            normalize=True,
        )

        for name in ("main", "authenticate", "accepted", "rejected"):
            assert proj.kb.functions.function(name=name) is not None, f"function {name} missing after global resume"

    def test_second_pass_idempotent(self):
        path = os.path.join(test_location, "x86_64", "fauxware")

        proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        node_count = len(cfg.model.graph)
        edge_count = len(cfg.model.graph.edges)
        func_addrs = set(proj.kb.functions)
        xref_count = sum(len(refs) for refs in proj.kb.xrefs.xrefs_by_ins_addr.values())

        # run a resume pass over the already-complete model with no new seeds
        cfg2 = proj.analyses.CFGFast(
            model=cfg.model,
            function_starts=[],
            normalize=True,
            data_references=True,
            **RESUME_ONLY_KWARGS,
        )

        assert cfg2.model is cfg.model
        assert len(cfg2.model.graph) == node_count
        assert len(cfg2.model.graph.edges) == edge_count
        assert set(proj.kb.functions) == func_addrs
        assert sum(len(refs) for refs in proj.kb.xrefs.xrefs_by_ins_addr.values()) == xref_count

    def test_abort_during_ij_resolution(self):
        # aborting during indirect-jump resolution must stop the batch instead of resolving all remaining jumps
        # (on this binary the first batch contains several jump tables)
        path = os.path.join(test_location, "x86_64", "cfg_switches")
        proj = angr.Project(path, auto_load_libs=False)

        calls = []
        orig = CFGBase._process_one_indirect_jump

        def abort_on_first(self, jump, func_graph_complete=True):
            calls.append(len(self._indirect_jumps_to_resolve))
            self.abort()
            return orig(self, jump, func_graph_complete=func_graph_complete)

        CFGBase._process_one_indirect_jump = abort_on_first
        try:
            cfg = proj.analyses.CFGFast(normalize=True)
        finally:
            CFGBase._process_one_indirect_jump = orig

        assert cfg.should_abort
        # the batch contained more than one indirect jump, but only the first one was processed before the abort
        # took effect
        assert calls and calls[0] > 1
        assert len(calls) == 1
        assert len(cfg.model.graph) > 0
        assert cfg.model.normalized


if __name__ == "__main__":
    unittest.main()
