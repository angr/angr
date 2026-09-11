#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.analyses.cfg.cfg_base import CFGBase
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _rescan(cfg):
    """Every function tracked by the analysis whose job set is empty."""
    return {func_addr for func_addr, jobs in cfg._jobs_to_analyze_per_function.items() if not jobs}


class TestCFGJobTracking(unittest.TestCase):
    """CFGBase reports the functions with no jobs left without rescanning every function."""

    def _recover_and_compare(self, path):
        """Run CFGFast, comparing what _get_finished_functions returns against a rescan on every call."""
        proj = angr.Project(path, auto_load_libs=False)
        original = CFGBase._get_finished_functions
        observed = {"calls": 0, "returned": 0}

        def compared(self):
            reported = set(original(self))
            rescanned = _rescan(self)
            assert reported == rescanned, (
                f"reported but not found by a rescan: {sorted(reported - rescanned)}; "
                f"found by a rescan but not reported: {sorted(rescanned - reported)}"
            )
            observed["calls"] += 1
            observed["returned"] += len(reported)
            return list(reported)

        CFGBase._get_finished_functions = compared
        try:
            proj.analyses.CFGFast()
        finally:
            CFGBase._get_finished_functions = original
        return observed

    def test_finished_functions_match_a_rescan_x86_64(self):
        observed = self._recover_and_compare(os.path.join(test_location, "x86_64", "fauxware"))
        assert observed["calls"] > 0
        assert observed["returned"] > 0

    def test_finished_functions_match_a_rescan_armel(self):
        observed = self._recover_and_compare(os.path.join(test_location, "armel", "fauxware"))
        assert observed["calls"] > 0
        assert observed["returned"] > 0

    def _empty_cfg(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        cfg._jobs_to_analyze_per_function.clear()
        cfg._functions_without_jobs.clear()
        return cfg

    def test_registering_a_job_unmarks_a_finished_function(self):
        cfg = self._empty_cfg()
        job = object()

        cfg._register_analysis_job(0x400000, job)
        assert cfg._get_finished_functions() == []
        assert _rescan(cfg) == set()

        cfg._deregister_analysis_job(0x400000, job)
        assert cfg._get_finished_functions() == [0x400000]
        assert _rescan(cfg) == {0x400000}

        cfg._register_analysis_job(0x400000, object())
        assert cfg._get_finished_functions() == []
        assert _rescan(cfg) == set()

    def test_deregistering_an_unknown_job_marks_the_function_finished(self):
        # _jobs_to_analyze_per_function is a defaultdict, so deregistering a job that was never
        # registered leaves an empty entry behind, and an empty entry counts as finished.
        cfg = self._empty_cfg()

        cfg._deregister_analysis_job(0x400000, object())
        assert cfg._get_finished_functions() == [0x400000]
        assert _rescan(cfg) == {0x400000}

    def test_cleanup_drops_the_function_from_both_records(self):
        cfg = self._empty_cfg()
        job = object()
        cfg._register_analysis_job(0x400000, job)
        cfg._deregister_analysis_job(0x400000, job)

        cfg._cleanup_analysis_jobs(finished_func_addrs=[0x400000])

        assert cfg._get_finished_functions() == []
        assert _rescan(cfg) == set()
        assert 0x400000 not in cfg._jobs_to_analyze_per_function


if __name__ == "__main__":
    unittest.main()
