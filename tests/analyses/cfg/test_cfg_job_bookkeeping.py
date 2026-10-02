#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestCfgJobBookkeeping(unittest.TestCase):
    def test_finished_functions_are_tracked_incrementally(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        # the final completion sweep leaves no empty job sets behind
        assert not cfg._functions_without_jobs
        assert all(jobs for jobs in cfg._jobs_to_analyze_per_function.values())

        job_a, job_b = object(), object()
        cfg._register_analysis_job(0x1000, job_a)
        assert cfg._get_finished_functions() == []
        cfg._deregister_analysis_job(0x1000, job_a)
        assert cfg._get_finished_functions() == [0x1000]

        # a job arriving before the completion sweep un-finishes the function
        cfg._register_analysis_job(0x1000, job_b)
        assert cfg._get_finished_functions() == []

        # deregistering an unknown job of an unknown function marks it finished (defaultdict semantics)
        cfg._deregister_analysis_job(0x2000, job_a)
        cfg._deregister_analysis_job(0x1000, job_b)
        assert cfg._get_finished_functions() == [0x2000, 0x1000]

        cfg._make_completed_functions()
        assert {0x1000, 0x2000} <= cfg._completed_functions
        assert 0x1000 not in cfg._jobs_to_analyze_per_function
        assert 0x2000 not in cfg._jobs_to_analyze_per_function
        assert cfg._get_finished_functions() == []


if __name__ == "__main__":
    unittest.main()
