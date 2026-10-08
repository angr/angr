#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import sys
import threading
import time
import unittest

import angr
from tests.common import bin_location

FAUXWARE = os.path.join(bin_location, "tests", "x86_64", "fauxware")


class TestCompleteCallingConventionsConcurrentEviction(unittest.TestCase):
    def test_analyze_tolerates_functions_mid_eviction(self):
        # While SpillingFunctionDict._evict_n moves a function from memory to LMDB, the function is briefly neither
        # cached nor in _spilled_keys, so FunctionManager.get_by_addr raises KeyError for it. CompleteCallingConventions
        # walks the call graph from another thread (an angr-management job) and must survive that window.
        proj = angr.Project(FAUXWARE, auto_load_libs=False, cache_limits={"functions": 100})
        proj.analyses.CFGFast()
        fm = proj.kb.functions
        sfd = fm._function_map
        sfd._db_batch_size = 1000
        sfd.cache_limit = 8

        stop = threading.Event()

        def churn():
            # keep evicting whatever the analysis thread loads; the call graph itself stays untouched
            while not stop.is_set():
                try:
                    with sfd._db_store_lock:
                        sfd._evict_n(sfd.cached_count)
                except RuntimeError:
                    pass  # LRU OrderedDict mutated by the analysis thread; covered by the SpillingFunctionDict test

        old_interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-5)
        t = threading.Thread(target=churn)
        t.start()
        try:
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                proj.analyses.CompleteCallingConventions(auto_start=False)
        finally:
            stop.set()
            t.join()
            sys.setswitchinterval(old_interval)


if __name__ == "__main__":
    unittest.main()
