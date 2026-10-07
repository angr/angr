#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.functions"  # pylint:disable=redefined-builtin

import os
import sys
import threading
import time
import unittest

import angr
from tests.common import bin_location

FAUXWARE = os.path.join(bin_location, "tests", "x86_64", "fauxware")


class TestSpillingFunctionDictConcurrentEviction(unittest.TestCase):
    def test_evict_n_tolerates_concurrent_lru_updates(self):
        # angr-management reads functions from the GUI thread while an analysis job stores new ones and triggers
        # evictions. Reads touch the LRU OrderedDict; _evict_n must not die with "OrderedDict mutated during
        # iteration".
        proj = angr.Project(FAUXWARE, auto_load_libs=False, cache_limits={"functions": 100})
        proj.analyses.CFGFast()
        fm = proj.kb.functions
        sfd = fm._function_map
        addrs = list(fm)
        sfd._db_batch_size = 1000
        sfd.cache_limit = 8

        errors: list[BaseException] = []
        stop = threading.Event()

        def reader():
            i = 0
            while not stop.is_set():
                try:
                    fm.get_by_addr(addrs[i % len(addrs)])
                except KeyError:
                    pass  # unrelated eviction window (function neither cached nor marked spilled yet)
                except BaseException as ex:  # pylint:disable=broad-exception-caught
                    errors.append(ex)
                    return
                i += 1

        def writer():
            fake = 0x900000
            while not stop.is_set():
                try:
                    fm.function(addr=fake, create=True)  # stores a function, which triggers _evict_lru
                except BaseException as ex:  # pylint:disable=broad-exception-caught
                    errors.append(ex)
                    return
                fake += 0x10

        old_interval = sys.getswitchinterval()
        sys.setswitchinterval(1e-5)
        try:
            threads = [threading.Thread(target=reader), threading.Thread(target=writer)]
            for t in threads:
                t.start()
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline and not errors:
                time.sleep(0.01)
            stop.set()
            for t in threads:
                t.join()
        finally:
            sys.setswitchinterval(old_interval)

        assert not errors, f"eviction raced with a concurrent read: {errors[0]!r}"


if __name__ == "__main__":
    unittest.main()
