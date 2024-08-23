#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.serialization"  # pylint:disable=redefined-builtin

from contextlib import suppress
import gc
import os
import pickle
import shutil
import unittest

from claripy import BVS

import angr
from angr.storage import SimFile

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestPickle(unittest.TestCase):
    @classmethod
    def tearDown(self):
        shutil.rmtree("pickletest", ignore_errors=True)
        shutil.rmtree("pickletest2", ignore_errors=True)
        with suppress(FileNotFoundError):
            os.remove("pickletest_good")
        with suppress(FileNotFoundError):
            os.remove("pickletest_bad")

    def _load_pickles(self):
        # This is the working case
        with open("pickletest_good", "rb"):
            pass

        # This will not work
        with open("pickletest_bad", "rb"):
            pass

    def _make_pickles(self):
        p = angr.Project(os.path.join(test_location, "i386", "fauxware"))

        fs = {
            "/dev/stdin": SimFile("/dev/stdin"),
            "/dev/stdout": SimFile("/dev/stdout"),
            "/dev/stderr": SimFile("/dev/stderr"),
        }

        MEM_SIZE = 1024
        mem_bvv = {}
        for f in fs:
            mem = BVS(f, MEM_SIZE * 8)
            mem_bvv[f] = mem

        with open("pickletest_good", "wb") as f:
            pickle.dump(mem_bvv, f, -1)

        # If you do not have a state you cannot write
        _ = p.factory.entry_state(fs=fs)
        for f in fs:
            mem = mem_bvv[f]
            fs[f].write(0, mem, MEM_SIZE)

        with open("pickletest_bad", "wb") as f:
            pickle.dump(mem_bvv, f, -1)

    def test_pickling(self):
        self._make_pickles()
        self._load_pickles()
        gc.collect()
        self._load_pickles()

    def test_project_pickling(self):
        # AnalysesHub should not be pickled together with the project itself
        p = angr.Project(os.path.join(test_location, "i386", "fauxware"))

        # make a copy of the active_preset so that we do not touch the global preset object. this is only for writing
        # this test case.
        p.analyses._active_preset = pickle.loads(pickle.dumps(p.analyses._active_preset, -1))
        assert len(p.analyses._active_preset._default_plugins) > 0
        p.analyses._active_preset = p.analyses._active_preset
        p.analyses._active_preset._default_plugins = {}
        assert len(p.analyses._active_preset._default_plugins) == 0

        s = pickle.dumps(p, -1)

        p1 = pickle.loads(s)
        assert len(p1.analyses._active_preset._default_plugins) > 0


if __name__ == "__main__":
    unittest.main()
