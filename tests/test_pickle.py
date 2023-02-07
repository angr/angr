from contextlib import suppress
from claripy import BVS
from angr.storage import SimFile
import pickle
import shutil
import angr
import gc
import os
import unittest

tests_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


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
        f = open("pickletest_good", "rb")
        f.close()

        # This will not work
        f = open("pickletest_bad", "rb")
        f.close()

    def _make_pickles(self):
        p = angr.Project(os.path.join(tests_location, "i386", "fauxware"))

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

        f = open("pickletest_good", "wb")
        pickle.dump(mem_bvv, f, -1)
        f.close()

        # If you do not have a state you cannot write
        _ = p.factory.entry_state(fs=fs)
        for f in fs:
            mem = mem_bvv[f]
            fs[f].write(0, mem, MEM_SIZE)

        f = open("pickletest_bad", "wb")
        pickle.dump(mem_bvv, f, -1)
        f.close()

    def test_pickling(self):
        self._make_pickles()
        self._load_pickles()
        gc.collect()
        self._load_pickles()

    def test_project_pickling(self):
        # AnalysesHub should not be pickled together with the project itself
        p = angr.Project(os.path.join(tests_location, "i386", "fauxware"))

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
