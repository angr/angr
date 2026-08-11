#!/usr/bin/env python3
# pylint:disable=no-self-use,missing-class-docstring,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.rtdb"  # pylint:disable=redefined-builtin

import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

import lmdb

from angr.errors import AngrRuntimeDbError
from angr.knowledge_plugins.rtdb.rtdb import RuntimeDb

CHILD_TIMEOUT = 60

# Exit code the child uses when it could not make mdb_env_set_mapsize() fail, so there is nothing to test.
NOT_SQUEEZED = 3

# This child squeezes RLIMIT_AS so that mdb_env_set_mapsize() fails, which leaves the environment pointing at
# addresses that are no longer mapped, and then calls drop_db() the way every spilling container's __del__ does.
# Opening a write transaction on such an environment segfaults, so a child that exits cleanly is the whole assertion.
CHILD_SCRIPT = """
import resource
import sys

import lmdb

from angr.knowledge_plugins.rtdb.rtdb import RuntimeDb

NOT_SQUEEZED = 3


class FakeKB:
    pass


def vmsize():
    with open("/proc/self/status", encoding="utf-8") as f:
        for line in f:
            if line.startswith("VmSize:"):
                return int(line.split()[1]) * 1024
    raise AssertionError("no VmSize in /proc/self/status")


# a segfault here is the failure this test is looking for, so do not spend a core dump on it
resource.setrlimit(resource.RLIMIT_CORE, (0, resource.getrlimit(resource.RLIMIT_CORE)[1]))

rtdb = RuntimeDb(FakeKB(), lmdb_path=sys.argv[1])
rtdb.open_db("testdb")
with rtdb.begin_txn("testdb", write=True) as txn:
    txn.put(b"k", b"v")

# ask for a 64 GiB map with 64 MiB of address space left: mmap cannot satisfy that, and the interpreter keeps
# enough room to raise the exception
rtdb._lmdb_mapsize = 64 * 1024 * 1024 * 1024
soft, hard = resource.getrlimit(resource.RLIMIT_AS)
resource.setrlimit(resource.RLIMIT_AS, (vmsize() + 64 * 1024 * 1024, hard))
try:
    rtdb.increase_lmdb_map_size()
    squeezed = False
except lmdb.Error:
    squeezed = True
finally:
    resource.setrlimit(resource.RLIMIT_AS, (soft, hard))

if not squeezed:
    sys.exit(NOT_SQUEEZED)

# this is the __del__ path of every spilling container
rtdb.drop_db("testdb")
rtdb.cleanup()
sys.exit(0)
"""


class FakeKB:
    pass


class PoisonedEnvironment:
    """
    Stands in for an lmdb.Environment whose set_mapsize() unmapped the existing region and then failed to map the
    new one. The real thing segfaults on every operation except close(); this raises AssertionError instead, so that
    a test can tell that the environment was used.
    """

    def __init__(self, env):
        self._env = env
        self.poisoned = False
        self.closed = False

    def _check(self) -> None:
        assert not self.poisoned, "used an LMDB environment that a failed set_mapsize() left unmapped"

    def set_mapsize(self, size):  # pylint:disable=unused-argument
        self.poisoned = True
        raise lmdb.MemoryError("mdb_env_set_mapsize: Cannot allocate memory")

    def open_db(self, name):
        self._check()
        return self._env.open_db(name)

    def begin(self, **kwargs):
        self._check()
        return self._env.begin(**kwargs)

    def close(self):
        # close() is the one operation that is still safe after the failure
        self.closed = True
        self._env.close()


class TestRuntimeDbMapSizeIncreaseFailure(unittest.TestCase):
    """
    Test that a failed LMDB map size increase discards the environment instead of leaving it in use.
    """

    def test_failed_increase_discards_the_environment(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rtdb_path = os.path.join(tmpdir, "rtdb")
            rtdb = RuntimeDb(FakeKB(), lmdb_path=rtdb_path)  # type: ignore  # an explicit path never touches the kb
            rtdb.open_db("testdb")
            mapsize = rtdb._lmdb_mapsize
            env = PoisonedEnvironment(rtdb._lmdb_env)
            rtdb._lmdb_env = env  # type: ignore  # stands in for an lmdb.Environment

            with self.assertRaises(lmdb.MemoryError):
                rtdb.increase_lmdb_map_size()

            # the environment is closed and forgotten: nothing can reach the unmapped region through it any more
            assert env.closed
            assert rtdb._lmdb_env is None
            assert not rtdb._dbs
            assert rtdb._lmdb_mapsize == mapsize, "a size that failed to map must not be recorded as the map size"
            assert not os.path.exists(rtdb_path), "the rtdb directory must not outlive the environment"

            # drop_db() runs from the __del__ of every spilling container and must stay quiet
            rtdb.drop_db("testdb")

            # every other entry point reports the loss instead of using a dead environment
            with self.assertRaises(AngrRuntimeDbError):
                rtdb.begin_txn("testdb")
            with self.assertRaises(AngrRuntimeDbError):
                rtdb.open_db("testdb")
            with self.assertRaises(AngrRuntimeDbError):
                rtdb.increase_lmdb_map_size()

            # the fork handler has nothing to reopen
            rtdb.reopen_lmdb()
            assert rtdb._lmdb_env is None

            rtdb.cleanup()

    @unittest.skipUnless(sys.platform.startswith("linux"), "needs an enforced RLIMIT_AS")
    def test_drop_db_after_a_real_failed_increase_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rtdb_path = os.path.join(tmpdir, "rtdb")
            script_path = os.path.join(tmpdir, "mapsize_child.py")
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(textwrap.dedent(CHILD_SCRIPT))
            result = subprocess.run(
                [sys.executable, script_path, rtdb_path],
                capture_output=True,
                text=True,
                timeout=CHILD_TIMEOUT,
                check=False,
            )
            if result.returncode == NOT_SQUEEZED:
                self.skipTest("could not make mdb_env_set_mapsize() run out of address space")
            assert result.returncode == 0, (
                f"child exited with {result.returncode} (a negative value is the signal that killed it)\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )
            # a finalizer that raises does not fail the child, it only prints, so check for that too
            assert "Exception ignored" not in result.stderr, result.stderr
            assert not os.path.exists(rtdb_path)


if __name__ == "__main__":
    unittest.main()
