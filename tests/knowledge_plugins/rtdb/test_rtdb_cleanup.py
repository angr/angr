#!/usr/bin/env python3
# pylint:disable=no-self-use,unnecessary-dunder-call,missing-class-docstring
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.rtdb"  # pylint:disable=redefined-builtin

import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

from angr.knowledge_plugins.rtdb.rtdb import PIN_FILENAME, RuntimeDb, _cleanup_all_rtdbs
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

CHILD_TIMEOUT = 60

# Common preamble for child scripts: create a RuntimeDb at an explicit path and force LMDB initialization.
# A fake KnowledgeBase suffices because an explicit lmdb_path never touches kb._project.
CHILD_PREAMBLE = """
import os
import sys
import time

from angr.knowledge_plugins.rtdb.rtdb import RuntimeDb


class FakeKB:
    pass


def make_rtdb(path):
    rtdb = RuntimeDb(FakeKB(), lmdb_path=path)
    rtdb.open_db("testdb")
    return rtdb


def wait_for(path):
    while not os.path.exists(path):
        time.sleep(0.05)
"""


class FakeKB:
    pass


def make_rtdb(path: str) -> RuntimeDb:
    rtdb = RuntimeDb(FakeKB(), lmdb_path=path)
    rtdb.open_db("testdb")
    return rtdb


def run_child(script_body: str, *args: str, env: dict[str, str] | None = None) -> None:
    """
    Run a child Python script (CHILD_PREAMBLE + script_body) in a subprocess and assert it exits cleanly.
    """
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(CHILD_PREAMBLE + textwrap.dedent(script_body))
        script_path = f.name
    try:
        full_env = dict(os.environ)
        if env:
            full_env.update(env)
        result = subprocess.run(
            [sys.executable, script_path, *args],
            capture_output=True,
            text=True,
            timeout=CHILD_TIMEOUT,
            env=full_env,
            check=False,
        )
        assert result.returncode == 0, f"child process failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    finally:
        os.unlink(script_path)


def wait_for_removal(path: str, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not os.path.exists(path):
            return True
        time.sleep(0.05)
    return False


class TestRuntimeDbAtexitCleanup(unittest.TestCase):
    """
    Test that RuntimeDb directories are removed at process exit even when __del__ never runs, and that they are
    removed at most once.
    """

    def test_rtdb_dir_leaks_without_atexit_hook(self):
        # This exposes the original problem: CPython does not guarantee __del__ runs at interpreter shutdown
        # (simulated by neutralizing __del__ and holding a strong global reference). With the atexit hook
        # unregistered, the rtdb directory leaks.
        with tempfile.TemporaryDirectory() as tmpdir:
            rtdb_path = os.path.join(tmpdir, "rtdb")
            run_child(
                """
                import atexit
                import angr.knowledge_plugins.rtdb.rtdb as rtdb_module

                atexit.unregister(rtdb_module._cleanup_all_rtdbs)
                RuntimeDb.__del__ = lambda self: None  # simulate __del__ never running
                _keep = make_rtdb(sys.argv[1])
                """,
                rtdb_path,
            )
            assert os.path.isdir(rtdb_path), "expected the rtdb directory to leak without the atexit hook"

    def test_atexit_cleans_up_when_del_does_not_run(self):
        # Same scenario as above, but with the atexit hook in place: the directory must be removed.
        with tempfile.TemporaryDirectory() as tmpdir:
            rtdb_path = os.path.join(tmpdir, "rtdb")
            run_child(
                """
                RuntimeDb.__del__ = lambda self: None  # simulate __del__ never running
                _keep = make_rtdb(sys.argv[1])
                """,
                rtdb_path,
            )
            assert not os.path.exists(rtdb_path)

    def test_atexit_cleans_up_on_normal_exit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rtdb_path = os.path.join(tmpdir, "rtdb")
            run_child(
                """
                _keep = make_rtdb(sys.argv[1])
                """,
                rtdb_path,
            )
            assert not os.path.exists(rtdb_path)

    def test_cleanup_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rtdb_path = os.path.join(tmpdir, "rtdb")
            rtdb = make_rtdb(rtdb_path)
            assert os.path.isdir(rtdb_path)

            rtdb.cleanup()
            assert not os.path.exists(rtdb_path)

            # a second cleanup, an explicit __del__, and the atexit hook must all be no-ops; in particular, they
            # must not remove an unrelated directory that reappears at the same path
            os.makedirs(rtdb_path)
            rtdb.cleanup()
            rtdb.__del__()
            _cleanup_all_rtdbs()
            assert os.path.isdir(rtdb_path)

    def test_project_rtdb_cleaned_up_at_exit(self):
        # End-to-end: a real project whose rtdb directory is placed via RTDB_BASE must leave nothing behind.
        binary = os.path.join(test_location, "x86_64", "fauxware")
        with tempfile.TemporaryDirectory() as tmpdir:
            run_child(
                """
                import angr

                proj = angr.Project(sys.argv[1], auto_load_libs=False)
                proj.kb.rtdb.open_db("testdb")
                _keep = proj  # lingering global reference
                """,
                binary,
                env={"RTDB_BASE": tmpdir},
            )
            assert os.listdir(tmpdir) == [], f"leftover rtdb directories: {os.listdir(tmpdir)}"


@unittest.skipIf(sys.platform == "win32", "flock-based pinning is POSIX-only")
class TestRuntimeDbMultiProcessCleanup(unittest.TestCase):
    """
    Test that when multiple processes share the same rtdb directory, only the last exiting process removes it.
    """

    WAITER_SCRIPT = """
    _keep = make_rtdb(sys.argv[1])
    with open(sys.argv[2], "w") as f:
        f.write("ready")
    wait_for(sys.argv[3])
    """

    def _spawn_waiter(self, tmpdir: str, rtdb_path: str, name: str) -> tuple[subprocess.Popen, str]:
        ready_f = os.path.join(tmpdir, f"ready_{name}")
        go_f = os.path.join(tmpdir, f"go_{name}")
        script_path = os.path.join(tmpdir, f"waiter_{name}.py")
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(CHILD_PREAMBLE + textwrap.dedent(self.WAITER_SCRIPT))
        proc = subprocess.Popen(  # pylint:disable=consider-using-with
            [sys.executable, script_path, rtdb_path, ready_f, go_f],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + CHILD_TIMEOUT
        while not os.path.exists(ready_f):
            assert proc.poll() is None, f"waiter process {name} died prematurely"
            assert time.monotonic() < deadline, f"waiter process {name} did not become ready in time"
            time.sleep(0.05)
        return proc, go_f

    def test_pin_held_by_another_locker_prevents_removal(self):
        # simulate another process pinning the directory: flock conflicts apply across open file descriptions,
        # so a second descriptor in this process behaves exactly like another process
        import fcntl  # pylint:disable=import-outside-toplevel

        with tempfile.TemporaryDirectory() as tmpdir:
            rtdb_path = os.path.join(tmpdir, "rtdb")
            rtdb = make_rtdb(rtdb_path)
            fd = os.open(os.path.join(rtdb_path, PIN_FILENAME), os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_SH)
                rtdb.cleanup()
                assert os.path.isdir(rtdb_path), "directory must survive while another pin is held"
            finally:
                os.close(fd)

    def test_two_processes_last_exit_removes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            rtdb_path = os.path.join(tmpdir, "rtdb")
            p1, go1 = self._spawn_waiter(tmpdir, rtdb_path, "p1")
            p2, go2 = self._spawn_waiter(tmpdir, rtdb_path, "p2")

            with open(go1, "w", encoding="utf-8") as f:
                f.write("go")
            assert p1.wait(timeout=CHILD_TIMEOUT) == 0
            assert os.path.isdir(rtdb_path), "directory must survive while another process still uses it"

            with open(go2, "w", encoding="utf-8") as f:
                f.write("go")
            assert p2.wait(timeout=CHILD_TIMEOUT) == 0
            assert not os.path.exists(rtdb_path), "last exiting process must remove the directory"

    def test_killed_process_releases_pin(self):
        # a SIGKILL-ed process runs no cleanup, but the kernel releases its flock, so the surviving process can
        # still remove the directory when it exits
        with tempfile.TemporaryDirectory() as tmpdir:
            rtdb_path = os.path.join(tmpdir, "rtdb")
            p1, _go1 = self._spawn_waiter(tmpdir, rtdb_path, "p1")
            p2, go2 = self._spawn_waiter(tmpdir, rtdb_path, "p2")

            p1.send_signal(signal.SIGKILL)
            p1.wait(timeout=CHILD_TIMEOUT)
            assert os.path.isdir(rtdb_path), "a killed process must not have removed the directory"

            with open(go2, "w", encoding="utf-8") as f:
                f.write("go")
            assert p2.wait(timeout=CHILD_TIMEOUT) == 0
            assert not os.path.exists(rtdb_path)

    def test_forked_child_exits_last(self):
        # a forked child inherits the parent's pin; the parent exits first and must leave the directory alone,
        # and the orphaned child removes it when it exits
        with tempfile.TemporaryDirectory() as tmpdir:
            rtdb_path = os.path.join(tmpdir, "rtdb")
            go_f = os.path.join(tmpdir, "go_child")
            script_path = os.path.join(tmpdir, "forker.py")
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(
                    CHILD_PREAMBLE
                    + textwrap.dedent(
                        """
                        _keep = make_rtdb(sys.argv[1])
                        pid = os.fork()
                        if pid == 0:
                            # child: wait for the go signal, then exit normally so atexit hooks run
                            wait_for(sys.argv[2])
                            sys.exit(0)
                        sys.exit(0)  # parent exits first
                        """
                    )
                )
            result = subprocess.run(
                [sys.executable, script_path, rtdb_path, go_f],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=CHILD_TIMEOUT,
                check=False,
            )
            assert result.returncode == 0
            assert os.path.isdir(rtdb_path), "directory must survive while the forked child is alive"

            with open(go_f, "w", encoding="utf-8") as f:
                f.write("go")
            assert wait_for_removal(rtdb_path), "the forked child must remove the directory on exit"


if __name__ == "__main__":
    unittest.main()
