# pylint:disable=no-self-use
"""
Regression tests for angr.utils.mp.protect_stdio_from_forked_children.

An MCP server (or any other host) that speaks a protocol over stdin/stdout keeps a thread parked in a blocking read
on ``sys.stdin``. CPython's ``BufferedReader`` holds its internal lock across that blocking read, so a ``fork()``
performed from a *different* thread produces a child that inherits the lock in a permanently locked state. The very
first thing ``multiprocessing.process.BaseProcess._bootstrap()`` does is ``util._close_stdin()``, which closes
``sys.stdin`` -- and hangs forever. Every angr analysis that takes a ``workers=N`` argument uses the ``fork`` start
method on Linux (see :func:`angr.utils.mp.mp_context`), so they all deadlock in that situation.

These tests run in a subprocess because they need to own stdin/stdout and to install a process-global
``os.register_at_fork`` hook.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

# language=python
_CHILD_SCRIPT = textwrap.dedent(
    """
    import io, multiprocessing, os, sys, threading, time

    if {install_fix}:
        from angr.utils.mp import protect_stdio_from_forked_children
        protect_stdio_from_forked_children()

    def stdin_reader():
        # this is what mcp.server.stdio.stdio_server() does
        io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace").readline()

    threading.Thread(target=stdin_reader, daemon=True).start()
    time.sleep(0.5)  # let it settle into the blocking read, holding the buffer lock

    def child():
        # both of these would land on the protocol channel without the fix
        print("CHILD_STDOUT")
        os.write(1, b"CHILD_FD1\\n")
        sys.stderr.write("CHILD_RAN\\n")
        sys.stderr.flush()

    ctx = multiprocessing.get_context("fork")
    procs = [ctx.Process(target=child, daemon=True) for _ in range(2)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=5)
    alive = [p.pid for p in procs if p.is_alive()]
    for p in procs:
        if p.is_alive():
            p.kill()
    sys.stderr.write("ALIVE=%d\\n" % len(alive))
    sys.stderr.flush()
    """
)


def _run(install_fix: bool) -> subprocess.CompletedProcess[str]:
    # The reader thread must still be *inside* the blocking read when fork() happens -- that is the steady state of
    # a stdio JSON-RPC server between requests. So hand the child a pipe and keep the write end open here;
    # subprocess.run(stdin=PIPE) would close it immediately, the read would return EOF, and the lock would be
    # released before the fork.
    read_fd, write_fd = os.pipe()
    try:
        return subprocess.run(
            [sys.executable, "-c", _CHILD_SCRIPT.format(install_fix=install_fix)],
            stdin=read_fd,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    finally:
        os.close(read_fd)
        os.close(write_fd)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires fork()")
class TestProtectStdioFromForkedChildren:
    """Tests for protect_stdio_from_forked_children()."""

    def test_forked_workers_deadlock_without_the_guard(self):
        """Without the guard, fork()ed children wedge in multiprocessing's _close_stdin()."""
        result = _run(install_fix=False)
        assert "ALIVE=2" in result.stderr, f"expected both children to hang; stderr={result.stderr!r}"
        assert "CHILD_RAN" not in result.stderr
        # they never even get as far as running the target, so nothing reaches stdout either
        assert result.stdout == ""

    def test_forked_workers_run_with_the_guard(self):
        """With the guard installed, the children start normally and finish."""
        result = _run(install_fix=True)
        assert "ALIVE=0" in result.stderr, f"children did not finish; stderr={result.stderr!r}"
        assert result.stderr.count("CHILD_RAN") == 2

    def test_child_output_is_kept_off_of_stdout(self):
        """The parent's stdout is a protocol channel; nothing a child writes may reach it."""
        result = _run(install_fix=True)
        assert result.stdout == "", f"child output leaked onto stdout: {result.stdout!r}"
        assert "CHILD_STDOUT" in result.stderr
        assert "CHILD_FD1" in result.stderr

    def test_is_idempotent(self):
        """Calling it repeatedly must not stack up fork hooks."""
        from angr.utils.mp import protect_stdio_from_forked_children  # pylint:disable=import-outside-toplevel

        protect_stdio_from_forked_children()
        protect_stdio_from_forked_children()
        protect_stdio_from_forked_children()


if __name__ == "__main__":
    pytest.main([__file__])
