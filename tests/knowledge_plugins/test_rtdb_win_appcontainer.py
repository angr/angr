#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,missing-function-docstring,line-too-long,no-self-use
"""
Test case for angr/angr#6391: LMDB fails inside Windows AppContainers.

The outer test (Windows-only) launches a child Python process inside a freshly
created AppContainer and runs the *core* test in that child. The core test
itself fails (raises ``AssertionError``) when not on Windows or not running
inside an AppContainer, so it is meaningful only when invoked the way the
outer test invokes it.

Without the fix the core test raises ``lmdb.Error: ...: Input/output error``
when ``RuntimeDb`` initializes its LMDB environment, because LMDB's
``CreateMutexA("Global\\MDB...r")`` is denied in AppContainers. With the fix,
``RuntimeDb`` detects the AppContainer and passes ``lock=False``
(``MDB_NOLOCK``) to ``lmdb.open``, so the open succeeds.
"""
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins"  # pylint: disable=redefined-builtin

import os
import subprocess
import sys
import tempfile
import unittest
import ctypes
from ctypes import wintypes

 

_AC_PROFILE_NAME = "angr.RtdbAppContainerTest.6391"
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _core_test() -> None:
    """
    The actual reproducer. Designed to run only inside the AppContainer child
    spawned by ``TestRtdbAppContainer.test_lmdb_in_appcontainer``. Asserts
    (does not skip) when its preconditions are not met, so an accidental
    invocation in a normal environment is reported as a failure.
    """
    assert sys.platform == "win32", "core test must be invoked on Windows"

    from angr.knowledge_plugins.rtdb.rtdb import _is_windows_appcontainer  # noqa: PLC0415

    assert _is_windows_appcontainer(), "core test must be invoked inside a Windows AppContainer"

    import angr  # noqa: PLC0415
    from tests.common import bin_location  # noqa: PLC0415

    bin_path = os.path.join(bin_location, "tests", "x86_64", "fauxware")
    project = angr.Project(bin_path, auto_load_libs=False)
    # Forces RuntimeDb._init_lmdb -> _attempt_creating_lmdb -> lmdb.open(...).
    # Without the lock=False fix this call raises lmdb.Error("Input/output error").
    db_name = project.kb.rtdb.open_db("appcontainer_repro")
    assert db_name == "appcontainer_repro"


# --------------------------------------------------------------------------- #
# Windows-only outer test: spawn the core test inside a fresh AppContainer.
# --------------------------------------------------------------------------- #


@unittest.skipUnless(sys.platform == "win32", "AppContainer is a Windows-only sandbox")
class TestRtdbAppContainer(unittest.TestCase):
    def test_lmdb_in_appcontainer(self):
        import ctypes  # noqa: PLC0415
        from ctypes import wintypes  # noqa: PLC0415

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        userenv = ctypes.WinDLL("userenv", use_last_error=True)

        # ---- Win32 structs / constants ---- #
        class SECURITY_CAPABILITIES(ctypes.Structure):
            _fields_ = [
                ("AppContainerSid", ctypes.c_void_p),
                ("Capabilities", ctypes.c_void_p),
                ("CapabilityCount", wintypes.DWORD),
                ("Reserved", wintypes.DWORD),
            ]

        class STARTUPINFOW(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR),
                ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD),
                ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD),
                ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD),
                ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE),
            ]

        class STARTUPINFOEXW(ctypes.Structure):
            _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("hProcess", wintypes.HANDLE),
                ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD),
            ]

        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000
        CREATE_UNICODE_ENVIRONMENT = 0x00000400
        STARTF_USESTDHANDLES = 0x00000100
        HANDLE_FLAG_INHERIT = 0x00000001
        INFINITE = 0xFFFFFFFF

        # ---- 1) Create / derive an AppContainer SID ---- #
        sid = ctypes.c_void_p(0)
        hr = userenv.CreateAppContainerProfile(
            ctypes.c_wchar_p(_AC_PROFILE_NAME),
            ctypes.c_wchar_p(_AC_PROFILE_NAME),
            ctypes.c_wchar_p("angr rtdb 6391 reproducer"),
            None,
            0,
            ctypes.byref(sid),
        )
        if hr != 0:
            # Already exists: derive its SID from the profile name.
            sid = ctypes.c_void_p(0)
            hr = userenv.DeriveAppContainerSidFromAppContainerName(
                ctypes.c_wchar_p(_AC_PROFILE_NAME), ctypes.byref(sid)
            )
            self.assertEqual(hr, 0, f"DeriveAppContainerSidFromAppContainerName hr={hr:#010x}")

        try:
            # ---- 2) Grant ALL APPLICATION PACKAGES (S-1-15-2-1) read+execute on every
            #         path the child needs to import from. AppContainer processes inherit
            #         from this SID, so this is sufficient regardless of which specific
            #         AppContainer SID we created above. ---- #
            mods_to_grant = ["angr", "lmdb", "claripy", "cle", "archinfo", "pyvex", "networkx"]
            grant_paths = {os.path.dirname(sys.executable), sys.exec_prefix}
            for name in mods_to_grant:
                try:
                    mod = __import__(name)
                except ImportError:
                    continue
                if getattr(mod, "__file__", None):
                    grant_paths.add(os.path.dirname(mod.__file__))
            grant_paths.add(_REPO_ROOT)
            from tests.common import bin_location  # noqa: PLC0415

            grant_paths.add(bin_location)

            for path in grant_paths:
                if path and os.path.exists(path):
                    subprocess.run(
                        ["icacls", path, "/grant", "*S-1-15-2-1:(OI)(CI)RX", "/T", "/Q"],
                        check=False,
                        capture_output=True,
                    )

            # Each granted path must also be reachable: every ancestor directory
            # needs traverse rights for the AppContainer, otherwise CreateProcessW
            # cannot resolve sys.executable and fails with ACCESS_DENIED. Grant
            # (RX) without OI/CI so it applies to that directory only (no
            # recursion into siblings/contents).
            ancestors: set[str] = set()
            for path in grant_paths:
                if not path:
                    continue
                cur = os.path.abspath(path)
                while True:
                    parent = os.path.dirname(cur)
                    if not parent or parent == cur:
                        break
                    ancestors.add(parent)
                    cur = parent
            for ancestor in ancestors - grant_paths:
                if os.path.exists(ancestor):
                    subprocess.run(
                        ["icacls", ancestor, "/grant", "*S-1-15-2-1:(RX)", "/Q"],
                        check=False,
                        capture_output=True,
                    )

            # ---- 3) Scratch dir the child can write to (LMDB output, temp). ---- #
            scratch = tempfile.mkdtemp(prefix="angr_rtdb_ac_")
            self.addCleanup(_safe_rmtree, scratch)
            subprocess.run(
                ["icacls", scratch, "/grant", "*S-1-15-2-1:(OI)(CI)F", "/T", "/Q"],
                check=False,
                capture_output=True,
            )

            # ---- 4) Capture the child's stdout/stderr via inheritable temp files. ---- #
            stdout_path = os.path.join(scratch, "stdout.txt")
            stderr_path = os.path.join(scratch, "stderr.txt")
            stdout_h = _open_inheritable_for_writing(kernel32, stdout_path, HANDLE_FLAG_INHERIT)
            stderr_h = _open_inheritable_for_writing(kernel32, stderr_path, HANDLE_FLAG_INHERIT)

            # ---- 5) Build proc-thread attribute list with security capabilities. ---- #
            capabilities = SECURITY_CAPABILITIES(
                AppContainerSid=sid, Capabilities=None, CapabilityCount=0, Reserved=0
            )

            size = ctypes.c_size_t(0)
            kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
            attr_buf = (ctypes.c_byte * size.value)()
            ok = kernel32.InitializeProcThreadAttributeList(attr_buf, 1, 0, ctypes.byref(size))
            self.assertTrue(ok, f"InitializeProcThreadAttributeList failed: {ctypes.get_last_error()}")

            try:
                ok = kernel32.UpdateProcThreadAttribute(
                    attr_buf,
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                    ctypes.byref(capabilities),
                    ctypes.sizeof(capabilities),
                    None,
                    None,
                )
                self.assertTrue(ok, f"UpdateProcThreadAttribute failed: {ctypes.get_last_error()}")

                # ---- 6) Build env block (UTF-16, double-null terminated). ---- #
                env = os.environ.copy()
                env["RTDB_BASE"] = scratch
                env["TMP"] = scratch
                env["TEMP"] = scratch
                env_str = "\0".join(f"{k}={v}" for k, v in env.items()) + "\0\0"
                env_buf = ctypes.create_unicode_buffer(env_str, len(env_str))

                # ---- 7) CreateProcessW into the AppContainer. ---- #
                argv = [
                    sys.executable,
                    "-m",
                    "tests.knowledge_plugins.test_rtdb_win_appcontainer",
                    "--core",
                ]
                cmdline = subprocess.list2cmdline(argv)
                cmd_buf = ctypes.create_unicode_buffer(cmdline)

                si = STARTUPINFOEXW()
                si.StartupInfo.cb = ctypes.sizeof(si)
                si.StartupInfo.dwFlags = STARTF_USESTDHANDLES
                si.StartupInfo.hStdInput = wintypes.HANDLE(0)
                si.StartupInfo.hStdOutput = stdout_h
                si.StartupInfo.hStdError = stderr_h
                si.lpAttributeList = ctypes.cast(attr_buf, ctypes.c_void_p)

                pi = PROCESS_INFORMATION()
                ok = kernel32.CreateProcessW(
                    None,
                    cmd_buf,
                    None,
                    None,
                    True,  # bInheritHandles — needed for the stdout/stderr handles
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                    ctypes.cast(env_buf, ctypes.c_void_p),
                    ctypes.c_wchar_p(_REPO_ROOT),
                    ctypes.byref(si),
                    ctypes.byref(pi),
                )
                if not ok:
                    err = ctypes.get_last_error()
                    self.fail(
                        f"CreateProcessW into AppContainer failed (GetLastError={err}). "
                        f"This usually means the AppContainer cannot read sys.executable "
                        f"or its DLLs; check that ALL APPLICATION PACKAGES has access."
                    )

                try:
                    kernel32.WaitForSingleObject(pi.hProcess, INFINITE)
                    exit_code = wintypes.DWORD(0)
                    kernel32.GetExitCodeProcess(pi.hProcess, ctypes.byref(exit_code))
                finally:
                    kernel32.CloseHandle(pi.hProcess)
                    kernel32.CloseHandle(pi.hThread)
                    kernel32.CloseHandle(stdout_h)
                    kernel32.CloseHandle(stderr_h)

                if exit_code.value != 0:
                    out = _read_text(stdout_path)
                    err = _read_text(stderr_path)
                    self.fail(
                        f"Core test failed inside AppContainer (exit={exit_code.value}).\n"
                        f"--- child stdout ---\n{out}\n"
                        f"--- child stderr ---\n{err}"
                    )
            finally:
                kernel32.DeleteProcThreadAttributeList(attr_buf)
        finally:
            # CreateAppContainerProfile / DeriveAppContainerSidFromAppContainerName allocate
            # a SID via the COM allocator; FreeSid is the documented cleanup.
            if sid.value:
                ctypes.WinDLL("advapi32", use_last_error=True).FreeSid(sid)


def _open_inheritable_for_writing(kernel32, path: str, handle_flag_inherit: int):
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    CREATE_ALWAYS = 2
    FILE_ATTRIBUTE_NORMAL = 0x80
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    sa = SECURITY_ATTRIBUTES(
        nLength=ctypes.sizeof(SECURITY_ATTRIBUTES),
        lpSecurityDescriptor=None,
        bInheritHandle=True,
    )
    kernel32.CreateFileW.restype = wintypes.HANDLE
    h = kernel32.CreateFileW(
        ctypes.c_wchar_p(path),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        ctypes.byref(sa),
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if h == INVALID_HANDLE_VALUE or h is None:
        raise OSError(f"CreateFileW({path!r}) failed: {ctypes.get_last_error()}")
    kernel32.SetHandleInformation(h, handle_flag_inherit, handle_flag_inherit)
    return wintypes.HANDLE(h)


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError as exc:
        return f"<could not read {path}: {exc}>"


def _safe_rmtree(path: str) -> None:
    import shutil  # noqa: PLC0415

    shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--core":
        _core_test()
    else:
        unittest.main()
