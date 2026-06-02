from __future__ import annotations

import contextlib
import functools
import logging
import os
import shutil
import sys
import tempfile
import uuid
import weakref
from collections import defaultdict
from typing import TYPE_CHECKING, Any

import lmdb

from angr.errors import AngrRuntimeDbError
from angr.knowledge_plugins.plugin import KnowledgeBasePlugin

if TYPE_CHECKING:
    from angr.knowledge_base import KnowledgeBase

RTDB_BASEDIR: str | None = os.environ.get("RTDB_BASE")


l = logging.getLogger(__name__)


@functools.cache
def _is_windows_appcontainer() -> bool:
    """
    Detect whether the current process is running inside a Windows AppContainer.

    AppContainer processes cannot access the ``Global\\`` kernel namespace, so
    LMDB's ``CreateMutexA``-based cross-process locking fails with a misleading
    ``Input/output error`` (see angr/angr#6391). When this returns ``True`` the
    caller should pass ``lock=False`` (``MDB_NOLOCK``) to ``lmdb.open``.
    """
    if sys.platform != "win32":
        return False

    import ctypes  # pylint:disable=import-outside-toplevel
    from ctypes import wintypes  # pylint:disable=import-outside-toplevel

    TOKEN_QUERY = 0x0008
    TokenIsAppContainer = 29  # TOKEN_INFORMATION_CLASS

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    except OSError:
        return False

    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
        return False
    try:
        is_app_container = wintypes.DWORD(0)
        return_length = wintypes.DWORD(0)
        if not advapi32.GetTokenInformation(
            token,
            TokenIsAppContainer,
            ctypes.byref(is_app_container),
            ctypes.sizeof(is_app_container),
            ctypes.byref(return_length),
        ):
            return False
        return is_app_container.value != 0
    finally:
        kernel32.CloseHandle(token)


class RuntimeDbForkCondom:
    """
    A class that invokes RuntimeDb.reopen_lmdb() upon forking. This is necessary to ensure that lmdb does not raise
    ReaderFullError in forked child processes. The reopen_rtdb() method is not called on Windows because
    os.register_at_fork does not exist on Windows.
    """

    def __init__(self, rtdb: RuntimeDb):
        self.rtdb = weakref.proxy(rtdb)
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self.reopen_rtdb)

    def reopen_rtdb(self):
        if self.rtdb is None:
            return
        try:
            self.rtdb.reopen_lmdb()
        except ReferenceError:
            self.rtdb = None


class RuntimeDb(KnowledgeBasePlugin):
    """
    External storage-backed database for angr knowledge base plugins.
    """

    def __init__(self, kb: KnowledgeBase, lmdb_path: str | None = None) -> None:
        super().__init__(kb)

        self._lmdb_path: str | None = lmdb_path
        self._lmdb_env: lmdb.Environment | None = None
        self._lmdb_mapsize: int = 1024 * 1024 * 10
        self._dbnames: defaultdict[str, int] = defaultdict(int)
        self._dbs: dict[str, Any] = {}
        self._condom = RuntimeDbForkCondom(self)

    def __del__(self):
        self.cleanup()

    def __getstate__(self):
        # We drop the following items:
        # - _lmdb_env, which is an unpicklable lmdb.Environment
        # - _dbs, which holds LMDB DB handles
        # - _condom, which holds a weakref.proxy and a registered fork callback
        # - _lmdb_path, which is the path for the currently opened LMDB
        #
        # Spilling dicts flush their data to memory before pickling, so dropping the
        # live LMDB state is safe: a fresh environment will be created lazily on next use.
        state = self.__dict__.copy()
        for key in ("_lmdb_env", "_dbs", "_dbnames", "_condom", "_lmdb_path"):
            state.pop(key, None)
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self._lmdb_path = None
        self._lmdb_env = None
        self._dbs = {}
        self._dbnames = defaultdict(int)
        self._condom = RuntimeDbForkCondom(self)

    def _init_lmdb(self):
        if self._lmdb_env is not None:
            return

        if self._lmdb_path is not None:
            # may fail and raise exceptions
            self._lmdb_env = self._attempt_creating_lmdb(self._lmdb_path)
        else:
            r = self._init_lmdb_attempt_multipele_locations()
            if r is None:
                raise AngrRuntimeDbError("Failed to initialize the LMDB environment.")
            self._lmdb_path, self._lmdb_env = r

        l.debug("Initialized LRU cache LMDB at %s", self._lmdb_path)

    def _init_lmdb_attempt_multipele_locations(self) -> tuple[str, lmdb.Environment] | None:
        if self._lmdb_env is not None:
            return None

        main_binary_path = self._kb._project.loader.main_object.binary
        basename = os.path.basename(main_binary_path) if isinstance(main_binary_path, str) else "angr_proj"

        basedir = None
        if RTDB_BASEDIR is not None:
            basedir = RTDB_BASEDIR
            if not os.access(basedir, os.W_OK):
                l.error("The directory %s is not writable. Falling back.", basedir)
                basedir = None
            else:
                db_filename = self._get_unique_db_filename(basedir, basename)
                lmdb_path = os.path.join(basedir, db_filename)
                lmdb_env = self._attempt_creating_lmdb(lmdb_path)
                if lmdb_env is not None:
                    return lmdb_path, lmdb_env
                basedir = None
                db_filename = None

        if basedir is None and isinstance(main_binary_path, str):
            # get the base directory of the project binary
            basedir = os.path.dirname(os.path.abspath(main_binary_path))
            # is the location writable?
            if not os.access(basedir, os.W_OK):
                l.error("The directory %s is not writable. Falling back to temporary directory.", basedir)
                basedir = None
            else:
                db_filename = self._get_unique_db_filename(basedir, basename)
                lmdb_path = os.path.join(basedir, db_filename)
                lmdb_env = self._attempt_creating_lmdb(lmdb_path)
                if lmdb_env is not None:
                    return lmdb_path, lmdb_env
                basedir = None
                db_filename = None

        if basedir is None:
            basedir = tempfile.gettempdir()
            if not os.access(basedir, os.W_OK):
                raise OSError("No writable directory found for RTDB storage.")
            db_filename = self._get_unique_db_filename(basedir, basename)
            lmdb_path = os.path.join(basedir, db_filename)
            lmdb_env = self._attempt_creating_lmdb(lmdb_path)
            if lmdb_env is not None:
                return lmdb_path, lmdb_env
            raise OSError("No writable directory found for RTDB storage.")

        return None

    def _attempt_creating_lmdb(self, lmdb_path: str):
        """
        Attempt to create the LMDB environment.
        """
        if self._lmdb_env is not None:
            return None

        kwargs: dict[str, Any] = {"sync": False, "map_size": self._lmdb_mapsize, "max_dbs": 10}
        if _is_windows_appcontainer():
            # AppContainer processes cannot access the ``Global\`` namespace used by LMDB's
            # cross-process mutex; ``MDB_NOLOCK`` is safe because RuntimeDb is single-process.
            kwargs["lock"] = False
        try:
            return lmdb.open(lmdb_path, **kwargs)
        except (PermissionError, OSError, lmdb.Error):
            return None

    @staticmethod
    def _get_unique_db_filename(basedir: str, basename: str) -> str:
        # find a unique rtdb name
        db_filename = basename + "_angr_rtdb"
        while True:
            db_path = os.path.join(basedir, db_filename)
            if not os.path.exists(db_path):
                break
            db_filename = basename + f"_angr_rtdb_{uuid.uuid4().hex}"
        return db_filename

    def _cleanup_lmdb(self):
        """
        Clean up LMDB resources.
        """
        if self._lmdb_env is not None:
            self._lmdb_env.close()
            self._lmdb_env = None

        if self._lmdb_path is not None:
            with contextlib.suppress(OSError):
                shutil.rmtree(self._lmdb_path)
            self._lmdb_path = None

    def _get_unique_dbname(self, base_name: str) -> str:
        count = self._dbnames[base_name]
        self._dbnames[base_name] += 1
        if count == 0:
            return base_name
        return f"{base_name}_{count}"

    def increase_lmdb_map_size(self) -> None:
        """
        Increase the LMDB map size.
        """
        if self._lmdb_env is None:
            return

        delta = min(self._lmdb_mapsize, 1024 * 1024 * 256)
        l.debug("Increasing LMDB map size by %d bytes", delta)
        self._lmdb_mapsize += delta
        self._lmdb_env.set_mapsize(self._lmdb_mapsize)

    def reopen_lmdb(self):
        """
        Reopen the existing LMDB environment and all open databases in self._dbs.
        """

        if self._lmdb_path is None:
            # we've never opened any LMDB before
            return

        if self._lmdb_env is not None:
            self._lmdb_env.close()
            self._lmdb_env = None

        self._init_lmdb()
        assert self._lmdb_env is not None

        for db_name in list(self._dbs):
            self._dbs[db_name] = self._lmdb_env.open_db(db_name.encode())

    def open_db(self, db_name: str, unique: bool = True) -> str:
        self._init_lmdb()
        assert self._lmdb_env is not None
        if unique:
            db_name = self._get_unique_dbname(db_name)
        if db_name in self._dbs:
            return db_name
        db = self._lmdb_env.open_db(db_name.encode())
        self._dbs[db_name] = db
        return db_name

    def begin_txn(self, db_name: str, write: bool = False):
        db = self._dbs[db_name]
        assert self._lmdb_env is not None
        return self._lmdb_env.begin(db=db, write=write)

    def drop_db(self, db_name: str) -> None:
        db = self._dbs[db_name]
        if self._lmdb_env is None:
            return
        with self._lmdb_env.begin(write=True) as txn:
            txn.drop(db)
        del self._dbs[db_name]

    def cleanup(self):
        self._cleanup_lmdb()


KnowledgeBasePlugin.register_default("rtdb", RuntimeDb)
