from __future__ import annotations
from typing import TYPE_CHECKING
import os
import logging
import tempfile
import uuid
import contextlib
import shutil
from collections import defaultdict

import lmdb

from angr.knowledge_plugins.plugin import KnowledgeBasePlugin

if TYPE_CHECKING:
    from angr.knowledge_base import KnowledgeBase

RTDB_BASEDIR: str | None = os.environ.get("RTDB_BASE")


l = logging.getLogger(__name__)


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

    def __del__(self):
        self._cleanup_lmdb()

    def _init_lmdb(self):
        if self._lmdb_env is not None:
            return

        # Only generate the path once
        if self._lmdb_path is None:
            main_binary_path = self._kb._project.loader.main_object.binary
            basename = os.path.basename(main_binary_path) if isinstance(main_binary_path, str) else "angr_proj"

            basedir = None
            if RTDB_BASEDIR is not None:
                basedir = RTDB_BASEDIR
                if not os.access(basedir, os.W_OK):
                    l.error("The directory %s is not writable. Falling back.", basedir)
                    basedir = None

            if basedir is None and isinstance(main_binary_path, str):
                # get the base directory of the project binary
                basedir = os.path.dirname(os.path.abspath(main_binary_path))
                basename = os.path.basename(main_binary_path)
                # is the location writable?
                if not os.access(basedir, os.W_OK):
                    l.error("The directory %s is not writable. Falling back to temporary directory.", basedir)
                    basedir = None

            if basedir is None:
                basedir = tempfile.gettempdir()
                if not os.access(basedir, os.W_OK):
                    raise OSError("No writable directory found for RTDB storage.")

            db_filename = basename + "_angr_rtdb"
            # find a unique rtdb name
            while True:
                db_path = os.path.join(basedir, db_filename)
                if not os.path.exists(db_path):
                    break
                db_filename = basename + f"_angr_rtdb_{uuid.uuid4().hex}"

            self._lmdb_path = os.path.join(basedir, db_filename)

        self._lmdb_env = lmdb.open(self._lmdb_path, map_size=self._lmdb_mapsize, max_dbs=10)
        l.debug("Initialized LRU cache LMDB at %s", self._lmdb_path)

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

    def get_db(self, db_name: str, unique: bool = True):
        self._init_lmdb()
        assert self._lmdb_env is not None
        if unique:
            db_name = self._get_unique_dbname(db_name)
        return self._lmdb_env.open_db(db_name.encode())

    def begin_txn(self, db, write: bool = False):
        assert self._lmdb_env is not None
        return self._lmdb_env.begin(db=db, write=write)

    def drop_db(self, db) -> None:
        if self._lmdb_env is None:
            return
        with self._lmdb_env.begin(write=True) as txn:
            txn.drop(db)


KnowledgeBasePlugin.register_default("rtdb", RuntimeDb)
