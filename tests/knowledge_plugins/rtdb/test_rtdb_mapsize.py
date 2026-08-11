#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,protected-access
"""Test cases for growing the RuntimeDb LMDB map."""

from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.rtdb"  # pylint:disable=redefined-builtin

import os
import tempfile
import unittest

import lmdb

from angr.errors import AngrRuntimeDbError
from angr.knowledge_base import KnowledgeBase
from angr.knowledge_plugins.rtdb.rtdb import RuntimeDb


class TestRuntimeDbMapSize(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()  # pylint:disable=consider-using-with
        # A project-less knowledge base is enough: an explicit lmdb_path means the RuntimeDb never consults it.
        self.rtdb = RuntimeDb(KnowledgeBase(None), lmdb_path=os.path.join(self._tmpdir.name, "rtdb"))
        self.rtdb._lmdb_mapsize = 1024 * 1024
        self.db_name = self.rtdb.open_db("functions")

    def tearDown(self):
        self.rtdb.cleanup()
        self._tmpdir.cleanup()

    def _fill(self, record_count: int) -> dict[bytes, bytes]:
        """
        Write record_count records, growing the map whenever it fills up, and return them.
        """
        records: dict[bytes, bytes] = {}
        written = 0
        while written < record_count:
            batch = {str(i).encode(): os.urandom(512) for i in range(written, min(written + 100, record_count))}
            try:
                with self.rtdb.begin_txn(self.db_name, write=True) as txn:
                    for key, value in batch.items():
                        txn.put(key, value)
            except lmdb.MapFullError:
                self.rtdb.increase_lmdb_map_size()
                continue
            records.update(batch)
            written += len(batch)
        return records

    def test_map_grows_while_no_transaction_is_open(self):
        mapsize_before = self.rtdb._lmdb_mapsize
        records = self._fill(4000)

        assert self.rtdb._lmdb_mapsize > mapsize_before, "the map should have had to grow to fit 4000 records"
        with self.rtdb.begin_txn(self.db_name) as txn:
            for key, value in records.items():
                assert txn.get(key) == value

    def test_map_does_not_grow_under_an_open_transaction(self):
        """
        Growing the map unmaps and remaps the environment, which invalidates everything a still-open transaction
        holds into the old mapping, so the RuntimeDb has to refuse instead.
        """
        records = self._fill(4000)

        with self.rtdb.begin_txn(self.db_name) as txn:
            with self.assertRaises(AngrRuntimeDbError):
                self.rtdb.increase_lmdb_map_size()
            # the transaction is intact because the environment was left alone
            for key, value in records.items():
                assert txn.get(key) == value

        # ... and once it is closed the map can grow again
        self.rtdb.increase_lmdb_map_size()

    def test_open_transactions_are_counted_back_down(self):
        assert self.rtdb._open_txns == 0
        with self.rtdb.begin_txn(self.db_name, write=True) as txn:
            txn.put(b"1", b"a")
            assert self.rtdb._open_txns == 1
        assert self.rtdb._open_txns == 0

        # and the count comes back down when the body raises, too
        with self.assertRaises(RuntimeError), self.rtdb.begin_txn(self.db_name):
            assert self.rtdb._open_txns == 1
            raise RuntimeError("boom")
        assert self.rtdb._open_txns == 0

    def test_an_unentered_transaction_is_not_counted(self):
        """A transaction is opened by entering the context manager, so one that is never entered holds nothing."""
        self.rtdb.begin_txn(self.db_name, write=True)
        assert self.rtdb._open_txns == 0
        self.rtdb.increase_lmdb_map_size()

    def test_reopening_the_environment_clears_the_count(self):
        """
        A forked child inherits the transaction count of every thread that did not come along with it, against an
        environment it is about to replace. Those transactions can never be closed, so the count goes with them.
        """
        self.rtdb.begin_txn(self.db_name).__enter__()  # pylint:disable=unnecessary-dunder-call
        assert self.rtdb._open_txns == 1

        self.rtdb.reopen_lmdb()

        assert self.rtdb._open_txns == 0
        self.rtdb.increase_lmdb_map_size()
        with self.rtdb.begin_txn(self.db_name, write=True) as txn:
            txn.put(b"1", b"a")


if __name__ == "__main__":
    unittest.main()
