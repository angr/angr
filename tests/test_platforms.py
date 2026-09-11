from __future__ import annotations

import importlib
import sys

import pytest

import angr.utils.lmdb as lmdb_utils


def test_lmdb_emscripten_fallback(monkeypatch):
    try:
        with monkeypatch.context() as patch:
            patch.setattr(sys, "platform", "emscripten")
            importlib.reload(lmdb_utils)

            assert not lmdb_utils.lmdb_available
            assert lmdb_utils.lmdb.Error is lmdb_utils.lmdb.MapFullError
            with pytest.raises(lmdb_utils.lmdb.Error, match="LMDB is not available"):
                lmdb_utils.lmdb.open("unused")
    finally:
        importlib.reload(lmdb_utils)
