from __future__ import annotations

import importlib
import sys

import pytest

import angr


def test_platform_capabilities():
    assert angr.capabilities.emscripten == (sys.platform == "emscripten")
    assert angr.capabilities.ailment
    assert angr.capabilities.capstone
    assert angr.capabilities.vex
    assert angr.capabilities.z3


def test_lmdb_emscripten_fallback(monkeypatch):
    import angr.utils.lmdb as lmdb_utils

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
