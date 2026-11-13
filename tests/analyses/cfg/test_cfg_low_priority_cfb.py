#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
"""CFGFast's Rust paths under angr-management's call: a CFBlanket, low_priority=True and a progress callback."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import os
import unittest
from unittest import mock

import angr
from angr.analyses.cfg import cfg_fast
from angr.analyses.cfg.cfg_fast import CFGFast
from tests.analyses.cfg.test_cfg_block import _digest
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _cfb_items(cfb) -> list:
    return [(a, type(o).__name__, getattr(o, "size", None), getattr(o, "thumb", None)) for a, o in cfb._blanket.items()]


class TestCFGFastLowPriorityCFB(unittest.TestCase):
    def _project(self, binary: str):
        return angr.Project(os.path.join(test_location, binary), auto_load_libs=False)

    def test_low_priority_stays_on_rust(self):
        proj = self._project("x86_64/fauxware")
        expected = _digest(proj.analyses.CFGFast(normalize=True))

        proj = self._project("x86_64/fauxware")
        release = mock.patch.object(CFGFast, "_release_gil", autospec=True, side_effect=CFGFast._release_gil)
        in_rust = mock.patch.object(
            CFGFast, "_make_functions_in_rust", autospec=True, side_effect=CFGFast._make_functions_in_rust
        )
        # a 1 ns budget makes the Rust scan return to the Python loop every BUDGET_CHECK_JOBS jobs
        with mock.patch.object(cfg_fast, "RUST_SCAN_BUDGET_NS", 1), release as rel, in_rust as mf:
            cfg = proj.analyses.CFGFast(normalize=True, low_priority=True)
        assert _digest(cfg) == expected
        assert cfg._block_scan_stats["rust"] > 0
        assert mf.call_count == 1
        assert rel.call_count > 0

    def _cfb_run(self, binary: str, rust: bool):
        proj = self._project(binary)
        cfb = proj.analyses.CFB(exclude_region_types={"kernel", "tls"})
        patches = [] if rust else [mock.patch.object(CFGFast, "_init_rust_lifter", return_value=None)]
        for p in patches:
            p.start()
        try:
            cfg = proj.analyses.CFGFast(
                normalize=True, low_priority=True, cfb=cfb, progress_callback=lambda *args, **kwargs: None
            )
        finally:
            for p in patches:
                p.stop()
        return cfg, cfb

    def _check_cfb(self, binary: str):
        cfg_rust, cfb_rust = self._cfb_run(binary, True)
        cfg_py, cfb_py = self._cfb_run(binary, False)
        assert cfg_rust._block_scan_stats["rust"] > 0
        assert cfg_py._block_scan_stats == {}
        assert _digest(cfg_rust) == _digest(cfg_py)
        assert _cfb_items(cfb_rust) == _cfb_items(cfb_py)
        blocks = [(a, o) for a, o in cfb_rust._blanket.items() if isinstance(o, angr.Block)]
        assert blocks
        py_blocks = dict(cfb_py._blanket.items())
        for a, o in blocks:
            assert o.bytes == py_blocks[a].bytes

    def test_cfb_x86_64(self):
        self._check_cfb("x86_64/fauxware")

    def test_cfb_armel(self):
        self._check_cfb("armel/fauxware")

    def test_abort_from_progress_callback(self):
        proj = self._project("x86_64/fauxware")
        full = proj.analyses.CFGFast(normalize=True).model.graph.number_of_nodes()

        proj = self._project("x86_64/fauxware")

        def progress(percentage, text=None, cfg=None):
            if cfg is not None:
                cfg.abort()

        # notify on every job so that the abort lands in the middle of the Rust scan
        with mock.patch.object(cfg_fast, "PROGRESS_NOTIFY_INTERVAL", 0):
            cfg = proj.analyses.CFGFast(normalize=True, low_priority=True, progress_callback=progress)
        assert cfg._block_scan_stats["rust"] > 0
        assert 0 < cfg.model.graph.number_of_nodes() < full


if __name__ == "__main__":
    unittest.main()
