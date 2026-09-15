# pylint:disable=missing-class-docstring,missing-function-docstring,no-self-use
"""
Tests for tail-call targets being recovered as separate functions.

``tailcall_dispatch_*`` are stripped PIE builds of tests_src/tailcall_dispatch.c: ``key_verify`` dispatches through a
jump table whose cases are ``jmp verify_x`` tail calls, and ``verify_a``..``verify_f`` are reached only through those
jumps. Without a boundary at each target, CFGFast absorbs all of them into ``key_verify``.

- ``tailcall_dispatch_nocet``: .eh_frame FDEs, no endbr64. Only the FDE boundaries split the targets.
- ``tailcall_dispatch_cet_nofde``: endbr64, no FDEs for the functions. Only the endbr64 heuristic splits them.
- ``tailcall_dispatch_cet``: both.
"""

from __future__ import annotations

import os
import unittest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests", "x86_64")

# nocet has a different layout after verify_c
CET_TARGETS = {0x4011C0, 0x401250, 0x4012E0, 0x401390, 0x401420, 0x4014B0}
NOCET_TARGETS = {0x4011C0, 0x401250, 0x4012E0, 0x401380, 0x401410, 0x4014A0}
KEY_VERIFY_COLD = 0x401050
CET_KEY_VERIFY = 0x401540
NOCET_KEY_VERIFY = 0x401530


class TestCfgFastEhFrameBoundaries(unittest.TestCase):
    def _cfg(self, binary: str, **kwargs):
        proj = angr.Project(os.path.join(test_location, binary), auto_load_libs=False)
        return proj.analyses.CFGFast(normalize=True, **kwargs)

    def test_fde_boundaries_split_tail_calls(self):
        cfg = self._cfg("tailcall_dispatch_nocet")
        assert set(cfg.kb.functions).issuperset(NOCET_TARGETS)
        key_verify = cfg.kb.functions[NOCET_KEY_VERIFY]
        assert not key_verify.block_addrs_set & NOCET_TARGETS
        assert all(cfg.kb.functions[addr].returning for addr in NOCET_TARGETS)

    def test_fde_boundaries_can_be_disabled(self):
        cfg = self._cfg("tailcall_dispatch_nocet", eh_frame_boundaries=False)
        # nothing else identifies these functions, so the tail-called targets are absorbed
        assert not NOCET_TARGETS & set(cfg.kb.functions)

    def test_endbr_targets_split_without_fdes(self):
        cfg = self._cfg("tailcall_dispatch_cet_nofde")
        assert set(cfg.kb.functions).issuperset(CET_TARGETS)
        assert not cfg.kb.functions[CET_KEY_VERIFY].block_addrs_set & CET_TARGETS

    def test_endbr_targets_split_with_boundaries_disabled(self):
        cfg = self._cfg("tailcall_dispatch_cet", eh_frame_boundaries=False)
        assert set(cfg.kb.functions).issuperset(CET_TARGETS)

    def test_cold_part_stays_with_its_function(self):
        # key_verify.cold has its own FDE but is only reached by a conditional jump from key_verify
        for binary, key_verify in (
            ("tailcall_dispatch_cet", CET_KEY_VERIFY),
            ("tailcall_dispatch_nocet", NOCET_KEY_VERIFY),
        ):
            cfg = self._cfg(binary)
            assert KEY_VERIFY_COLD not in cfg.kb.functions
            assert KEY_VERIFY_COLD in cfg.kb.functions[key_verify].block_addrs_set


if __name__ == "__main__":
    unittest.main()
