#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
"""CFGFast's scan-time function bookkeeping in Rust (ScanState.take_completed, ReturningAnalyzer) against Python."""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.cfg"  # pylint:disable=redefined-builtin

import io
import os
import unittest
from unittest import mock

import angr
from angr.analyses.cfg.cfg_base import CFGBase
from angr.analyses.cfg.cfg_fast import CFGFast
from tests.common import bin_location

from .test_cfg_make_functions import _run

test_location = os.path.join(bin_location, "tests")

# 0x400000: call 0x400040; call 0x400050; call 0x400060; ret
# 0x400040: jmp rax
# 0x400050: jmp [rip+0x2a]      (slot 0x400080 -> 0x400040)
# 0x400060: bnd jmp [rip+0x21]  (slot 0x400088 -> 0x400040)
XFG_BLOB = (
    bytes.fromhex("e83b000000e846000000e851000000c3").ljust(0x40, b"\xcc")
    + bytes.fromhex("ffe0").ljust(0x10, b"\xcc")
    + bytes.fromhex("ff252a000000").ljust(0x10, b"\xcc")
    + bytes.fromhex("f2ff2521000000").ljust(0x20, b"\xcc")
    + (0x400040).to_bytes(8, "little") * 2
)


def _project(path):
    if isinstance(path, bytes):
        return angr.Project(
            io.BytesIO(path),
            main_opts={"backend": "blob", "arch": "amd64", "base_addr": 0x400000, "entry_point": 0x400000},
            auto_load_libs=False,
        )
    return angr.Project(path, auto_load_libs=False)


class TestCompletedFilter(unittest.TestCase):
    flag = "_rust_completed_filter"

    def _check(self, path, **kwargs):
        expected = _run(path, False, self.flag, **kwargs)
        actual = _run(path, True, self.flag, **kwargs)
        assert expected.keys() == actual.keys()
        for k, v in expected.items():
            assert actual[k] == v, k
        return actual

    def test_x86_64(self):
        self._check(os.path.join(test_location, "x86_64", "fauxware"), normalize=True)

    def test_i386(self):
        self._check(os.path.join(test_location, "i386", "fauxware"), normalize=True)

    def test_xfg_dispatch_patterns(self):
        snap = self._check(XFG_BLOB, normalize=True)
        jmp_rax = {f[0] for f in snap["funcs"] if '"jmp_rax": true' in f[10]}
        assert jmp_rax == {0x400040, 0x400050}

    def test_skipped_calls_have_no_effect(self):
        orig_fc = CFGFast._function_completed
        orig_mcf = CFGFast._make_completed_functions
        called: list[int] = []
        counts = {"skipped": 0}

        def state(cfg, addr):
            fm = cfg.kb.functions
            g = fm.get_by_addr(addr)._graph
            keys = {k: sorted(v) for k, v in fm.get_key_func_type_and_addrs().items()}
            return dict(fm.get_by_addr(addr).info), keys, g.block_size(addr), g.local_count()

        def fc(self, func_addr):
            called.append(func_addr)
            orig_fc(self, func_addr)

        def mcf(self):
            fresh = [a for a in self._scan.finished_functions() if a not in self._completed_functions]
            del called[:]
            orig_mcf(self)
            done = set(called)
            for a in fresh:
                assert a in self._completed_functions
                if a in done or not self.kb.functions.contains_addr(a):
                    continue
                counts["skipped"] += 1
                before = state(self, a)
                orig_fc(self, a)
                assert state(self, a) == before, hex(a)

        for path in (os.path.join(test_location, "x86_64", "fauxware"), XFG_BLOB):
            proj = _project(path)
            # the patched methods are CFGFast's own attributes, so the Rust filter stays on
            with (
                mock.patch.object(CFGFast, "_make_completed_functions", mcf),
                mock.patch.object(CFGFast, "_function_completed", fc),
            ):
                cfg = proj.analyses.CFGFast(normalize=True)
            assert isinstance(cfg._completed_functions, set)
        assert counts["skipped"] > 0

    def test_python_path_when_function_completed_is_overridden(self):
        def run(rust: bool) -> list[int]:
            calls: list[int] = []

            class CFGFastHooked(CFGFast):
                def _function_completed(self, func_addr: int):
                    calls.append(func_addr)
                    super()._function_completed(func_addr)

            proj = _project(os.path.join(test_location, "x86_64", "fauxware"))
            with mock.patch.object(CFGFast, self.flag, rust):
                cfg = proj.analyses[CFGFastHooked].prep()(normalize=True)
            assert cfg._completed_filter is None
            return calls

        calls = run(True)
        # every finished function is completed exactly once, as on the Python path
        assert calls == run(False)
        assert len(calls) == len(set(calls)) > 0


class TestReturningAnalyzer(unittest.TestCase):
    flag = "_rust_returning"

    def _check(self, path, **kwargs):
        expected = _run(path, False, self.flag, **kwargs)
        actual = _run(path, True, self.flag, **kwargs)
        assert expected.keys() == actual.keys()
        for k, v in expected.items():
            assert actual[k] == v, k

    def test_x86_64(self):
        self._check(os.path.join(test_location, "x86_64", "fauxware"), normalize=True)

    def test_armel(self):
        self._check(os.path.join(test_location, "armel", "fauxware"), normalize=True)

    def test_mips(self):
        self._check(os.path.join(test_location, "mips", "fauxware"), normalize=True)

    def test_every_call_matches_python(self):
        calls = {"n": 0}

        def aff(self, all_funcs_completed=False):
            analyzer = self._returning_analyzer
            assert analyzer is not None and self.kb.functions is self._returning_manager
            store = self.kb.functions.store
            ret, noret = analyzer.analyze(list(self._updated_nonreturning_functions), all_funcs_completed)
            for a in ret + noret:
                store.set_returning(a, None)
            py = CFGBase._analyze_function_features(self, all_funcs_completed=all_funcs_completed)
            assert (py["functions_return"], py["functions_do_not_return"]) == (ret, noret)
            calls["n"] += 1
            return py

        for arch in ("x86_64", "armel", "mips"):
            proj = _project(os.path.join(test_location, arch, "fauxware"))
            # only the scan-time calls go through the override; post-analysis runs on the final manager
            with (
                mock.patch.object(CFGFast, "_analyze_function_features", aff),
                mock.patch.object(CFGFast, "_post_analysis", lambda self: None),
            ):
                proj.analyses.CFGFast(normalize=True)
        assert calls["n"] > 0

    def test_python_path_when_determine_is_overridden(self):
        class CFGFastHooked(CFGFast):
            def _determine_function_returning(self, func, all_funcs_completed=False):
                return super()._determine_function_returning(func, all_funcs_completed=all_funcs_completed)

        proj = _project(os.path.join(test_location, "x86_64", "fauxware"))
        with mock.patch.object(CFGFast, "_post_analysis", lambda self: None):
            cfg = proj.analyses[CFGFastHooked].prep()(normalize=True)
        assert cfg._returning_analyzer is None
        assert cfg._scan is not None


if __name__ == "__main__":
    unittest.main()
