# pylint: disable=missing-class-docstring,no-self-use
"""
Go signature versioning: kb.go_signatures.version ticks when inference changes a record, a decompilation remembers the
state it was based on, and the Decompiler runs the Clinic again when a run learned a signature it had built on.
"""

from __future__ import annotations

import re
import unittest

import angr
from angr.analyses.decompiler.decompilation_cache import DecompilationCache
from tests.common import load_project_with_scoped_cfg

from .test_go_decompiler import go_binary, go_func_addrs

IFACE = go_binary("go1.27.1", "iface_stripped")
# an interface method call whose string result the first run only learns about from the caller's reads
REPORT_CALL = r"(?:string\()?\w+\.field_0\.field_20\(\w+\.field_8\)"


class TestVersionTicksOnChange(unittest.TestCase):
    def test_version_ticks_only_on_change(self):
        proj = angr.Project(IFACE, auto_load_libs=False)
        sigs = proj.kb.go_signatures
        assert sigs.version == 0
        sigs.set_inferred("main.f", ["int"], results={0: ("string", 2)})
        assert sigs.version == 1
        # an equal record, directly or as the whole record (as the sweep's parent merges it)
        sigs.set_inferred("main.f", ["int"], results={0: ("string", 2)})
        sigs.set_inferred("main.f", dict(sigs.inferred_record("main.f")))
        assert sigs.version == 1
        sigs.set_inferred("main.f", caller_results={1: ("bool", 1)})
        assert sigs.version == 2
        sigs.set_closure_context(0x1000, "struct { F uintptr; X0 int }")
        sigs.set_closure_context(0x1000, "struct { F uintptr; X0 int }")
        assert sigs.version == 3
        sigs.set_callsite_inferred(0x2000, caller_results={0: ("error", 2)})
        sigs.set_callsite_inferred(0x2000, caller_results={0: ("error", 2)})
        assert sigs.version == 4
        assert sigs.record_version("main.f") == 2 and sigs.record_version("closure:0x1000") == 3
        assert sigs.record_version("nobody") == 0
        assert sigs.copy().version == 4

    def test_tracking_records_what_was_consulted(self):
        proj = angr.Project(IFACE, auto_load_libs=False)
        sigs = proj.kb.go_signatures
        sigs.set_inferred("main.f", ["int"])
        with sigs.track() as deps:
            sigs.inferred_record("main.f")
            sigs.inferred_record("main.g")
            sigs.closure_context(0x1000)
            with sigs.untracked():
                sigs.callsite_record(0x2000)
        assert deps == {"main.f": 1, "main.g": 0, "closure:0x1000": 0}
        assert sigs.deps_current(deps, 1)
        sigs.set_inferred("main.g", ["string"])
        assert not sigs.deps_current(deps, 1)
        assert not sigs.deps_current(deps, None)


class TestClinicRerun(unittest.TestCase):
    """main.report of the go1.27 interface binary: the result binder records the interface call's result words during
    the first Clinic run, after the call site was built."""

    @classmethod
    def setUpClass(cls):
        cls.addrs = go_func_addrs(IFACE, "main.report", "main.describe")

    def _project(self):
        return load_project_with_scoped_cfg(
            IFACE, self.addrs["main.report"], extra_func_addrs=[self.addrs["main.describe"]], call_tree_depth=1
        )

    def test_single_run_sets_the_flag(self):
        proj, cfg = self._project()
        dec = proj.analyses.Decompiler(
            self.addrs["main.report"], cfg=cfg.model, flavor="go", fail_fast=True, go_sigs_rerun=False
        )
        clinic = dec.clinic
        assert clinic.go_sigs_version == 0 and clinic.go_sigs_updated and clinic.go_sigs_stale
        assert proj.kb.go_signatures.version > 0
        assert dec.go_sigs_updated and dec.go_sigs_version == 0
        # the call site predates the record: the string result is read through a two-word temporary
        text = dec.codegen.text
        assert re.search(r"string\(\w+\.field_0\.field_20\(\w+\.field_8\)\)", text), text
        # a single run's output is stale by its own writes
        assert proj.kb.go_signatures.stale_decompilations() == [(self.addrs["main.report"], "go")]

    def test_rerun_reflects_what_the_first_run_learned(self):
        proj, cfg = self._project()
        sigs = proj.kb.go_signatures
        dec = proj.analyses.Decompiler(self.addrs["main.report"], cfg=cfg.model, flavor="go", fail_fast=True)
        assert dec.go_sigs_updated
        # the second run started from the records the first one wrote and changed nothing more
        assert dec.go_sigs_version == sigs.version and not dec.clinic.go_sigs_updated
        text = dec.codegen.text
        assert re.search(REPORT_CALL, text), text
        assert "uint128" not in text and "string{ptr:" not in text, text
        assert not re.search(r"^    var \w+ [^/]*// (rbx|rcx|rdi|rsi|r8|r9|r10|r11)$", text, re.MULTILINE), text

        # the cache remembers the state the output reflects
        cache = proj.kb.decompilations[(self.addrs["main.report"], "go")]
        assert cache.go_sigs_version == sigs.version and cache.go_sigs_deps == dec.clinic.go_sigs_deps
        assert sigs.is_current(cache) and sigs.stale_decompilations() == []
        sigs.set_inferred("main.nobody", ["int"])
        assert sigs.stale_decompilations() == []
        consulted = next(k for k in cache.go_sigs_deps if k.startswith("callsite:"))
        sigs.set_callsite_inferred(int(consulted[9:], 16), caller_results={0: ("[]byte", 3)})
        assert sigs.stale_decompilations() == [(self.addrs["main.report"], "go")]

    def test_cache_version_survives_serialization(self):
        proj, cfg = self._project()
        dec = proj.analyses.Decompiler(self.addrs["main.report"], cfg=cfg.model, flavor="go", fail_fast=True)
        cache = proj.kb.decompilations[(self.addrs["main.report"], "go")]
        cache.codegen = None  # the Go codegen is not serializable yet
        back = DecompilationCache.parse(cache.serialize(), project=proj, kb=proj.kb, function=dec.func)
        assert back.go_sigs_version == cache.go_sigs_version and back.go_sigs_deps == cache.go_sigs_deps
        assert proj.kb.go_signatures.is_current(back)
        # a cache from before versioning counts as stale
        old = DecompilationCache.parse(DecompilationCache(dec.func.addr).serialize())
        assert old.go_sigs_version is None and old.go_sigs_deps is None
        assert not proj.kb.go_signatures.is_current(old)


if __name__ == "__main__":
    unittest.main()
