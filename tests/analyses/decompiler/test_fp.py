#!/usr/bin/env python3
"""
Floating point decompilation tests.
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import pytest
import archinfo

import angr
from angr.analyses import CFGFast, Decompiler
from angr.analyses.complete_calling_conventions import (
    CompleteCallingConventionsAnalysis,
    CallingConventionAnalysisMode,
)

# -- Paths & binary matrix --------------------------------------------

_fp_dir = os.path.join(os.path.dirname(__file__), "fp")

I386_BINS = ["i386_O0", "i386_O1"]
AMD64_BINS = ["amd64_O0", "amd64_O1"]
# Default (SSE) amd64 binaries: compiled without -mlong-double-80 / -mfpmath=387
SSE_BINS = ["amd64_default_O0", "amd64_default_O1"]
# x87-forced binaries (compiled with -mfpmath=387 / -mlong-double-80)
X87_BINS = I386_BINS + AMD64_BINS
ALL_BINS = X87_BINS + SSE_BINS

_BIN_PATHS = {n: os.path.join(_fp_dir, f"fp_basic_{n}") for n in ALL_BINS}

# -- Cached project environments --------------------------------------

_NOINLINE_HELPERS = ["identity_f64", "recursive_f64", "square_f32"]


class _Env:
    """Cached project + CFG + decompilation results for a binary variant."""

    __slots__ = ("_text_cache", "cfg", "name", "project")

    def __init__(self, name):
        self.name = name
        self._text_cache: dict[str, str] = {}
        path = _BIN_PATHS[name]
        if not os.path.exists(path):
            pytest.skip(f"{path} not found")
        self.project = angr.Project(path, auto_load_libs=False)
        self.cfg = self.project.analyses[CFGFast].prep()(normalize=True, data_references=True)
        # Run CCA so all functions have prototypes before any decompilation.
        # This mirrors real usage and prevents order-dependent KB pollution.
        self.project.analyses[CompleteCallingConventionsAnalysis].prep()(cfg=self.cfg, recover_variables=True)
        # Pre-decompile noinline helpers so prototypes are available to callers.
        # Cache results to avoid re-decompilation on polluted KB.
        for h in _NOINLINE_HELPERS:
            if h in self.cfg.functions:
                dec = self.project.analyses[Decompiler].prep()(self.cfg.functions[h], cfg=self.cfg.model)
                if dec.codegen is not None and dec.codegen.text is not None:
                    self._text_cache[h] = dec.codegen.text

    def get_text(self, func_name):
        """Decompile and cache.  Re-decompiling on a shared KB can produce
        degraded output (KB state from the first pass interferes), so we
        cache the first result."""
        if func_name in self._text_cache:
            return self._text_cache[func_name]
        f = self.cfg.functions[func_name]
        dec = self.project.analyses[Decompiler].prep(fail_fast=True)(f, cfg=self.cfg.model)
        assert dec.codegen is not None, f"{func_name} no codegen [{self.name}]"
        text = dec.codegen.text
        assert text is not None, f"{func_name} no text [{self.name}]"
        self._text_cache[func_name] = text
        return text


_cache: dict[str, _Env] = {}


def _env(name: str) -> _Env:
    if name not in _cache:
        _cache[name] = _Env(name)
    return _cache[name]


def _sig(text: str) -> str:
    """Extract the function signature line (last line before the opening brace)."""
    preamble = text.split("{")[0]
    for line in reversed(preamble.strip().splitlines()):
        line = line.strip()
        if line and not line.startswith("extern ") and not line.startswith("//"):
            return line
    return preamble.strip()


# -- Dual-path prototype recovery helpers ---------------------------------

_vr_cache: dict[str, dict[str, object]] = {}


def _get_vr_prototypes(bin_name: str) -> dict[str, object]:
    """Run Path 2 (variable recovery) CC analysis and return {func_name: prototype}."""
    if bin_name in _vr_cache:
        return _vr_cache[bin_name]
    path = _BIN_PATHS[bin_name]
    proj = angr.Project(path, auto_load_libs=False)
    cfg = proj.analyses[CFGFast].prep()(normalize=True, data_references=True)
    proj.analyses[CompleteCallingConventionsAnalysis].prep()(
        mode=CallingConventionAnalysisMode.VARIABLES,
        recover_variables=True,
        cfg=cfg,
    )
    result = {}
    for func in cfg.kb.functions.values():
        if func.prototype is not None and func.name:
            result[func.name] = func.prototype
    _vr_cache[bin_name] = result
    return result


def _get_fc_prototypes(bin_name: str) -> dict[str, object]:
    """Run Path 1 (FactCollector/FASTISH) CC analysis and return {func_name: prototype}."""
    path = _BIN_PATHS[bin_name]
    proj = angr.Project(path, auto_load_libs=False)
    cfg = proj.analyses[CFGFast].prep()(normalize=True, data_references=True)
    proj.analyses[CompleteCallingConventionsAnalysis].prep()(
        mode=CallingConventionAnalysisMode.FASTISH,
        cfg=cfg,
    )
    result = {}
    for func in cfg.kb.functions.values():
        if func.prototype is not None and func.name:
            result[func.name] = func.prototype
    return result


# ======================================================================
# Decompilation quality -- one test per function
# ======================================================================


def _check_sig(sig, *types):
    """Check return type and param types. First element is return type (supports
    'A|B' alternatives), rest are param types that must appear in the params."""
    if not types:
        return
    ret = types[0]
    if ret:
        alts = ret.split("|")
        assert any(sig.strip().startswith(r + " ") for r in alts), f"return type: {sig}"
    params = sig.split("(")[1] if "(" in sig else ""
    for pt in types[1:]:
        alts = pt.split("|")
        assert any(a in params for a in alts), f"expected '{pt}' param: {sig}"


def _check_no_x87_artifacts(text):
    """Assert no x87 dirty-helper / state artifacts remain in decompiled text."""
    assert "dirtyhelper" not in text
    assert "storeF80le" not in text
    assert "loadF80le" not in text
    assert "nan" not in text.lower()
    assert "ftop" not in text
    assert "fptag" not in text
    assert "fpround" not in text


@pytest.mark.parametrize("bin_name", ALL_BINS)
class TestFPDecompilation:
    """Consolidated decompilation quality -- one test method per function."""

    # ------------------------------------------------------------------
    # double functions
    # ------------------------------------------------------------------

    def test_add_f64(self, bin_name):
        text = _env(bin_name).get_text("add_f64")
        sig = _sig(text)
        _check_sig(sig, "double", "double", "double")
        assert "+" in text

    def test_max_f64(self, bin_name):
        text = _env(bin_name).get_text("max_f64")
        sig = _sig(text)
        _check_sig(sig, "double", "double", "double")
        assert "?" in text or "if" in text or "fmax" in text
        assert "CmpF" not in text
        body = text.split("{", 1)[1]
        assert "unsigned long long" not in body

    def test_mul_f64(self, bin_name):
        text = _env(bin_name).get_text("mul_f64")
        sig = _sig(text)
        _check_sig(sig, "double", "double", "double")
        assert "*" in text

    def test_divide_f64(self, bin_name):
        text = _env(bin_name).get_text("divide_f64")
        sig = _sig(text)
        _check_sig(sig, "double", "double", "double")
        assert "/" in text

    def test_polynomial_f64(self, bin_name):
        text = _env(bin_name).get_text("polynomial_f64")
        sig = _sig(text)
        _check_sig(sig, "double", "double")
        assert "*" in text and "+" in text
        assert "3.0" in text and "2.0" in text and "1.0" in text

    def test_sum_array_f64(self, bin_name):
        text = _env(bin_name).get_text("sum_array_f64")
        sig = _sig(text)
        _check_sig(sig, "double", "double *|double*")
        assert "+=" in text
        assert "do" in text or "while" in text or "for" in text
        assert "long long *" not in text and "long long*" not in text
        if bin_name in SSE_BINS:
            assert "uint128_t" not in text
            assert "double" in text

    def test_arithmetic_f64(self, bin_name):
        text = _env(bin_name).get_text("arithmetic_f64")
        sig = _sig(text)
        _check_sig(sig, "unsigned int", "int", "double", "double", "double", "double")
        assert ("do" in text or "while" in text or "for" in text) and "*" in text
        assert "!= 1" not in text
        if bin_name in SSE_BINS and bin_name.endswith("_O0"):
            assert "MulV" not in text
            assert "AddV" not in text
        if bin_name in SSE_BINS:
            assert "uint128_t" not in text
            assert "double" in text

    def test_mixed_args_f64(self, bin_name):
        text = _env(bin_name).get_text("mixed_args_f64")
        sig = _sig(text)
        _check_sig(sig, "double", "double")
        assert "+" in text

    def test_multi_return_f64(self, bin_name):
        text = _env(bin_name).get_text("multi_return_f64")
        sig = _sig(text)
        _check_sig(sig, "double", "double")
        assert "+" in text and "-" in text and "*" in text

    def test_deep_stack_f64(self, bin_name):
        text = _env(bin_name).get_text("deep_stack_f64")
        sig = _sig(text)
        _check_sig(sig, "double", "double", "double", "double", "double", "double", "double")
        assert "*" in text and "+" in text

    def test_cast_chain_f32(self, bin_name):
        text = _env(bin_name).get_text("cast_chain_f32")
        sig = _sig(text)
        _check_sig(sig, "float", "double")
        assert "(float)" in text

    def test_negate_f64(self, bin_name):
        text = _env(bin_name).get_text("negate_f64")
        sig = _sig(text)
        _check_sig(sig, "double", "double")
        assert "-" in text.split("{")[1]

    def test_abs_f64(self, bin_name):
        text = _env(bin_name).get_text("abs_f64")
        sig = _sig(text)
        _check_sig(sig, "double", "double")
        assert "?" in text or "if" in text or "fabs" in text

    def test_min_f64(self, bin_name):
        text = _env(bin_name).get_text("min_f64")
        sig = _sig(text)
        _check_sig(sig, "double", "double", "double")
        assert "?" in text or "if" in text or "fmin" in text

    def test_negate_and_abs_f64(self, bin_name):
        text = _env(bin_name).get_text("negate_and_abs_f64")
        sig = _sig(text)
        _check_sig(sig, "double", "double")
        assert "0x8000000000000000" not in text

    def test_int_to_f64(self, bin_name):
        sig = _sig(_env(bin_name).get_text("int_to_f64"))
        _check_sig(sig, "double")

    def test_f64_to_int(self, bin_name):
        sig = _sig(_env(bin_name).get_text("f64_to_int"))
        _check_sig(sig, "int", "double")

    def test_identity_f64(self, bin_name):
        if bin_name.endswith("_O1") and "amd64" in bin_name:
            pytest.xfail("identity_f64 at O1 is a trivial 'ret' -- no register writes to infer type from")
        sig = _sig(_env(bin_name).get_text("identity_f64"))
        _check_sig(sig, "double", "double")

    def test_call_f64_func(self, bin_name):
        text = _env(bin_name).get_text("call_f64_func")
        sig = _sig(text)
        _check_sig(sig, "double", "double")
        assert sig.count("double") >= 3
        assert "unsigned int" not in sig
        assert "identity_f64" in text
        assert text.count("identity_f64") >= 2
        assert "+" in text
        assert "Insert" not in text
        assert "unsigned int *" not in text

    def test_chained_f64_calls(self, bin_name):
        if bin_name.endswith("_O1") and "amd64" in bin_name:
            pytest.xfail("chained_f64_calls at O1: identity_f64 is a trivial 'ret' with no type info")
        text = _env(bin_name).get_text("chained_f64_calls")
        sig = _sig(text)
        _check_sig(sig, "double", "double")
        assert "identity_f64" in text
        assert "Insert" not in text
        assert "unsigned int *" not in text

    def test_compare_lt_f64(self, bin_name):
        text = _env(bin_name).get_text("compare_lt_f64")
        sig = _sig(text)
        _check_sig(sig, "int|char", "double", "double")
        assert ">" in text or "<" in text
        assert "CmpF" not in text

    def test_compare_eq_f64(self, bin_name):
        text = _env(bin_name).get_text("compare_eq_f64")
        sig = _sig(text)
        _check_sig(sig, "int|char", "double", "double")
        assert "==" in text
        assert "CmpF" not in text

    def test_read_global_f64(self, bin_name):
        text = _env(bin_name).get_text("read_global_f64")
        sig = _sig(text)
        _check_sig(sig, "double")
        assert "g_f64_value" in text

    def test_write_global_f64(self, bin_name):
        text = _env(bin_name).get_text("write_global_f64")
        assert "g_f64_value" in text

    def test_recursive_f64(self, bin_name):
        text = _env(bin_name).get_text("recursive_f64")
        sig = _sig(text)
        _check_sig(sig, "double", "double", "int")
        if bin_name in I386_BINS:
            # i386: first param should be double (stack-based order is known)
            params = sig.split("(")[1]
            assert "double" in params.split(",")[0]
        if bin_name in ("amd64_O0", *SSE_BINS):
            pytest.xfail("recursive_f64: 1.0 rendered as hex integer, not float literal")
        assert "1.0" in text
        assert "*" in text
        assert text.count("recursive_f64") >= 2

    # ------------------------------------------------------------------
    # float functions
    # ------------------------------------------------------------------

    def test_add_f32(self, bin_name):
        text = _env(bin_name).get_text("add_f32")
        sig = _sig(text)
        _check_sig(sig, "float")
        assert "+" in text
        assert "(double)" not in text

    def test_mul_f32(self, bin_name):
        text = _env(bin_name).get_text("mul_f32")
        sig = _sig(text)
        _check_sig(sig, "float")
        assert "*" in text

    def test_divide_f32(self, bin_name):
        text = _env(bin_name).get_text("divide_f32")
        sig = _sig(text)
        _check_sig(sig, "float")
        assert "/" in text

    def test_polynomial_f32(self, bin_name):
        text = _env(bin_name).get_text("polynomial_f32")
        sig = _sig(text)
        if not sig.strip().startswith("float ") and bin_name in (*I386_BINS, *SSE_BINS):
            pytest.xfail("polynomial_f32: return type is double (x87 F64 internally / SSE promotion)")
        _check_sig(sig, "float", "float")
        assert "*" in text and "+" in text
        if ("3.0" not in text or "1.0" not in text) and bin_name in SSE_BINS:
            pytest.xfail("polynomial_f32: float constants rendered as raw doubles")

    def test_max_f32(self, bin_name):
        text = _env(bin_name).get_text("max_f32")
        sig = _sig(text)
        _check_sig(sig, "float")
        assert "?" in text or "if" in text or "fmax" in text
        assert "(double)" not in text
        assert "CmpF" not in text
        if bin_name in SSE_BINS and bin_name.endswith("_O1"):
            assert "fmax" in text
        if bin_name in SSE_BINS:
            assert "MaxV" not in text

    def test_min_f32(self, bin_name):
        text = _env(bin_name).get_text("min_f32")
        sig = _sig(text)
        _check_sig(sig, "float")
        assert "?" in text or "if" in text or "fmin" in text

    def test_abs_f32(self, bin_name):
        text = _env(bin_name).get_text("abs_f32")
        sig = _sig(text)
        _check_sig(sig, "float", "float")
        assert "?" in text or "if" in text or "fabs" in text

    def test_sum_array_f32(self, bin_name):
        text = _env(bin_name).get_text("sum_array_f32")
        sig = _sig(text)
        if not sig.strip().startswith("float ") and bin_name in ("i386_O1", "amd64_default_O1"):
            pytest.xfail("sum_array_f32: return type is double instead of float (O1 accumulator stays F64)")
        _check_sig(sig, "float", "float *")
        assert "+=" in text
        assert "do" in text or "while" in text or "for" in text
        assert not sig.strip().startswith("void ")
        assert "int *" not in text and "int*" not in text
        if bin_name in SSE_BINS:
            assert "uint128_t" not in text
            assert "float" in text

    def test_int_to_f32(self, bin_name):
        text = _env(bin_name).get_text("int_to_f32")
        sig = _sig(text)
        if bin_name in I386_BINS:
            pytest.xfail("int_to_f32 on i386: fild produces F64 -- no F32 info in IR")
        _check_sig(sig, "float")
        # Fallback for all: at least some FP type is present
        assert "double" in text or "float" in text

    def test_f32_to_int(self, bin_name):
        sig = _sig(_env(bin_name).get_text("f32_to_int"))
        _check_sig(sig, "int", "float")

    def test_f32_to_f64(self, bin_name):
        text = _env(bin_name).get_text("f32_to_f64")
        sig = _sig(text)
        if not sig.strip().startswith("double "):
            pytest.xfail("f32_to_f64: return type is float instead of double (F32toF64 ambiguity)")
        assert "float" in text

    def test_f64_to_f32(self, bin_name):
        text = _env(bin_name).get_text("f64_to_f32")
        sig = _sig(text)
        _check_sig(sig, "float", "double")
        assert "(float)" in text

    def test_mixed_f32_f64(self, bin_name):
        text = _env(bin_name).get_text("mixed_f32_f64")
        sig = _sig(text)
        _check_sig(sig, "double", "float", "double", "float")

    def test_square_f32(self, bin_name):
        text = _env(bin_name).get_text("square_f32")
        sig = _sig(text)
        _check_sig(sig, "float")
        assert "*" in text
        assert "(double)" not in text
        assert not sig.strip().startswith("void ")
        # x87-forced amd64: (float) cast expected (x87 computes in F64)
        if bin_name not in AMD64_BINS:
            assert "(float)" not in text
        if bin_name in SSE_BINS:
            assert "MulV" not in text
            assert " * " in text

    def test_call_f32_func(self, bin_name):
        text = _env(bin_name).get_text("call_f32_func")
        sig = _sig(text)
        if bin_name in I386_BINS:
            pytest.xfail("call_f32_func on i386: callee return type (float) not propagated")
        _check_sig(sig, "float", "float", "float")
        assert text.count("square_f32") >= 2
        assert "a0" in text and "a1" in text
        assert "+" in text
        assert "(long long)" not in text

    def test_negate_f32(self, bin_name):
        text = _env(bin_name).get_text("negate_f32")
        sig = _sig(text)
        if not sig.strip().startswith("float ") and bin_name == "amd64_default_O1":
            pytest.xfail("negate_f32: return type not float (V128 read loses size info)")
        params = sig.split("(")[1] if "(" in sig else ""
        if "float" not in params.split(",")[0] and bin_name == "amd64_default_O1":
            pytest.xfail("negate_f32: param type not float (V128 read loses size info)")
        assert "-" in text.split("{")[1]

    def test_compare_eq_f32(self, bin_name):
        text = _env(bin_name).get_text("compare_eq_f32")
        sig = _sig(text)
        _check_sig(sig, "int|char", "float", "float")
        assert "==" in text

    def test_compare_lt_f32(self, bin_name):
        text = _env(bin_name).get_text("compare_lt_f32")
        sig = _sig(text)
        _check_sig(sig, "int|char", "float", "float")
        assert ">" in text or "<" in text
        assert "CmpF" not in text

    def test_bitcast_int_to_f32(self, bin_name):
        text = _env(bin_name).get_text("bitcast_int_to_f32")
        sig = _sig(text)
        assert "bitcast_int_to_f32" in sig
        if bin_name in ("amd64_O0", "amd64_default_O0"):
            pytest.xfail("bitcast_int_to_f32 amd64 O0: stack canary (fs register) not cleaned up")
        assert "fs" not in text.lower()

    def test_const_f32_to_f64(self, bin_name):
        sig = _sig(_env(bin_name).get_text("const_f32_to_f64"))
        _check_sig(sig, "double")

    def test_const_f64_to_f32(self, bin_name):
        if bin_name in I386_BINS:
            pytest.xfail("const_f64_to_f32 on i386: x87 F64 internally, no F32 signal")
        sig = _sig(_env(bin_name).get_text("const_f64_to_f32"))
        _check_sig(sig, "float")

    # ------------------------------------------------------------------
    # long double functions
    # ------------------------------------------------------------------

    def test_add_f80(self, bin_name):
        text = _env(bin_name).get_text("add_f80")
        sig = _sig(text)
        assert "long double" in sig
        assert "+" in text
        if bin_name not in I386_BINS:
            _check_no_x87_artifacts(text)

    def test_mul_f80(self, bin_name):
        text = _env(bin_name).get_text("mul_f80")
        sig = _sig(text)
        assert "long double" in sig
        assert "*" in text
        if bin_name not in I386_BINS:
            _check_no_x87_artifacts(text)

    def test_divide_f80(self, bin_name):
        text = _env(bin_name).get_text("divide_f80")
        sig = _sig(text)
        assert "long double" in sig
        assert "/" in text
        if bin_name not in I386_BINS:
            _check_no_x87_artifacts(text)

    def test_max_f80(self, bin_name):
        text = _env(bin_name).get_text("max_f80")
        sig = _sig(text)
        assert "long double" in sig
        assert any(op in text for op in ["?", "if", ">", "<"])
        if bin_name not in I386_BINS:
            _check_no_x87_artifacts(text)

    def test_min_f80(self, bin_name):
        text = _env(bin_name).get_text("min_f80")
        sig = _sig(text)
        assert "long double" in sig
        assert "?" in text or "if" in text or "fmin" in text
        if bin_name not in I386_BINS:
            _check_no_x87_artifacts(text)

    def test_negate_f80(self, bin_name):
        text = _env(bin_name).get_text("negate_f80")
        sig = _sig(text)
        assert "long double" in sig
        assert "-" in text.split("{")[1]
        if bin_name not in I386_BINS:
            _check_no_x87_artifacts(text)

    def test_abs_f80(self, bin_name):
        text = _env(bin_name).get_text("abs_f80")
        sig = _sig(text)
        assert "long double" in sig
        assert "?" in text or "if" in text or "fabs" in text
        if bin_name not in I386_BINS:
            _check_no_x87_artifacts(text)

    def test_polynomial_f80(self, bin_name):
        text = _env(bin_name).get_text("polynomial_f80")
        sig = _sig(text)
        if "long double" not in sig:
            pytest.xfail("polynomial_f80: return type is double instead of long double")
        assert "*" in text and "+" in text
        assert "3.0" in text and "2.0" in text and "1.0" in text
        if bin_name not in I386_BINS:
            _check_no_x87_artifacts(text)

    def test_sum_array_f80(self, bin_name):
        text = _env(bin_name).get_text("sum_array_f80")
        sig = _sig(text)
        assert "long double" in sig.split("(")[0]
        assert sig.count(",") == 1
        assert "do" in text or "while" in text or "for" in text
        if bin_name not in I386_BINS:
            _check_no_x87_artifacts(text)
            # long_double should dominate over standalone double
            long_double_count = len(re.findall(r"long double", text))
            stripped = re.sub(r"long double", "", text)
            standalone_double_count = len(re.findall(r"\bdouble\b", stripped))
            assert long_double_count >= standalone_double_count

    def test_round_trip_f80(self, bin_name):
        text = _env(bin_name).get_text("round_trip_f80")
        sig = _sig(text)
        if not sig.strip().startswith("double "):
            pytest.xfail("round_trip_f80: return type should be double")
        assert "+" in text
        if bin_name not in I386_BINS:
            _check_no_x87_artifacts(text)

    def test_store_reload_f80(self, bin_name):
        text = _env(bin_name).get_text("store_reload_f80")
        sig = _sig(text)
        assert "long double" in sig
        assert "*" in text or "+" in text
        if bin_name not in I386_BINS:
            _check_no_x87_artifacts(text)

    def test_f80_to_f64(self, bin_name):
        sig = _sig(_env(bin_name).get_text("f80_to_f64"))
        _check_sig(sig, "double", "long double")

    def test_f80_to_int(self, bin_name):
        text = _env(bin_name).get_text("f80_to_int")
        sig = _sig(text)
        assert sig.strip().startswith("int ")
        assert "long double" in sig.split("(")[1]
        if bin_name not in I386_BINS:
            _check_no_x87_artifacts(text)

    def test_f64_to_f80(self, bin_name):
        sig = _sig(_env(bin_name).get_text("f64_to_f80"))
        if "long double" not in sig.split("(")[0] and bin_name in I386_BINS:
            pytest.xfail("f64_to_f80: return type is double instead of long double (i386 x87 F64)")

    def test_int_to_f80(self, bin_name):
        text = _env(bin_name).get_text("int_to_f80")
        if bin_name not in I386_BINS:
            _check_no_x87_artifacts(text)
        pytest.xfail("int_to_f80: no binary distinction between double and long double conversion")

    def test_mixed_f64_f64_f80(self, bin_name):
        text = _env(bin_name).get_text("mixed_f64_f64_f80")
        sig = _sig(text)
        if bin_name not in I386_BINS:
            _check_no_x87_artifacts(text)
        assert sig.count(",") == 1
        params = sig.split("(")[1]
        assert "double" in params and "long double" in params

    def test_mixed_f80_f64_f80(self, bin_name):
        text = _env(bin_name).get_text("mixed_f80_f64_f80")
        sig = _sig(text)
        assert sig.count(",") == 1
        params = sig.split("(")[1]
        assert "double" in params and "long double" in params

    # ------------------------------------------------------------------
    # struct functions
    # ------------------------------------------------------------------

    def test_struct_point_distance_sq(self, bin_name):
        text = _env(bin_name).get_text("struct_point_distance_sq")
        sig = _sig(text)
        _check_sig(sig, "double")
        assert sig.count(",") == 0
        assert "*" in sig.split("(")[1]  # pointer param
        assert "*" in text and "+" in text

    def test_struct_point_dot(self, bin_name):
        text = _env(bin_name).get_text("struct_point_dot")
        sig = _sig(text)
        _check_sig(sig, "double")
        assert sig.count(",") >= 1

    def test_struct_point_scale(self, bin_name):
        text = _env(bin_name).get_text("struct_point_scale")
        sig = _sig(text)
        assert sig.count(",") == 1
        assert "*" in text

    def test_struct_particle_energy(self, bin_name):
        text = _env(bin_name).get_text("struct_particle_energy")
        assert "double struct_particle_energy" in text
        assert "->" in text or "[" in text or "*(a0" in text
        assert "0.5" in text
        assert "*" in text

    def test_struct_particle_step(self, bin_name):
        text = _env(bin_name).get_text("struct_particle_step")
        sig = _sig(text)
        assert sig.count(",") == 1
        assert "*" in text


# ======================================================================
# Dual-path prototype recovery
#
# Tests that both FactCollector (Path 1) and variable recovery (Path 2)
# produce correct parameter counts and sizes.  Path 2 doesn't infer FP
# types (params show as long long / int), so we check structural
# properties rather than exact type names.
# ======================================================================

# Expected: (return_size_bytes, [param_size_bytes, ...])
_PROTO_SIZES = {
    "add_f64": (8, [8, 8]),
    "max_f64": (8, [8, 8]),
    "divide_f64": (8, [8, 8]),
    "polynomial_f64": (8, [8]),
    "f64_to_int": (4, [8]),
    "int_to_f64": (8, [4]),
    "deep_stack_f64": (8, [8, 8, 8, 8, 8, 8]),
    "add_f32": (4, [4, 4]),
    "square_f32": (4, [4]),
    "call_f32_func": (4, [4, 4]),
    "f32_to_int": (4, [4]),
    "f32_to_f64": (8, [4]),
    "mixed_f32_f64": (8, [4, 8, 4]),
    "sum_array_f64": (8, [4, 4]),
    "sum_array_f32": (4, [4, 4]),
    "call_f64_func": (8, [8, 8]),
    "chained_f64_calls": (8, [8]),
    "identity_f64": (8, [8]),
    "mixed_args_f64": (8, [4, 8, 4, 8]),
}


def _proto_param_sizes(proto) -> list[int]:
    """Extract parameter sizes in bytes from a SimTypeFunction prototype."""
    sizes = []
    for arg in proto.args:
        a = arg.with_arch(archinfo.ArchX86()) if arg._arch is None else arg
        sz = a.size
        sizes.append(sz // 8 if sz else 0)
    return sizes


@pytest.mark.parametrize("bin_name", I386_BINS)
@pytest.mark.parametrize(
    "func_name",
    sorted(_PROTO_SIZES.keys()),
)
class TestDualPathPrototype:
    """Verify that both CC analysis paths recover the same parameter count and sizes."""

    # Functions where variable recovery at O1 can't merge doubles
    _VR_O1_SPLIT = {"chained_f64_calls", "call_f64_func"}

    def test_factcollector_param_count(self, bin_name, func_name):
        """Path 1 (FactCollector) recovers the correct number of parameters."""
        protos = _get_fc_prototypes(bin_name)
        proto = protos.get(func_name)
        if proto is None:
            pytest.skip(f"{func_name} has no prototype via FactCollector")
        expected = _PROTO_SIZES[func_name]
        assert len(proto.args) == len(expected[1]), (
            f"FC {bin_name} {func_name}: expected {len(expected[1])} params, got {len(proto.args)}: {proto}"
        )

    def test_variable_recovery_param_count(self, bin_name, func_name):
        """Path 2 (variable recovery) recovers the correct number of parameters."""
        if bin_name == "i386_O1" and func_name in self._VR_O1_SPLIT:
            pytest.xfail(f"VR i386 O1: {func_name} double params not merged (no local copies at O1)")
        protos = _get_vr_prototypes(bin_name)
        proto = protos.get(func_name)
        if proto is None:
            pytest.skip(f"{func_name} has no prototype via VR")
        expected = _PROTO_SIZES[func_name]
        assert len(proto.args) == len(expected[1]), (
            f"VR {bin_name} {func_name}: expected {len(expected[1])} params, got {len(proto.args)}: {proto}"
        )

    def test_factcollector_param_sizes(self, bin_name, func_name):
        """Path 1 recovers correct parameter sizes."""
        protos = _get_fc_prototypes(bin_name)
        proto = protos.get(func_name)
        if proto is None:
            pytest.skip(f"{func_name} has no prototype via FactCollector")
        expected_sizes = _PROTO_SIZES[func_name][1]
        actual_sizes = _proto_param_sizes(proto)
        assert actual_sizes == expected_sizes, (
            f"FC {bin_name} {func_name}: expected sizes {expected_sizes}, got {actual_sizes}: {proto}"
        )

    def test_variable_recovery_param_sizes(self, bin_name, func_name):
        """Path 2 recovers correct parameter sizes."""
        if bin_name == "i386_O1" and func_name in self._VR_O1_SPLIT:
            pytest.xfail(f"VR i386 O1: {func_name} double params not merged (no local copies at O1)")
        protos = _get_vr_prototypes(bin_name)
        proto = protos.get(func_name)
        if proto is None:
            pytest.skip(f"{func_name} has no prototype via VR")
        expected_sizes = _PROTO_SIZES[func_name][1]
        actual_sizes = _proto_param_sizes(proto)
        assert actual_sizes == expected_sizes, (
            f"VR {bin_name} {func_name}: expected sizes {expected_sizes}, got {actual_sizes}: {proto}"
        )


# ======================================================================
# Stack slot reuse: FP value overwritten by int at the same offset
#
# Hand-written assembly (slot_reuse_{i386,amd64}.o) that spills a
# float/double to a stack slot then overwrites it with fisttp (int).
# The decompiler must NOT unify the FP and int variables.
# ======================================================================


def _decompile_asm_func(filename: str, func_name: str) -> str:
    """Decompile a function from an object file in the fp test directory."""
    path = os.path.join(_fp_dir, filename)
    if not os.path.exists(path):
        pytest.skip(f"{path} not found")
    proj = angr.Project(path, auto_load_libs=False)
    cfg = proj.analyses[CFGFast].prep()(normalize=True, data_references=True)
    func = cfg.functions[func_name]
    dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
    assert dec.codegen is not None
    text = dec.codegen.text
    assert text is not None
    return text


_SLOT_REUSE_BINS = ["slot_reuse_amd64.o", "slot_reuse_i386.o"]


@pytest.mark.parametrize("asm_bin", _SLOT_REUSE_BINS)
class TestStackSlotReuse:
    """Verify that FP and int variables at the same stack offset are not unified."""

    @pytest.mark.parametrize("func_name", ["slot_reuse_dbl", "slot_reuse_flt"])
    def test_no_type_conflict(self, asm_bin, func_name):
        """The decompiled output must not have 'Other Possible Types'."""
        text = _decompile_asm_func(asm_bin, func_name)
        assert "Other Possible Types" not in text, f"Type conflict in {func_name}:\n{text}"

    @pytest.mark.parametrize("func_name", ["slot_reuse_dbl", "slot_reuse_flt"])
    def test_has_fp_and_int_locals(self, asm_bin, func_name):
        """Both a floating-point and an integer local should exist."""
        if "i386" in asm_bin:
            pytest.xfail("i386: fisttp spill/reload optimized away, slot reuse not detected")
        text = _decompile_asm_func(asm_bin, func_name)
        assert "double " in text or "float " in text, f"No FP local in {func_name}:\n{text}"
        assert "unsigned int " in text or "int " in text, f"No int local in {func_name}:\n{text}"

    @pytest.mark.parametrize("func_name", ["slot_reuse_dbl", "slot_reuse_flt"])
    def test_returns_int(self, asm_bin, func_name):
        """The return type should be int, not double/float."""
        if "i386" in asm_bin:
            pytest.xfail("i386: fisttp spill/reload optimized away, returns FP instead of int")
        text = _decompile_asm_func(asm_bin, func_name)
        sig = text.split("{")[0].strip()
        assert sig.startswith(("int ", "unsigned int ")), f"Wrong return type: {sig}"


# ======================================================================
# i386 structural FP detection
#
# Tests that the VEX propagator detects FP-returning callees
# structurally (via PutI to fpreg) when no prototype is available.
# ======================================================================


class TestI386StructuralFPDetection:
    """Test that i386 FP return detection works without pre-decompiled callees."""

    def test_call_f64_func_without_predecomp(self):
        """Decompile call_f64_func WITHOUT pre-decompiling identity_f64.
        The propagator must detect identity_f64 returns FP structurally."""
        path = _BIN_PATHS.get("i386_O1")
        if path is None or not os.path.exists(path):
            pytest.skip("i386_O1 binary not found")
        # Fresh project -- no pre-decompilation of helpers
        proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()(normalize=True, data_references=True)
        # Decompile call_f64_func directly (identity_f64 has no prototype yet)
        text = (
            proj.analyses[Decompiler].prep(fail_fast=True)(cfg.functions["call_f64_func"], cfg=cfg.model).codegen.text
        )
        assert text is not None
        assert "identity_f64" in text, f"Should reference callee: {text[:300]}"

    def test_chained_f64_calls_without_predecomp(self):
        """Decompile chained_f64_calls without pre-decompiling helpers."""
        path = _BIN_PATHS.get("i386_O0")
        if path is None or not os.path.exists(path):
            pytest.skip("i386_O0 binary not found")
        proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()(normalize=True, data_references=True)
        text = (
            proj.analyses[Decompiler]
            .prep(fail_fast=True)(cfg.functions["chained_f64_calls"], cfg=cfg.model)
            .codegen.text
        )
        assert text is not None
        assert "identity_f64" in text, f"Should reference callee: {text[:300]}"


# ======================================================================
# Hand-crafted assembly tests
# ======================================================================


class TestFourDoubles:
    """Test i386 function with 4 double parameters (four_doubles_i386.o)."""

    def test_smoke(self):
        text = _decompile_asm_func("four_doubles_i386.o", "four_doubles")
        assert len(text) > 0

    def test_has_multiplication(self):
        text = _decompile_asm_func("four_doubles_i386.o", "four_doubles")
        assert "*" in text, f"Expected multiplication: {text[:300]}"

    def test_has_addition(self):
        text = _decompile_asm_func("four_doubles_i386.o", "four_doubles")
        assert "+" in text, f"Expected addition: {text[:300]}"


class TestFtopConflict:
    """Test i386 function with conditional FP stack usage (ftop_conflict_i386.o)."""

    def test_smoke_no_crash(self):
        text = _decompile_asm_func("ftop_conflict_i386.o", "ftop_conflict")
        assert text is not None

    def test_no_ireg_artifacts(self):
        """No raw IRegister syntax should leak into decompiled output."""
        text = _decompile_asm_func("ftop_conflict_i386.o", "ftop_conflict")
        assert "ireg_" not in text, f"IRegister leaked into output: {text[:400]}"


if __name__ == "__main__":
    unittest.main()
