#!/usr/bin/env python3
"""
Floating point decompilation tests.
"""

from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import archinfo
import pytest

import angr
from angr.analyses import CFGFast, Decompiler
from angr.analyses.complete_calling_conventions import (
    CallingConventionAnalysisMode,
    CompleteCallingConventionsAnalysis,
)
from angr.analyses.decompiler.structured_codegen.c_serialize import parse_codegen, serialize_codegen
from angr.calling_conventions import SimCCMicrosoftFastcall
from angr.sim_type import SimTypeDouble, SimTypeFloat, SimTypeLongLong, SimTypeNum
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from tests.common import bin_location, load_project_with_scoped_cfg

# -- Paths & binary matrix --------------------------------------------

_fp_dir = os.path.join(bin_location, "tests", "decompiler_fp")

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
        # gcc folds 2.0 * x into x + x (fadd %st(0),%st / addsd %xmm0,%xmm0): no 2.0 constant exists in the binary
        assert "3.0" in text and "1.0" in text
        assert "2.0" in text or re.search(r"(\w+) \+ \1\b", text)

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
        assert sig.split("(")[1].count("double") == 6, sig
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
        _check_sig(sig, "long double", "long double")
        assert "*" in text and "+" in text
        assert "3.0" in text and "1.0" in text
        assert "2.0" in text or re.search(r"(\w+) \+ \1\b", text)
        assert "(long long)" not in text
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


def _decompile_asm_func(filename: str, func_name: str, cca: bool = False) -> str:
    """Decompile a function from an object file in the fp test directory."""
    path = os.path.join(_fp_dir, filename)
    if not os.path.exists(path):
        pytest.skip(f"{path} not found")
    proj = angr.Project(path, auto_load_libs=False)
    cfg = proj.analyses[CFGFast].prep()(normalize=True, data_references=True)
    if cca:
        proj.analyses[CompleteCallingConventionsAnalysis].prep()(cfg=cfg.model)
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
# Lane-wise SSE conversions on a scalar widened into lane 0 (cvtdq2ps after
# movd; MSVC's inlined floorf).  They must become plain (float) casts.
# ======================================================================


class TestVectorConvertLowering:
    def test_int_to_float(self):
        text = _decompile_asm_func("vec_convert_amd64.o", "int_to_float")
        assert "return (float)a0;" in text, text

    def test_floorf_idiom(self):
        text = _decompile_asm_func("vec_convert_amd64.o", "floorf_idiom")
        assert "Conv" not in text and "x4" not in text, text
        assert "(int)a0" in text and "isunordered(" in text, text
        # jp and jne both reach the decrement
        assert re.search(r"\w+ != a0", text), text


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


class TestFpNegationThroughPhi:
    def test_go_printfloat_entry_phi(self):
        # runtime.printfloat in a Windows Go binary: the stack-check back edge makes the entry a loop head, so the
        # xmm0 parameter reaches the sign-flip XOR through an entry phi; FpNegation must see through it.
        bin_path = os.path.join(
            bin_location,
            "tests",
            "x86_64",
            "windows",
            "131252a8059fdbb12d77cd4711e597c45bb48e6d4bc3ddc808697a5e0488ff2c",
        )
        proj, cfg = load_project_with_scoped_cfg(bin_path, 0x436B40, expand_call_tree=False, run_ccc=False)
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(cfg.functions[0x436B40], cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert "fneg(" not in text, text
        assert re.search(r"(\w+) = -\(\1\);", text), text


class TestX87ConstantLiterals:
    """80-bit x87 constants outside the double range must render as long double literals."""

    def test_round_and_return_ldbl_limits(self):
        # glibc's round_and_return compares against LDBL_MIN and LDBL_MAX, whose exponents overflow a Python float
        bin_path = os.path.join(bin_location, "tests", "x86_64", "static")
        proj = angr.Project(bin_path, auto_load_libs=False)
        func_addr = 0x48E590
        cfg = proj.analyses[CFGFast].prep()(
            normalize=True,
            data_references=True,
            regions=[(func_addr, 0x48E9F0)],
            function_starts=[func_addr],
            start_at_entry=False,
        )
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(cfg.functions[func_addr], cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert "1.18973149535723176502e+4932L" in text
        assert "3.36210314311209350626e-4932L" in text

    def test_decode_x87_extended_edges(self):
        from angr.analyses.decompiler.structured_codegen.c import _decode_x87_extended

        def enc(sign, exp, sig):
            return (((sign << 15) | exp) << 64) | sig

        assert _decode_x87_extended(enc(0, 16383, 1 << 63)) == "1.0L"
        assert _decode_x87_extended(enc(1, 16384, 3 << 62)) == "-3.0L"
        assert _decode_x87_extended(enc(1, 0, 0)) == "-0.0L"
        assert _decode_x87_extended(enc(0, 0x7FFF, 1 << 63)) == "HUGE_VALL"
        assert _decode_x87_extended(enc(1, 0x7FFF, 1 << 63)) == "-HUGE_VALL"
        assert _decode_x87_extended(enc(0, 0x7FFF, (1 << 63) | 1)) == "NAN"
        assert _decode_x87_extended(enc(0, 0, 1)) == "3.64519953188247460253e-4951L"
        assert _decode_x87_extended(enc(0, 16383 + 1024, 1 << 63)) == "1.79769313486231590773e+308L"


class TestI386PrototypelessCalleePushes:
    """Decompiling a callee first leaves it with a prototype but no calling convention. The caller's fact collector
    must not feed the raw stack pushes of such a callsite into the prototype-indexed arg-use table."""

    @staticmethod
    def _scoped_cfg(proj, callee_addr, caller_addr, end_addr):
        return proj.analyses[CFGFast].prep()(
            normalize=True,
            regions=[(callee_addr, end_addr)],
            function_starts=[callee_addr, caller_addr],
        )

    @pytest.mark.parametrize(
        "callee_addr,caller_addr,end_addr",
        [(0x1006872E, 0x100688C8, 0x10068BE9), (0x10069A2F, 0x10069B1D, 0x10069C51)],
    )
    def test_decompile_callee_then_caller(self, callee_addr, caller_addr, end_addr):
        bin_path = os.path.join(
            bin_location,
            "tests",
            "i386",
            "windows",
            "53575875777863a69a573be858e75ceea834ea54c844bb528128a4ad16879d45",
        )
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = self._scoped_cfg(proj, callee_addr, caller_addr, end_addr)

        callee = cfg.functions[callee_addr]
        proj.analyses[Decompiler].prep(fail_fast=True)(callee, cfg=cfg.model)
        assert callee.calling_convention is None and callee.prototype is not None

        caller = cfg.functions[caller_addr]
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(caller, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert caller.calling_convention is not None


class TestX87StatusWordIdioms:
    """fcomp; fnstsw ax; test ah, imm / sahf; jcc (MSVC) and gcc -march=i386 shapes fold into IEEE comparisons."""

    @pytest.mark.parametrize(
        "func_name,taken_cond,taken_ret",
        [
            ("lt_test_jp", "a0 >= a1", 2),
            ("gt_test_jne", "a0 <= a1", 2),
            ("eq_test_jnp", "a0 == a1", 2),
            ("lt_test_jne", "a0 < a1", 2),
            ("ge_sahf_jb", "a0 < a1", 2),
            ("le_sahf_ja", "a0 > a1", 2),
            ("eq_sahf_jne", "a0 != a1", 2),
            ("isnan_sahf_jnp", "isnan(a0)", 1),
        ],
    )
    def test_msvc_branches(self, func_name, taken_cond, taken_ret):
        text = _decompile_asm_func("x87_fnstsw_i386.o", func_name)
        assert "CmpF" not in text and "_ccall" not in text and "ftop" not in text, text
        # either `if (cond) return taken; return other;` or the structurer's flipped form
        other = 3 - taken_ret
        flipped = {
            "a0 >= a1": "a0 < a1",
            "a0 <= a1": "a0 > a1",
            "a0 == a1": "a0 != a1",
            "a0 < a1": "a0 >= a1",
            "a0 > a1": "a0 <= a1",
            "a0 != a1": "a0 == a1",
            "isnan(a0)": "!isnan(a0)",
        }[taken_cond]
        pat_taken = rf"if \({re.escape(taken_cond)}\)\s*return {taken_ret};\s*return {other};"
        pat_flipped = rf"if \({re.escape(flipped)}\)\s*return {other};\s*return {taken_ret};"
        assert re.search(pat_taken, text) or re.search(pat_flipped, text), text

    def test_sahf_setb(self):
        text = _decompile_asm_func("x87_fnstsw_i386.o", "lt_sahf_setb")
        assert "return a0 < a1;" in text, text

    @pytest.mark.parametrize(
        "func_name,expected",
        [
            ("lt_f64", "return a1 > a0;"),
            ("le_f64", "return a1 >= a0;"),
            ("gt_f64", "return a0 > a1;"),
            ("ge_f64", "return a0 >= a1;"),
            ("eq_f64", "return a0 == a1;"),
            ("ne_f64", "return a0 != a1;"),
        ],
    )
    def test_gcc_i386_setcc(self, func_name, expected):
        text = _decompile_asm_func("x87_fcom_i386_O1.o", func_name)
        assert expected in text, text

    @pytest.mark.parametrize(
        "func_name,expected",
        [("br_lt_f64", "return (a1 <= a0) + 1;"), ("br_eq_f64", "return (a0 != a1) + 1;")],
    )
    def test_gcc_i386_setcc_inc(self, func_name, expected):
        # setne al; movzx eax,al; inc eax: the add stays 32-bit (a 1-bit add would wrap true + 1 to 0)
        text = _decompile_asm_func("x87_fcom_i386_O1.o", func_name)
        assert expected in text and "unsigned int" not in text, text


class TestX87FxamAndStoredStatusWord:
    """fxam status bits fold into classification tests; a status word stored by fnstsw and reloaded is folded too."""

    @pytest.mark.parametrize(
        "func_name,cond,negated",
        [
            ("fxam_isnan", "isnan(a0)", "!isnan(a0)"),
            ("fxam_isinf", "isinf(a0)", "!isinf(a0)"),
            ("fxam_iszero", "a0 == 0.0", "a0 != 0.0"),
            ("fxam_isnormal", "isnormal(a0)", "!isnormal(a0)"),
            ("fxam_signbit", "signbit(a0)", "!signbit(a0)"),
            ("fxam_notfinite_sahf", "!isfinite(a0)", "isfinite(a0)"),
            ("fxam_mem_notfinite", "!isfinite(a0)", "isfinite(a0)"),
            ("ftst_mem_le", "a0 <= 0.0", "a0 > 0.0"),
            ("fcomp_local_lt", "a0 < a1", "a0 >= a1"),
        ],
    )
    def test_branches(self, func_name, cond, negated):
        # every function returns 1 when the tested condition holds and 2 otherwise
        text = _decompile_asm_func("x87_fxam_i386.o", func_name)
        assert "_ccall" not in text, text
        pat = rf"if \({re.escape(cond)}\)\s*return 1;\s*return 2;"
        pat_flipped = rf"if \({re.escape(negated)}\)\s*return 2;\s*return 1;"
        assert re.search(pat, text) or re.search(pat_flipped, text), text


# ======================================================================
# sse_lane_amd64.o: lane-wise SSE ops (psrlq/cmpeqsd/psubq/mulpd) applied to
# scalar doubles; only lane 0 is read, so the C must use scalar operators.
# ======================================================================


class TestSSELaneOps:
    def test_exponent_bits(self):
        text = _decompile_asm_func("sse_lane_amd64.o", "exponent_bits")
        assert "ShrNV" not in text and ">> 52" in text, text

    def test_is_one(self):
        text = _decompile_asm_func("sse_lane_amd64.o", "is_one")
        assert "CmpEQV" not in text and "1.0 == a0" in text, text

    def test_sub_lane0(self):
        text = _decompile_asm_func("sse_lane_amd64.o", "sub_lane0")
        assert "SubV" not in text and "a1 - a0" in text, text

    def test_mulpd_lane0(self):
        text = _decompile_asm_func("sse_lane_amd64.o", "mulpd_lane0")
        assert "MulV" not in text and "a0 * a1" in text, text


# ======================================================================
# movmskpd / movmskps: lane-wise sign-bit gathering. A genuine vector renders as the intrinsic; lane 0 of a scalar
# (the upper lanes masked off by the consumer) renders as signbit().
# ======================================================================


class TestSSEMoveMask:
    _LIBM_BITS = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_libm_bits")

    def test_vector_movemask(self):
        assert "return _mm_movemask_pd(*(a0));" in _decompile_asm_func("sse_movmsk_amd64.o", "mask_pd")
        assert "return _mm_movemask_ps(*(a0));" in _decompile_asm_func("sse_movmsk_amd64.o", "mask_ps")

    def test_scalar_signbit(self):
        assert "return signbit(a0);" in _decompile_asm_func("sse_movmsk_amd64.o", "sign_d")
        assert "return signbit(a0);" in _decompile_asm_func("sse_movmsk_amd64.o", "sign_f")

    def test_libm_isinf_signbit(self):
        # f_isinf: andpd/ucomisd, then movmskpd; and 1; cmp 1; sbb; and 2; sub 1
        text = _decompile_scoped(self._LIBM_BITS, 0x401430)
        assert "v1 = (signbit(a0) ? 0xffffffff : 1);" in text, text
        assert "(a0 & 0x7fffffffffffffff) > 1.7976931348623157e+308" in text, text
        # f_signbit: movmskpd reads only the high half of the double argument, which must stay a double
        text = _decompile_scoped(self._LIBM_BITS, 0x4013F0)
        assert "int f_signbit(double a0)" in text and "return signbit(a0);" in text, text


# ======================================================================
# sse_phi_insert_i386.o: a cmpeqsd mask whose lane 0 is tested also flows, with a movlpd lane-0 Insert, into a phi
# read only at lane 0 (CRT log()). The phi class must narrow to 64 bits so the compare lowers to a scalar test.
# ======================================================================


def test_sse_phi_insert_narrowing():
    text = _decompile_asm_func("sse_phi_insert_i386.o", "lane_cmp_phi")
    assert "CmpEQV" not in text and "_INSERT" not in text and "uint128_t" not in text, text
    assert "a0 != 0.0" in text or "a0 == 0.0" in text, text
    assert "a0 * a0" in text, text


# ======================================================================
# cvtsi2sd_signed_amd64.o: cvtsi2sd reads its operand as a signed integer. The
# operand is typed signed when nothing contradicts it; otherwise the C must cast
# through the signed integer type, since (double)x of an unsigned or pointer x
# converts differently for values with the sign bit set.
# ======================================================================


class TestSignedIntToFP:
    def test_field_typed_signed(self):
        text = _decompile_asm_func("cvtsi2sd_signed_amd64.o", "field_to_double")
        assert "long long *a0" in text, text
        assert "(double)(long long)" not in text, text

    @pytest.mark.parametrize("func_name,param", [("s64_to_double", "long long a0"), ("s32_to_double", "int a0")])
    def test_param_typed_signed(self, func_name, param):
        text = _decompile_asm_func("cvtsi2sd_signed_amd64.o", func_name)
        assert param in text, text
        assert "(double)a0" in text, text

    def test_pointer_operand_is_cast(self):
        text = _decompile_asm_func("cvtsi2sd_signed_amd64.o", "ptr_to_double")
        assert re.search(r"\(double\)\(long long\)a\d", text), text

    def test_unsigned_operand_is_cast(self):
        # shr types the operand unsigned; the 32-bit cvtsi2sd still converts it as int
        text = _decompile_asm_func("cvtsi2sd_signed_amd64.o", "shr_to_double")
        assert "(double)(int)(a1 >> 3)" in text, text


if __name__ == "__main__":
    unittest.main()


# ======================================================================
# x87 transcendental / remainder instructions
# ======================================================================


class TestX87Math(unittest.TestCase):
    """fsin, fcos, fptan, fpatan, fsqrt, fprem, fprem1, fyl2x, fyl2xp1, f2xm1 and fscale: the VEX ops behind
    them have no symbolic-engine model, and used to decompile to operand-less `unsupported_Iop_*()` calls."""

    _env: _Env | None = None

    @classmethod
    def setUpClass(cls):
        path = os.path.join(_fp_dir, "x87_math_amd64")
        if not os.path.exists(path):
            pytest.skip(f"{path} not found")
        _BIN_PATHS["x87_math_amd64"] = path
        cls._env = _Env("x87_math_amd64")

    def _text(self, func_name: str) -> str:
        assert self._env is not None
        text = self._env.get_text(func_name)
        assert "unsupported_" not in text, text
        return text

    def test_libm_unary(self):
        assert "sqrt(" in self._text("x87_sqrt")
        # fsin/fcos only run on finite in-range arguments; VEX keeps the range check
        assert re.search(r"<= 1085 \? sin\(", self._text("x87_sin"))
        assert re.search(r"<= 1085 \? cos\(", self._text("x87_cos"))

    def test_atan2(self):
        assert re.search(r"atan2\(\w+, \w+\)", self._text("x87_atan2"))

    def test_fprem_loop(self):
        # gcc's fmod: do { fprem } while (C2) is one complete fmod()
        text = self._text("x87_fmod")
        assert re.search(r"fmod\(\w+, a1\)", text), text
        assert "x87_fprem_c3210" not in text and "while" not in text, text
        # the codegen survives serialization
        assert self._env is not None
        dec = self._env.project.analyses[Decompiler].prep()(
            self._env.cfg.functions["x87_fmod"], cfg=self._env.cfg.model
        )
        assert dec.codegen is not None
        parsed = parse_codegen(serialize_codegen(dec.codegen), project=dec.project, kb=dec.kb, func=dec.func)
        assert parsed.text == dec.codegen.text
        text = self._text("x87_remainder")
        assert re.search(r"remainder\(\w+, a1\)", text), text
        assert "x87_fprem1_c3210" not in text and "while" not in text, text

    def test_log2_and_log1p(self):
        # fld1; fyl2x: 1.0 * log2(x) folds to log2(x)
        text = self._text("x87_log2")
        assert re.search(r"\blog2\(\w+\)", text) and "1.0 *" not in text, text
        # log1p(x) = ln2 * log2(x + 1) (fyl2xp1 with ST1 = ln2)
        assert re.search(r"0\.69314718\d* \* log2\(\w+ \+ 1\.0\)", self._text("x87_log1p"))

    def test_exp2_and_ldexp(self):
        # exp2(x) = ldexp(f2xm1(x - rint(x)) + 1, (int)rint(x)); f2xm1; fld1; faddp folds back to exp2()
        text = self._text("x87_exp2")
        assert re.search(r"ldexp\(exp2\(\w+ - rint\(\w+\)\), \(int\)rint\(\w+\)\)", text), text
        assert "1.0" not in text and "Round" not in text, text
        # the int -> double -> int round trip of the exponent is exact
        assert re.search(r"ldexp\(\w+, \w+\)", self._text("x87_ldexp"))


class TestRoundToInt:
    """VEX `Round(rm, x)` renders as rint() for the current rounding mode and as the fixed-mode libm function for
    a constant one (roundsd/roundss immediates)."""

    @pytest.mark.parametrize(
        "func_name,expected",
        [
            ("round_even", "return roundeven(a0);"),
            ("round_floor", "return floor(a0);"),
            ("round_ceil", "return ceil(a0);"),
            ("round_trunc", "return trunc(a0);"),
            ("round_dyn", "return rint(a0);"),
            ("round_dyn_f32", "return rintf(a0);"),
        ],
    )
    def test_round(self, func_name, expected):
        text = _decompile_asm_func("sse_round_amd64.o", func_name)
        assert expected in text, text


class TestX87FpremLoop:
    """fprem/fprem1 loops that repeat until C2 (partial remainder) clears are one complete fmod()/remainder()."""

    def test_sin_reduce(self):
        # MSVC _CIsin: fsin sets C2 when out of range; reduce by (pi/2)*2^63 with fprem1, then fsin again
        text = _decompile_asm_func("x87_fprem_i386.o", "sin_reduce")
        assert re.search(r"if \(.*> 1085\)\n", text), text
        assert text.count("sin(") == 3 and "remainder(" in text, text
        assert "while" not in text and "x87_fprem1_c3210" not in text and "_ccall" not in text, text

    def test_fmod_test_ah(self):
        text = _decompile_asm_func("x87_fprem_i386.o", "fmod_test_ah")
        assert "return fmod(a0, a1);" in text, text

    def test_quotient_bits_keep_intrinsic(self):
        text = _decompile_asm_func("x87_fprem_i386.o", "fmod_quotient_bits")
        assert "while" not in text and "x87_fprem_c3210(a0, a1)" in text, text

    def test_live_counter_keeps_loop(self):
        # the iteration count is stored after the loop: one iteration is not equivalent
        text = _decompile_asm_func("x87_fprem_i386.o", "fmod_count")
        assert "while" in text, text


# x87 stack tracking across calls and the fptag/fistp/fxam/long double
# shapes seen in MSVC code (x87_call_delta_i386.o)
# ======================================================================


_X87_CALL_DELTA_BIN = "x87_call_delta_i386.o"


def _assert_no_x87_leaks(text: str) -> None:
    assert "ireg_" not in text, text
    assert "ftop" not in text, text
    assert "fptag" not in text, text
    assert "fpreg[" not in text, text


class TestX87CallDelta:
    """IRegisterResolver must resolve every x87 stack access to a concrete st(i) regardless of how the callees
    affect the stack."""

    def test_callee_pushes_despite_int_prototype(self):
        # ret_double also writes eax; the push comes from the callee's own code and the caller consumes st(0)
        text = _decompile_asm_func(_X87_CALL_DELTA_BIN, "caller_merge", cca=True)
        _assert_no_x87_leaks(text)
        assert len(re.findall(r"\w+ = ret_double\(", text)) == 2, text
        # fsubr/fstp qword [ecx]: a dereference of the double * held in ecx, never the address of the register
        assert "*)&" not in text, text
        assert re.search(r"\*\(?(v\d+)\)? = \*\(?\1\)? - v\d+;", text), text

    def test_callee_pops_argument(self):
        text = _decompile_asm_func(_X87_CALL_DELTA_BIN, "caller_pop")
        _assert_no_x87_leaks(text)
        assert "1.0" in text

    def test_extern_callee_inferred_from_caller(self):
        text = _decompile_asm_func(_X87_CALL_DELTA_BIN, "caller_extern")
        _assert_no_x87_leaks(text)
        assert "ext_fn(" in text

    def test_unbalanced_paths_fall_back(self):
        text = _decompile_asm_func(_X87_CALL_DELTA_BIN, "caller_unbalanced")
        _assert_no_x87_leaks(text)

    def test_fistp_saturation_keeps_fptag_ite(self):
        # the fptag check is the first ITE of fistp; the saturation ITE after it must not turn it into a branch
        text = _decompile_asm_func(_X87_CALL_DELTA_BIN, "fistp_word")
        _assert_no_x87_leaks(text)
        assert "(short)" in text
        assert "if (" not in text

    def test_fisttp_before_shift_diamond(self):
        # the shift-by-cl ITE becomes a diamond; the fisttp store ahead of it in the same block must survive
        text = _decompile_asm_func(_X87_CALL_DELTA_BIN, "fisttp_then_shl")
        _assert_no_x87_leaks(text)
        assert "= (long long)" in text

    def test_long_double_load_from_ccall_address(self):
        # loadF80le into a 64-bit tmp whose address is a segment-selector ccall (the tmp is not propagated)
        text = _decompile_asm_func(_X87_CALL_DELTA_BIN, "fld_f80_seg")
        _check_no_x87_artifacts(text)
        assert "long double" in text

    def test_fxam_intrinsic(self):
        text = _decompile_asm_func(_X87_CALL_DELTA_BIN, "fxam_fn")
        _assert_no_x87_leaks(text)
        assert "_ccall" not in text
        if text.startswith("char "):
            # with the (inferred) char return type only al is returned, and al is zero after fnstsw ax
            assert "return 0;" in text, text
        else:
            assert "__fxam(" in text, text


class TestX87ReturnPrototype:
    """A value left on the x87 stack is the return value even when eax holds a scratch value; callers consume it
    (x87_ret_proto_win32.exe, __fastcall and __cdecl)."""

    @classmethod
    def setup_class(cls):
        path = os.path.join(_fp_dir, "x87_ret_proto_win32.exe")
        if not os.path.exists(path):
            pytest.skip(f"{path} not found")
        cls.proj = angr.Project(path, auto_load_libs=False)
        cls.cfg = cls.proj.analyses[CFGFast].prep()(normalize=True, data_references=True)
        cls.proj.analyses[CompleteCallingConventionsAnalysis].prep()(cfg=cls.cfg.model)

    def _proto(self, name: str):
        return self.cfg.functions[name].prototype

    def _text(self, name: str) -> str:
        dec = self.proj.analyses[Decompiler].prep(fail_fast=True)(self.cfg.functions[name], cfg=self.cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        _assert_no_x87_leaks(dec.codegen.text)
        return dec.codegen.text

    def test_x87_push_beats_eax_scratch(self):
        for name in ("fast_ret_double", "cdecl_ret_double", "caller_pass"):
            assert isinstance(self._proto(name).returnty, SimTypeDouble), name
        assert isinstance(self.cfg.functions["fast_ret_double"].calling_convention, SimCCMicrosoftFastcall)
        assert "double fast_ret_double(" in self._text("fast_ret_double")

    def test_balanced_x87_use_returns_int(self):
        # fld/fstp, or a push consumed by the callee, leaves nothing on the x87 stack
        for name in ("store_ret_int", "trunc_int", "caller_consume_int"):
            assert not isinstance(self._proto(name).returnty, SimTypeFloat), name

    def test_caller_consumes_st0_after_jmp(self):
        text = self._text("caller_fast_add")
        m = re.search(r"(\w+) = fast_ret_double\(", text)
        assert m is not None, text
        assert re.search(rf"= {m.group(1)} \+ ", text), text
        # fadd/fstp qword [esi]: a dereference of the pointer in esi, never the address of the register
        assert "*)&" not in text, text
        # its only accesses are F64 loads and stores: a double *
        assert "double *a1" in text, text
        assert re.search(rf"\*\(?a1\)? = {m.group(1)} \+ \*\(?a1\)?;", text), text

    def test_caller_stores_st0(self):
        assert re.search(r"\*\(?a0\)? = cdecl_ret_double\(a0\);", self._text("caller_consume_int"))


class TestX87IntReturnClassifier:
    """An integer-returning classifier that reads its double argument via the x87 stack and writes `mov ax, imm16` on
    one path is not a float-returning function (x87_dclass_win32.exe)."""

    def test_dclass_returns_int(self):
        path = os.path.join(_fp_dir, "x87_dclass_win32.exe")
        if not os.path.exists(path):
            pytest.skip(f"{path} not found")
        proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()(normalize=True, data_references=True)
        proj.analyses[CompleteCallingConventionsAnalysis].prep()(cfg=cfg.model)
        dclass = cfg.functions["dclass"]
        assert not isinstance(dclass.prototype.returnty, SimTypeFloat)

        dec = proj.analyses[Decompiler].prep(fail_fast=True)(dclass, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "float" not in dec.codegen.text, dec.codegen.text
        # the decompiler's refined prototype must not turn the int return into a float either
        assert not isinstance(dclass.prototype.returnty, SimTypeFloat)

        dec = proj.analyses[Decompiler].prep(fail_fast=True)(cfg.functions["caller"], cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert re.search(r"dclass\(a0\) == 2", text), text
        assert "float" not in text and "double)" not in text, text


class TestX87Int64Copy:
    """MSVC copies an int64 spilled as two dwords with fild/fistp qword; it must decompile to a plain int64 copy."""

    def test_fild_fistp_is_int64_copy(self):
        text = _decompile_asm_func("x87_int64_copy_win32.exe", "copy64")
        assert "_INSERT" not in text, text
        assert "double" not in text, text
        assert len(re.findall(r"(v\d+) = CONCAT\(a3, a2\);\n\s+\*\(a0\) = \1;", text)) == 3, text


# -- Integer views of floating-point registers ------------------------

_AARCH64_LIBC = os.path.join(bin_location, "tests", "aarch64", "libc.so.6")
_AMD64_LIBC = os.path.join(bin_location, "tests", "x86_64", "libc.so.6")


def _decompile_scoped(bin_path: str, addr: int) -> str:
    proj, cfg = load_project_with_scoped_cfg(bin_path, addr, window=0x200, expand_call_tree=False)
    dec = proj.analyses[Decompiler].prep(fail_fast=True)(cfg.functions[addr], cfg=cfg.model)
    assert dec.codegen is not None and dec.codegen.text is not None
    # the reinterpret nodes must survive a serialization round trip
    parsed = parse_codegen(serialize_codegen(dec.codegen), project=proj, kb=dec.kb, func=dec.func)
    assert parsed.text == dec.codegen.text
    return dec.codegen.text


class TestFPRegisterBitPatterns(unittest.TestCase):
    """
    An integer move out of or into a floating-point register (``fmov x2, d0`` / ``movq rax, xmm0``) views the bit
    pattern of the double; the bit operations must not be applied to the double itself.
    """

    def test_frexp_aarch64(self):
        text = _decompile_scoped(_AARCH64_LIBC, 0x432E30)  # frexp
        sig = _sig(text)
        _check_sig(sig, "double", "unsigned int *|int *", "double")
        # parameter order from the libc prototype frexp(double, int *)
        assert re.search(r"\(double a0, (unsigned )?int \*a1\)", sig), sig
        # fmov x2, d0; ubfx x1, x2, #52, #11
        # a0 is held in d0: the helper form, not the address of a register
        assert re.search(r"= __double_as_longlong\(a\d\);", text), text
        assert re.search(r"\(int\)\(?a\d\)? (>>|\*)", text) is None, text
        # fmul d1, d0, d1; fmov x2, d1
        assert "__double_as_longlong(a0 * " in text, text
        # and x2, ...; orr x2, ...; fmov d0, x2
        assert "__longlong_as_double(" in text, text
        assert "CmpF(a0, 0.0)" in text or "isnan(a0)" in text or "isunordered(" in text, text

    def test_frexp_amd64(self):
        text = _decompile_scoped(_AMD64_LIBC, 0x436310)  # frexp
        sig = _sig(text)
        _check_sig(sig, "double", "unsigned int *|int *", "double")
        # parameter order from the libc prototype frexp(double, int *)
        assert re.search(r"\(double a0, (unsigned )?int \*a1\)", sig), sig
        # movq rcx, xmm0
        assert "= __double_as_longlong(a0);" in text, text
        # movq xmm0, rax
        assert "a0 = __longlong_as_double(" in text, text
        assert "__double_as_longlong(a0 * " in text, text


class TestFusedMultiplyAddDecompilation:
    """
    Fused multiply-add is a VEX Qop that never reached the AIL op mapper, so FMA-using functions decompiled to
    `return a0;` with their whole body gone; the PPC single-precision ops (`fmuls`, `frsp`, `stfs`) lost their
    operand the same way.
    """

    @staticmethod
    def _decompile(arch_dir: str, bin_name: str, addr: int) -> str:
        bin_path = os.path.join(bin_location, "tests", arch_dir, bin_name)
        if not os.path.exists(bin_path):
            pytest.skip(f"{bin_path} not found")
        proj, cfg = load_project_with_scoped_cfg(
            bin_path, addr, expand_call_tree=False, project_kwargs={"auto_load_libs": False}
        )
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(cfg.functions[addr], cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "unsupported_" not in dec.codegen.text
        return dec.codegen.text

    def test_s390x_fmaf64(self):
        # fmaf64: madbr %f4, %f0, %f2 ; ldr %f0, %f4 ; br %r14
        text = self._decompile("s390x", "libm.so.6", 0x440990)
        assert text.startswith("double fmaf64(double a0, double a1, double a2)"), text
        assert re.search(r"return a\d \* a\d \+ a\d;", text), text

    def test_ppc64_fmadd_frsp(self):
        # std r3 ; fcfid f1 ; lfd f0 ; fcfid f0 ; fmadd f1, f1, f12, f0 ; frsp f1, f1 ; blr
        # the single-precision result travels in f1 as a double: a float return, not the low word of fpr1
        text = self._decompile("ppc64", "libc.so.6", 0x572930)
        assert text.startswith("float sub_572930(double a0, "), text
        assert re.search(r"return \(float\)\(.* \* .* \+ .*\);", text), text

    def test_ppc64_signbitf(self):
        # __signbitf: stfs f1, -0x10(r1) ; lwz r9, -0x10(r1) ; rlwinm r3, r9, 0, 0, 0
        text = self._decompile("ppc64", "libc.so.6", 0x45F768)
        assert "(float)" in text, text
        assert "0x80000000" in text, text


class TestX87LongDoubleLocal:
    """
    ``long double t = x * 3.0L; float y = (float)t;`` at -O0 (x87_ld_local_i386_O0.o): fstpt/fldt go through a
    10-byte stack local, which must be a long double and never be converted as an integer.
    """

    _BIN = "x87_ld_local_i386_O0.o"

    def test_local_is_long_double(self):
        text = _decompile_asm_func(self._BIN, "ld_local_to_f32")
        assert "uint80_t" not in text, text
        assert re.search(r"long double v\d+;", text), text
        assert re.search(r"v\d+ = a0 \* 3\.0L;", text), text
        assert re.search(r"v\d+ = \(float\)v\d+;", text), text

    def test_int_typed_local_is_viewed_as_long_double(self):
        # an 80-bit local forced to an integer type is read and written through its long double bit pattern
        path = os.path.join(_fp_dir, self._BIN)
        if not os.path.exists(path):
            pytest.skip(f"{path} not found")
        proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()(normalize=True, data_references=True)
        func = cfg.functions["ld_local_to_f32"]
        proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
        vm = proj.kb.dec_variables[func.addr]
        local = next(v for v in vm.get_variables() if isinstance(v, SimStackVariable) and v.size == 10 and v.offset < 0)
        vm.set_variable_type(local, SimTypeNum(80, signed=False).with_arch(proj.arch), mark_manual=True)
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, use_cache=False)
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert "uint80_t v1;" in text, text
        assert "(uint80_t)" not in text, text
        assert "*((long double *)&v1) = a0 * 3.0L;" in text, text
        assert "(float)*((long double *)&v1)" in text, text


def test_int_typed_register_variable_uses_reinterpret_helpers():
    # a register variable has no address: its bit-pattern views use __double_as_longlong / __longlong_as_double
    path = os.path.join(_fp_dir, "fp_reg_view_amd64.o")
    if not os.path.exists(path):
        pytest.skip(f"{path} not found")
    proj = angr.Project(path, auto_load_libs=False)
    cfg = proj.analyses[CFGFast].prep()(normalize=True, data_references=True)
    func = cfg.functions["int_sq"]
    proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
    vm = proj.kb.dec_variables[func.addr]
    xmm1 = proj.arch.registers["xmm1"][0]
    var = next(v for v in vm.get_variables() if isinstance(v, SimRegisterVariable) and v.reg == xmm1)
    vm.set_variable_type(var, SimTypeLongLong(signed=False).with_arch(proj.arch), mark_manual=True)
    dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, use_cache=False)
    assert dec.codegen is not None and dec.codegen.text is not None
    text = dec.codegen.text
    assert "*)&" not in text, text
    assert "v1 = __double_as_longlong((double)a0);" in text, text
    assert "return __longlong_as_double(v1) * __longlong_as_double(v1) + __longlong_as_double(v1);" in text, text


class TestClampThroughSlotPointers:
    """
    A [-1, 1] clamp that picks its result through pointers to two stack slots (lea/lea/cmovbe; movsd xmm0, [eax]). The
    upper-bound slot is only written with 1.0 and only read through the selected pointer.
    """

    def test_slot_written_by_movsd_is_double(self):
        text = _decompile_asm_func("fp_clamp_ref_i386.o", "clamp_ref")
        assert re.search(r"double v\d+;  // \[bp-0xc\]", text), text
        assert re.search(r"v\d+ = 1\.0;", text), text
        assert "0x3ff0000000000000" not in text and "unsigned long long" not in text, text

    def test_slot_written_by_int_immediate_is_double(self):
        text = _decompile_asm_func("fp_clamp_ref_amd64.o", "clamp_ref_imm")
        assert re.search(r"double v\d+;  // \[bp-0x10\]", text), text
        assert re.search(r"v\d+ = 1\.0;", text), text
        assert "0x3ff0000000000000" not in text, text
        # the store goes through the pointer argument, not into the argument variable
        assert re.search(r"\*\(\(double \*\)a\d\) = ", text), text

    def test_int_typed_slot_keeps_bit_pattern(self):
        # a double constant stored to a slot forced to an integer type is a bit copy, not a value conversion
        path = os.path.join(_fp_dir, "fp_clamp_ref_i386.o")
        if not os.path.exists(path):
            pytest.skip(f"{path} not found")
        proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses[CFGFast].prep()(normalize=True, data_references=True)
        func = cfg.functions["clamp_ref"]
        proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
        vm = proj.kb.dec_variables[func.addr]
        slot = vm.unified_variable(next(iter(vm.find_variables_by_stack_offset(-0xC))))
        assert slot is not None
        vm.set_variable_type(slot, SimTypeNum(64, signed=False).with_arch(proj.arch), mark_manual=True)
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, use_cache=False)
        assert dec.codegen is not None and dec.codegen.text is not None
        text = dec.codegen.text
        assert re.search(r"v\d+ = 0x3ff0000000000000;", text), text
        assert ")1.0;" not in text, text
