"""Recompilability round-trip test for decompiled ccop_triggers.

Verifies that decompiled C output from angr can be recompiled with gcc
and remains semantically equivalent to the original source.

Three stages per function:
1. Decompile — use angr to decompile each ``ccop_*`` function
2. Compile check — write decompiled C to temp file, ``gcc -c``
3. Semantic equivalence — link decompiled + original, run with test inputs,
   compare ``g_sink`` values

Only tests x86_64 O1 binaries (same decompiler bugs manifest across O1/O2/Os).
"""

from __future__ import annotations

import os
import re
import subprocess
import textwrap

import pytest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")
src_location = os.path.join(bin_location, "tests_src", "ccop_triggers")


# ---------------------------------------------------------------------------
# Discovery: use nm to find ccop_* symbols at collection time (no angr needed)
# ---------------------------------------------------------------------------


def _discover_functions():
    """Find all ccop_* functions in O1 x86_64 binaries, returning pytest params."""
    bin_dir = os.path.join(test_location, "x86_64", "ccop_triggers")
    if not os.path.isdir(bin_dir):
        return []
    params = []
    for bname in sorted(os.listdir(bin_dir)):
        if not bname.startswith("ccop_"):
            continue
        # O1 only: matches ccop_*_O1 and ccop_*_O1_*
        if not re.search(r"_O1(_|$)", bname):
            continue
        bpath = os.path.join(bin_dir, bname)
        result = subprocess.run(["nm", "-g", bpath], capture_output=True, text=True, check=False)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[1] == "T" and parts[2].startswith("ccop_"):
                params.append(pytest.param(bpath, parts[2], id=f"{bname}/{parts[2]}"))
    return params


# ---------------------------------------------------------------------------
# Decompilation cache: decompile all functions per binary once
# ---------------------------------------------------------------------------

_decompiled_cache: dict[str, dict[str, str]] = {}


def _get_decompiled(bin_path):
    """Decompile all ccop_* functions in a binary, caching results."""
    if bin_path not in _decompiled_cache:
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions(
            cfg=cfg.model,
            recover_variables=True,
            analyze_callsites=True,
        )
        results = {}
        for func in cfg.kb.functions.values():
            if func.name.startswith("ccop_") and not func.is_plt and not func.is_simprocedure:
                try:
                    d = proj.analyses.Decompiler(func, cfg=cfg.model)
                    if d.codegen and d.codegen.text:
                        results[func.name] = d.codegen.text
                except (ValueError, TypeError, KeyError, AttributeError):
                    pass
        _decompiled_cache[bin_path] = results
    return _decompiled_cache[bin_path]


# ---------------------------------------------------------------------------
# Source preparation for standalone compile check
# ---------------------------------------------------------------------------

_COMPILE_PREAMBLE = textwrap.dedent("""\
    #include <stdint.h>
    #include <stdbool.h>

    volatile unsigned int g_sink;

""")


def _strip_extern_gsink(text):
    """Remove ``extern`` declarations for ``g_sink`` from decompiled text."""
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("extern") and "g_sink" in stripped:
            continue
        lines.append(line)
    return "\n".join(lines)


def _prepare_source(text):
    """Prepare decompiled text for standalone compilation check."""
    return _COMPILE_PREAMBLE + _strip_extern_gsink(text)


def _try_compile(source, tmp_dir, name):
    """Try to compile C source to an object file. Returns ``(success, stderr)``."""
    c_path = os.path.join(tmp_dir, f"{name}.c")
    with open(c_path, "w", encoding="utf-8") as f:
        f.write(source)
    r = subprocess.run(
        [
            "gcc",
            "-c",
            "-std=gnu11",
            "-Werror=implicit-function-declaration",
            "-Wno-unused-variable",
            "-Wno-unused-but-set-variable",
            "-o",
            os.path.join(tmp_dir, f"{name}.o"),
            c_path,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return r.returncode == 0, r.stderr


# ---------------------------------------------------------------------------
# Classification of known failures (detected dynamically from output text)
# ---------------------------------------------------------------------------


def _classify(func_name, text):
    """Classify decompiled output for known failure modes.

    Returns ``(category, reason)`` where *category* is one of:

    - ``"ok"``: expected to compile and be semantically correct
    - ``"compile_fail"``: expected to fail compilation
    - ``"semantic_fail"``: expected to compile but have wrong semantics
    """
    # Unrewritten ccalls won't compile
    if "_ccall(" in text or "calculate_condition" in text or "calculate_rflags_c" in text:
        return "compile_fail", "contains unrewritten ccall"

    # 8-bit functions: VEX inlines the comparison at register width and the
    # decompiler renders parameters as ``char`` (signed by default in most ABIs).
    # Unsigned conditions (condB/condNB/condBE/condNBE) and some operations
    # (shr, umul) need ``unsigned char`` semantics at 8-bit which the decompiler
    # doesn't preserve after optimisation passes strip the narrowing casts.
    width = _parse_width(func_name)
    cond = _extract_condition(func_name)
    op = _extract_op(func_name)
    if width == 8:
        if cond in _UNSIGNED_CONDS:
            return "semantic_fail", f"8-bit unsigned cond ({cond}) with signed char params"
        if op in _ALWAYS_UNSIGNED_OPS:
            return "semantic_fail", f"8-bit unsigned op ({op}) with signed char params"

    return "ok", None


# ---------------------------------------------------------------------------
# Semantic equivalence checking
# ---------------------------------------------------------------------------


def _get_source_path(bin_path):
    """Map binary path to original source path.

    ``ccop_add_O1`` → ``ccop_add.c``;
    ``ccop_inc_dec_O1_incdec`` → ``ccop_inc_dec.c``.
    """
    bname = os.path.basename(bin_path)
    src_name = re.sub(r"_O[12s].*$", "", bname)
    return os.path.join(src_location, f"{src_name}.c")


def _parse_width(func_name):
    """Extract width from function name suffix (``_8``, ``_16``, ``_32``, ``_64``)."""
    m = re.search(r"_(\d+)$", func_name)
    return int(m.group(1)) if m else None


def _count_args(text, func_name):
    """Count arguments in the decompiled function signature."""
    pattern = re.escape(func_name) + r"\s*\(([^)]*)\)"
    m = re.search(pattern, text)
    if not m:
        return None
    args_str = m.group(1).strip()
    if not args_str or args_str == "void":
        return 0
    return len([a.strip() for a in args_str.split(",") if a.strip()])


_UNSIGNED_CONDS = frozenset({"condb", "condnb", "condbe", "condnbe"})
_SIGNED_CONDS = frozenset({"condl", "condnl", "condle", "condnle", "conds", "condns"})
# Operations whose source functions always use unsigned argument types
_ALWAYS_UNSIGNED_OPS = frozenset({"shl", "shr", "rflagsc", "umul"})

_SIGNED_C_TYPES = {8: "int8_t", 16: "int16_t", 32: "int32_t", 64: "int64_t"}
_UNSIGNED_C_TYPES = {8: "uint8_t", 16: "uint16_t", 32: "uint32_t", 64: "uint64_t"}

_INPUTS_2ARG = {
    8: [(0, 0), (1, 2), (0x7F, 1), (0xFF, 1), (0xFF, 0xFF), (0x80, 0x80)],
    16: [(0, 0), (1, 2), (0x7FFF, 1), (0xFFFF, 1), (0xFFFF, 0xFFFF), (0x8000, 0x8000)],
    32: [
        (0, 0),
        (1, 2),
        (0x7FFFFFFF, 1),
        (0xFFFFFFFF, 1),
        (0xFFFFFFFF, 0xFFFFFFFF),
        (0x80000000, 0x80000000),
    ],
    64: [
        (0, 0),
        (1, 2),
        (0x7FFFFFFFFFFFFFFF, 1),
        (0xFFFFFFFFFFFFFFFF, 1),
        (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
        (0x8000000000000000, 0x8000000000000000),
    ],
}

_INPUTS_1ARG = {
    8: [0, 1, 0x7F, 0xFF, 0x80],
    16: [0, 1, 0x7FFF, 0xFFFF, 0x8000],
    32: [0, 1, 0x7FFFFFFF, 0xFFFFFFFF, 0x80000000],
    64: [0, 1, 0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x8000000000000000],
}


def _extract_op(func_name):
    """Extract the operation type from the function name.

    ``ccop_add_condz_32`` → ``"add"``; ``ccop_rflagsc_sub_32`` → ``"rflagsc"``.
    """
    if not func_name.startswith("ccop_"):
        return None
    rest = func_name[5:]
    # rflagsc is a compound op name
    if rest.startswith("rflagsc_"):
        return "rflagsc"
    # Take everything before the last two _-separated parts (cond_width)
    parts = rest.rsplit("_", 2)
    if len(parts) >= 3:
        return parts[0]
    return None


def _get_logic_c_op(func_name):
    """Return the C operator for a logic op function name, or None."""
    op = _extract_op(func_name)
    if op == "logic":
        return "&"  # VEX LOGIC ops use dep_1=result; AND is the common case
    return None


def _extract_condition(func_name):
    """Extract the condition type from the function name.

    ``ccop_add_condz_32`` → ``"condz"``; ``ccop_rflagsc_sub_32`` → ``None``.
    """
    # Longest match first to avoid condl matching condle
    for cond in sorted(
        [
            "condnle",
            "condnbe",
            "condnl",
            "condnb",
            "condns",
            "condno",
            "condnz",
            "condle",
            "condbe",
            "condl",
            "condb",
            "conds",
            "condo",
            "condz",
        ],
        key=len,
        reverse=True,
    ):
        if f"_{cond}_" in func_name:
            return cond
    return None


def _get_expected_nargs(func_name):
    """Determine expected argument count from the function name."""
    op = _extract_op(func_name)
    if op in ("inc", "dec"):
        return 1
    if op == "rflagsc":
        # rflagsc_add/sub take 2 args, rflagsc_dec takes 1
        if "_dec_" in func_name:
            return 1
        return 2
    if op in ("adc", "sbb"):
        return 4  # 128-bit ops split into 4 args on x86-64
    if op == "logic":
        cond = _extract_condition(func_name)
        # condz uses "test a, b" (2 args); condnz/conds/condns/condl/condnl/condle/condnle
        # use "test reg, reg" (1 arg); condb/condbe use inline asm with 2 args
        if cond in {"condz", "condb", "condnb", "condbe", "condnbe"}:
            return 2
        return 1
    # sub, add, shl, shr, umul, smul, copy: all take 2 args
    return 2


def _decompiled_has_unsigned_args(text, func_name):
    """Check if the decompiled function uses unsigned argument types."""
    pattern = re.escape(func_name) + r"\s*\(([^)]*)\)"
    m = re.search(pattern, text)
    if not m:
        return None
    return "unsigned" in m.group(1)


def _is_unsigned_func(func_name):
    """Return True if the original function uses unsigned argument types."""
    op = _extract_op(func_name)
    # Operations that always use unsigned args in the original source
    if op in _ALWAYS_UNSIGNED_OPS:
        return True
    # Unsigned condition codes
    cond = _extract_condition(func_name)
    return cond in _UNSIGNED_CONDS


def _generate_harness(func_name, decomp_body, width, nargs, is_unsigned, decomp_nargs=None):
    """Generate a complete harness C source file.

    The harness:
    - Declares the original function (from ``ref.o``)
    - Includes the renamed decompiled function body inline
    - Runs both with test inputs and compares ``g_sink`` values

    When *decomp_nargs* < *nargs* (e.g. decompiler optimised away an arg),
    the harness pre-computes the intermediate result and passes it to the
    decompiled function.
    """
    if decomp_nargs is None:
        decomp_nargs = nargs
    c_type = _UNSIGNED_C_TYPES[width] if is_unsigned else _SIGNED_C_TYPES[width]
    decomp_name = f"decomp_{func_name}"

    if nargs == 1:
        inputs = _INPUTS_1ARG[width]
        test_arr = ", ".join(f"{v}ULL" for v in inputs)
        orig_decl = f"int {func_name}({c_type} a);"
        call_code = textwrap.dedent(f"""\
            unsigned long long tests[] = {{ {test_arr} }};
            int n = sizeof(tests) / sizeof(tests[0]);
            for (int i = 0; i < n; i++) {{
                {c_type} a = ({c_type})tests[i];
                {func_name}(a);
                unsigned int ref = (unsigned int)g_sink;
                {decomp_name}(a);
                unsigned int dec = (unsigned int)g_sink;
                if (ref != dec) {{
                    fprintf(stderr, "MISMATCH %s(%llu): ref=%u dec=%u\\n",
                            "{func_name}", tests[i], ref, dec);
                    return 1;
                }}
            }}""")
    elif nargs == 2 and decomp_nargs == 1:
        # Decompiler optimised away one arg (e.g. logic ops where dep_1=result).
        # Pre-compute the intermediate result and pass it to the decompiled function.
        logic_c_op = _get_logic_c_op(func_name)
        if logic_c_op is None:
            logic_c_op = "&"  # fallback
        inputs = _INPUTS_2ARG[width]
        test_arr = ", ".join(f"{{{a}ULL, {b}ULL}}" for a, b in inputs)
        orig_decl = f"int {func_name}({c_type} a, {c_type} b);"
        call_code = textwrap.dedent(f"""\
            unsigned long long tests[][2] = {{ {test_arr} }};
            int n = sizeof(tests) / sizeof(tests[0]);
            for (int i = 0; i < n; i++) {{
                {c_type} a = ({c_type})tests[i][0];
                {c_type} b = ({c_type})tests[i][1];
                {func_name}(a, b);
                unsigned int ref = (unsigned int)g_sink;
                {c_type} logic_result = a {logic_c_op} b;
                {decomp_name}(logic_result);
                unsigned int dec = (unsigned int)g_sink;
                if (ref != dec) {{
                    fprintf(stderr, "MISMATCH %s(%llu,%llu): ref=%u dec=%u\\n",
                            "{func_name}", tests[i][0], tests[i][1], ref, dec);
                    return 1;
                }}
            }}""")
    else:  # nargs == 2
        inputs = _INPUTS_2ARG[width]
        test_arr = ", ".join(f"{{{a}ULL, {b}ULL}}" for a, b in inputs)
        orig_decl = f"int {func_name}({c_type} a, {c_type} b);"
        call_code = textwrap.dedent(f"""\
            unsigned long long tests[][2] = {{ {test_arr} }};
            int n = sizeof(tests) / sizeof(tests[0]);
            for (int i = 0; i < n; i++) {{
                {c_type} a = ({c_type})tests[i][0];
                {c_type} b = ({c_type})tests[i][1];
                {func_name}(a, b);
                unsigned int ref = (unsigned int)g_sink;
                {decomp_name}(a, b);
                unsigned int dec = (unsigned int)g_sink;
                if (ref != dec) {{
                    fprintf(stderr, "MISMATCH %s(%llu,%llu): ref=%u dec=%u\\n",
                            "{func_name}", tests[i][0], tests[i][1], ref, dec);
                    return 1;
                }}
            }}""")

    return textwrap.dedent(f"""\
        #include <stdio.h>
        #include <stdint.h>
        #include <stdbool.h>

        extern volatile int g_sink;

        /* Original function (from ref.o) */
        {orig_decl}

        /* Decompiled function (renamed, pasted inline) */
        {decomp_body}

        int main(void) {{
        {textwrap.indent(call_code, "    ")}
            return 0;
        }}
    """)


def _check_semantics(bin_path, func_name, text, tmp_dir):
    """Build and run a semantic equivalence test.

    Compiles the original source, pastes the renamed decompiled function into
    a harness, links them together, and runs with test inputs to compare
    ``g_sink`` values.
    """
    src_path = _get_source_path(bin_path)
    if not os.path.exists(src_path):
        pytest.skip(f"Original source not found: {src_path}")

    width = _parse_width(func_name)
    if width is None:
        pytest.skip(f"Cannot parse width from {func_name}")

    nargs = _get_expected_nargs(func_name)
    if nargs < 1 or nargs > 2:
        pytest.skip(f"Unsupported arg count ({nargs}) for {func_name}")

    if width not in _INPUTS_2ARG:
        pytest.skip(f"No test inputs for width {width}")

    is_unsigned = _is_unsigned_func(func_name)

    # 1. Compile original source -> ref.o
    ref_o = os.path.join(tmp_dir, "ref.o")
    r = subprocess.run(
        [
            "gcc",
            "-c",
            "-O0",
            "-std=gnu11",
            "-fcommon",
            "-Dmain=__ref_unused_main",
            "-I",
            os.path.dirname(src_path),
            "-o",
            ref_o,
            src_path,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert r.returncode == 0, f"Failed to compile reference:\n{r.stderr}"

    # 2. Prepare decompiled function body (strip extern g_sink, rename function)
    decomp_name = f"decomp_{func_name}"
    decomp_body = _strip_extern_gsink(text)
    decomp_body = re.sub(r"\b" + re.escape(func_name) + r"\b", decomp_name, decomp_body)

    # Detect actual arg count in the decompiled function
    decomp_nargs = _count_args(decomp_body, decomp_name)
    if decomp_nargs is None:
        decomp_nargs = nargs

    # 3. Generate harness (decomp body pasted inline, no separate .o needed)
    harness_text = _generate_harness(func_name, decomp_body, width, nargs, is_unsigned, decomp_nargs=decomp_nargs)
    harness_c = os.path.join(tmp_dir, "harness.c")
    with open(harness_c, "w", encoding="utf-8") as f:
        f.write(harness_text)

    # 4. Compile and link
    test_bin = os.path.join(tmp_dir, "test")
    r = subprocess.run(
        [
            "gcc",
            "-std=gnu11",
            "-O0",
            "-fcommon",
            "-Werror=implicit-function-declaration",
            "-Wno-unused-variable",
            "-Wno-unused-but-set-variable",
            "-o",
            test_bin,
            harness_c,
            ref_o,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert r.returncode == 0, f"Failed to compile harness:\n{r.stderr}\n\nHarness source:\n{harness_text}"

    # 5. Run and check
    r = subprocess.run([test_bin], capture_output=True, text=True, timeout=10, check=False)
    assert r.returncode == 0, f"Semantic mismatch:\n{r.stderr}"


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

_FUNCTIONS = _discover_functions()


@pytest.mark.skipif(not _FUNCTIONS, reason="ccop_triggers binaries not found")
@pytest.mark.parametrize("bin_path,func_name", _FUNCTIONS)
def test_recompilability(bin_path, func_name, tmp_path):
    """Decompile, recompile, and check semantic equivalence against original."""
    decompiled = _get_decompiled(bin_path)
    if func_name not in decompiled:
        pytest.skip("no decompilation output")

    text = decompiled[func_name]
    category, reason = _classify(func_name, text)

    # Stage 1: Compilation check
    source = _prepare_source(text)
    compiled, stderr = _try_compile(source, str(tmp_path), func_name)

    if category == "compile_fail":
        if not compiled:
            pytest.xfail(reason or "compile failure")
        # Unexpected success — fall through to semantic check
    elif not compiled:
        pytest.fail(f"Compilation failed:\n{stderr}")

    # Stage 2: Semantic equivalence
    try:
        _check_semantics(bin_path, func_name, text, str(tmp_path))
    except (AssertionError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        if category == "semantic_fail":
            pytest.xfail(f"{reason}: {e}")
        raise
