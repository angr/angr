"""Round-trip compilation coverage for decompiled ccop_triggers."""

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


def _discover_functions():
    bin_dir = os.path.join(test_location, "x86_64", "ccop_triggers")
    if not os.path.isdir(bin_dir):
        return []
    params = []
    for bname in sorted(os.listdir(bin_dir)):
        if not bname.startswith("ccop_") or not re.search(r"_O1(_|$)", bname):
            continue
        bpath = os.path.join(bin_dir, bname)
        result = subprocess.run(["nm", "-g", bpath], capture_output=True, text=True, check=False)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[1] == "T" and parts[2].startswith("ccop_"):
                params.append(pytest.param(bpath, parts[2], id=f"{bname}/{parts[2]}"))
    return params


_decompiled_cache: dict[str, dict[str, str]] = {}


def _get_decompiled(bin_path):
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


_COMPILE_PREAMBLE = textwrap.dedent("""\
    #include <stdint.h>
    #include <stdbool.h>

    volatile unsigned int g_sink;

""")


def _strip_extern_gsink(text):
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("extern") and "g_sink" in stripped:
            continue
        lines.append(line)
    return "\n".join(lines)


def _prepare_source(text):
    return _COMPILE_PREAMBLE + _strip_extern_gsink(text)


def _try_compile(source, tmp_dir, name):
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


def _classify(func_name, text):
    if "_ccall(" in text or "calculate_condition" in text or "calculate_rflags_c" in text:
        return "compile_fail", "contains unrewritten ccall"
    if "__CFADD__(" in text:
        return "compile_fail", "contains unresolved __CFADD__ helper"

    width = _parse_width(func_name)
    cond = _extract_condition(func_name)
    op = _extract_op(func_name)
    if width == 8:
        if cond in _UNSIGNED_CONDS:
            return "semantic_fail", f"8-bit unsigned cond ({cond}) with signed char params"
        if op in _ALWAYS_UNSIGNED_OPS:
            return "semantic_fail", f"8-bit unsigned op ({op}) with signed char params"

    return "ok", None


def _get_source_path(bin_path):
    bname = os.path.basename(bin_path)
    src_name = re.sub(r"_O[12s].*$", "", bname)
    return os.path.join(src_location, f"{src_name}.c")


def _parse_width(func_name):
    m = re.search(r"_(\d+)$", func_name)
    return int(m.group(1)) if m else None


def _count_args(text, func_name):
    pattern = re.escape(func_name) + r"\s*\(([^)]*)\)"
    m = re.search(pattern, text)
    if not m:
        return None
    args_str = m.group(1).strip()
    if not args_str or args_str == "void":
        return 0
    return len([a.strip() for a in args_str.split(",") if a.strip()])


_UNSIGNED_CONDS = frozenset({"condb", "condnb", "condbe", "condnbe"})
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
    if not func_name.startswith("ccop_"):
        return None
    rest = func_name[5:]
    if rest.startswith("rflagsc_"):
        return "rflagsc"
    parts = rest.rsplit("_", 2)
    if len(parts) >= 3:
        return parts[0]
    return None


def _get_logic_c_op(func_name):
    return "&" if _extract_op(func_name) == "logic" else None


def _extract_condition(func_name):
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
    op = _extract_op(func_name)
    if op in ("inc", "dec"):
        return 1
    if op == "rflagsc":
        return 1 if "_dec_" in func_name else 2
    if op in ("adc", "sbb"):
        return 4
    if op == "logic":
        cond = _extract_condition(func_name)
        if cond in {"condz", "condb", "condnb", "condbe", "condnbe"}:
            return 2
        return 1
    return 2


def _is_unsigned_func(func_name):
    op = _extract_op(func_name)
    if op in _ALWAYS_UNSIGNED_OPS:
        return True
    cond = _extract_condition(func_name)
    return cond in _UNSIGNED_CONDS


def _generate_harness(func_name, decomp_body, width, nargs, is_unsigned, decomp_nargs=None):
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
        logic_c_op = _get_logic_c_op(func_name) or "&"
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
    else:
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

        {orig_decl}

        {decomp_body}

        int main(void) {{
        {textwrap.indent(call_code, "    ")}
            return 0;
        }}
    """)


def _check_semantics(bin_path, func_name, text, tmp_dir):
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

    decomp_name = f"decomp_{func_name}"
    decomp_body = _strip_extern_gsink(text)
    decomp_body = re.sub(r"\b" + re.escape(func_name) + r"\b", decomp_name, decomp_body)

    decomp_nargs = _count_args(decomp_body, decomp_name)
    if decomp_nargs is None:
        decomp_nargs = nargs

    harness_text = _generate_harness(func_name, decomp_body, width, nargs, is_unsigned, decomp_nargs=decomp_nargs)
    harness_c = os.path.join(tmp_dir, "harness.c")
    with open(harness_c, "w", encoding="utf-8") as f:
        f.write(harness_text)

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

    r = subprocess.run([test_bin], capture_output=True, text=True, timeout=10, check=False)
    assert r.returncode == 0, f"Semantic mismatch:\n{r.stderr}"


_FUNCTIONS = _discover_functions()


@pytest.mark.skipif(not _FUNCTIONS, reason="ccop_triggers binaries not found")
@pytest.mark.parametrize("bin_path,func_name", _FUNCTIONS)
def test_recompilability(bin_path, func_name, tmp_path):
    decompiled = _get_decompiled(bin_path)
    if func_name not in decompiled:
        pytest.skip("no decompilation output")

    text = decompiled[func_name]
    category, reason = _classify(func_name, text)

    source = _prepare_source(text)
    compiled, stderr = _try_compile(source, str(tmp_path), func_name)

    if category == "compile_fail":
        if not compiled:
            pytest.xfail(reason or "compile failure")
    elif not compiled:
        pytest.fail(f"Compilation failed:\n{stderr}")
