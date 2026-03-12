"""Regression coverage for Issue 1 in the recompile-dataset suite.

These eight x86_64 gcc O1 functions previously decompiled local pointer
temporaries as arrays, producing invalid assignments like ``cur = &v0``.
The test keeps scope tight to that regression instead of treating the
entire recompile-dataset corpus as green.
"""

from __future__ import annotations

import os
import re
import subprocess
import textwrap

import pytest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests", "x86_64", "recompile_dataset")
src_location = os.path.join(bin_location, "tests_src", "recompile_dataset")

_CASES = [
    pytest.param(
        "t3_memory_gcc_O1",
        "t3_array_copy",
        id="x86_64/recompile_dataset/t3_memory_gcc_O1/t3_array_copy",
    ),
    pytest.param(
        "t3_memory_gcc_O1",
        "t3_array_max",
        id="x86_64/recompile_dataset/t3_memory_gcc_O1/t3_array_max",
    ),
    pytest.param(
        "t3_memory_gcc_O1",
        "t3_array_of_structs",
        id="x86_64/recompile_dataset/t3_memory_gcc_O1/t3_array_of_structs",
    ),
    pytest.param(
        "t3_memory_gcc_O1",
        "t3_array_reverse",
        id="x86_64/recompile_dataset/t3_memory_gcc_O1/t3_array_reverse",
    ),
    pytest.param(
        "t3_memory_gcc_O1",
        "t3_array_sum",
        id="x86_64/recompile_dataset/t3_memory_gcc_O1/t3_array_sum",
    ),
    pytest.param(
        "t3_memory_gcc_O1",
        "t3_matrix_trace",
        id="x86_64/recompile_dataset/t3_memory_gcc_O1/t3_matrix_trace",
    ),
    pytest.param(
        "t3_memory_gcc_O1",
        "t3_ptr_walk",
        id="x86_64/recompile_dataset/t3_memory_gcc_O1/t3_ptr_walk",
    ),
    pytest.param(
        "t5_patterns_gcc_O1",
        "t5_minmax",
        id="x86_64/recompile_dataset/t5_patterns_gcc_O1/t5_minmax",
    ),
]

_decompiled_cache: dict[str, dict[str, str]] = {}

_COMPILE_PREAMBLE = textwrap.dedent("""\
    #include <stdint.h>
    #include <stdbool.h>

    volatile unsigned int g_sink;

""")

_INPUTS = [
    (0, 0),
    (1, 2),
    (-1, 1),
    (0, -1),
    (127, 1),
    (-128, -128),
    (255, 255),
    (1000, -1000),
    (0x7FFFFFFF, 1),
    (0x7FFFFFFF, 0x7FFFFFFF),
    (-2147483648, 0),
    (-2147483648, -1),
    (42, 0),
    (0, 42),
    (3, 7),
    (-3, -7),
]
def _get_binary_path(bin_name: str) -> str:
    return os.path.join(test_location, bin_name)


def _get_source_path(bin_name: str) -> str:
    src_name = re.sub(r"_(gcc|clang|msvc)_.*$", "", bin_name)
    return os.path.join(src_location, f"{src_name}.c")


def _get_decompiled(bin_name: str) -> dict[str, str]:
    bin_path = _get_binary_path(bin_name)
    if bin_path in _decompiled_cache:
        return _decompiled_cache[bin_path]

    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
    proj.analyses.CompleteCallingConventions(
        cfg=cfg.model,
        recover_variables=True,
        analyze_callsites=True,
    )

    results = {}
    for func in cfg.kb.functions.values():
        if not func.name.startswith(("t3_", "t5_")) or func.is_plt or func.is_simprocedure:
            continue
        try:
            dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        except (AttributeError, KeyError, TypeError, ValueError):
            continue
        if dec.codegen and dec.codegen.text:
            results[func.name] = dec.codegen.text

    _decompiled_cache[bin_path] = results
    return results


def _strip_extern_gsink(text: str) -> str:
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("extern") and "g_sink" in stripped:
            continue
        lines.append(line)
    return "\n".join(lines)


def _prepare_source(text: str) -> str:
    return _COMPILE_PREAMBLE + _strip_extern_gsink(text)


def _try_compile(source: str, tmp_dir: str, name: str) -> tuple[bool, str]:
    c_path = os.path.join(tmp_dir, f"{name}.c")
    with open(c_path, "w", encoding="utf-8") as f:
        f.write(source)

    result = subprocess.run(
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
    return result.returncode == 0, result.stderr


def _count_args(text: str, func_name: str) -> int | None:
    match = re.search(re.escape(func_name) + r"\s*\(([^)]*)\)", text)
    if match is None:
        return None

    args = match.group(1).strip()
    if not args or args == "void":
        return 0
    return len([arg for arg in args.split(",") if arg.strip()])


def _generate_harness(func_name: str, decomp_body: str, decomp_nargs: int | None) -> str:
    decomp_name = f"decomp_{func_name}"
    test_arr = ", ".join(f"{{{a}, {b}}}" for a, b in _INPUTS)

    if decomp_nargs == 1:
        decomp_call = f"{decomp_name}(a)"
    elif decomp_nargs == 0:
        decomp_call = f"{decomp_name}()"
    else:
        decomp_call = f"{decomp_name}(a, b)"

    return textwrap.dedent(f"""\
        #include <stdio.h>
        #include <stdint.h>
        #include <stdbool.h>

        volatile int g_sink;

        int {func_name}(int32_t a, int32_t b);

        {decomp_body}

        int main(void) {{
            int tests[][2] = {{ {test_arr} }};
            int n = sizeof(tests) / sizeof(tests[0]);
            for (int i = 0; i < n; i++) {{
                int32_t a = (int32_t)tests[i][0];
                int32_t b = (int32_t)tests[i][1];
                {func_name}(a, b);
                unsigned int ref = (unsigned int)g_sink;
                {decomp_call};
                unsigned int dec = (unsigned int)g_sink;
                if (ref != dec) {{
                    fprintf(
                        stderr,
                        "MISMATCH %s(%d,%d): ref=%u dec=%u\\n",
                        "{func_name}",
                        tests[i][0],
                        tests[i][1],
                        ref,
                        dec
                    );
                    return 1;
                }}
            }}
            return 0;
        }}
    """)


def _check_semantics(bin_name: str, func_name: str, text: str, tmp_dir: str) -> None:
    src_path = _get_source_path(bin_name)
    ref_o = os.path.join(tmp_dir, "ref.o")
    result = subprocess.run(
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
    assert result.returncode == 0, f"Failed to compile reference:\n{result.stderr}"

    decomp_name = f"decomp_{func_name}"
    decomp_body = _strip_extern_gsink(text)
    decomp_body = re.sub(r"\b" + re.escape(func_name) + r"\b", decomp_name, decomp_body)

    harness_text = _generate_harness(func_name, decomp_body, _count_args(decomp_body, decomp_name))
    harness_c = os.path.join(tmp_dir, "harness.c")
    with open(harness_c, "w", encoding="utf-8") as f:
        f.write(harness_text)

    test_bin = os.path.join(tmp_dir, "test")
    result = subprocess.run(
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
    assert result.returncode == 0, f"Failed to compile harness:\n{result.stderr}\n\nHarness source:\n{harness_text}"

    result = subprocess.run([test_bin], capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, f"Semantic mismatch:\n{result.stderr}"


@pytest.mark.skipif(not os.path.isdir(test_location), reason="recompile-dataset binaries not found")
@pytest.mark.parametrize("bin_name,func_name", _CASES)
def test_recompile_dataset_issue1(bin_name: str, func_name: str, tmp_path) -> None:
    bin_path = _get_binary_path(bin_name)
    if not os.path.isfile(bin_path):
        pytest.skip(f"Missing binary: {bin_path}")

    decompiled = _get_decompiled(bin_name)
    if func_name not in decompiled:
        pytest.skip(f"No decompilation output for {func_name}")

    text = decompiled[func_name]
    compiled, stderr = _try_compile(_prepare_source(text), str(tmp_path), func_name)
    assert compiled, f"Compilation failed:\n{stderr}"

    _check_semantics(bin_name, func_name, text, str(tmp_path))
