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

_TARGET_CASES = (
    (os.path.join(test_location, "t3_memory_gcc_O1"), "t3_array_copy", r"\bchar \(\*\w+\)\[4\];"),
    (os.path.join(test_location, "t3_memory_gcc_O1"), "t3_array_max", r"\bchar \(\*\w+\)\[4\];"),
    (os.path.join(test_location, "t3_memory_gcc_O1"), "t3_array_of_structs", r"\bunsigned int \(\*\w+\)\[2\];"),
    (os.path.join(test_location, "t3_memory_gcc_O1"), "t3_array_reverse", r"\bchar \(\*\w+\)\[4\];"),
    (os.path.join(test_location, "t3_memory_gcc_O1"), "t3_array_sum", r"\bchar \(\*\w+\)\[4\];"),
    (os.path.join(test_location, "t3_memory_gcc_O1"), "t3_matrix_trace", None),
    (os.path.join(test_location, "t3_memory_gcc_O1"), "t3_ptr_walk", None),
    (os.path.join(test_location, "t5_patterns_gcc_O1"), "t5_minmax", r"\bchar \(\*\w+\)\[4\];"),
)

_TARGETS = tuple(
    pytest.param(
        bin_path,
        func_name,
        decl_pattern,
        id=f"x86_64/recompile_dataset/{os.path.basename(bin_path)}/{func_name}",
    )
    for bin_path, func_name, decl_pattern in _TARGET_CASES
)

_TARGET_FUNCTIONS = {
    bin_path: {func_name for target_bin_path, func_name, _ in _TARGET_CASES if target_bin_path == bin_path}
    for bin_path, _, _ in _TARGET_CASES
}

_COMPILE_PREAMBLE = textwrap.dedent("""\
    #include <stdbool.h>
    #include <stdint.h>
    #include <stdlib.h>
    #include <string.h>

    volatile unsigned int g_sink;

""")

_POINTER_WARNING_PATTERNS = (
    "incompatible pointer type",
    "comparison of distinct pointer types lacks a cast",
    "cast from pointer to integer of different size",
)

_TEST_INPUTS = (
    (0, 0),
    (1, 2),
    (-3, 5),
    (7, -4),
    (13, 9),
    (-15, 6),
    (123, 17),
    (-256, 1),
    (512, -7),
    (1024, 33),
)

_decompiled_cache: dict[str, dict[str, str]] = {}


def _decompile_functions(bin_path: str, func_names: set[str]) -> dict[str, str]:
    assert func_names

    if bin_path in _decompiled_cache:
        cached = _decompiled_cache[bin_path]
        if func_names <= cached.keys():
            return {func_name: cached[func_name] for func_name in func_names}

    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
    proj.analyses.CompleteCallingConventions(
        cfg=cfg.model,
        recover_variables=True,
        analyze_callsites=True,
    )

    results = _decompiled_cache.setdefault(bin_path, {})
    for func_name in func_names:
        if func_name in results:
            continue
        func = cfg.kb.functions.function(name=func_name)
        assert func is not None, f"Function {func_name} not found in {bin_path}"

        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        results[func_name] = dec.codegen.text

    return {func_name: results[func_name] for func_name in func_names}


def _get_decompiled(bin_path):
    return _decompile_functions(bin_path, _TARGET_FUNCTIONS[bin_path])


def _prepare_source(text):
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("extern") and "g_sink" in stripped:
            continue
        lines.append(line)
    return _COMPILE_PREAMBLE + "\n".join(lines) + "\n"


def _try_compile(source, tmp_dir, func_name):
    c_path = os.path.join(tmp_dir, f"{func_name}.c")
    with open(c_path, "w", encoding="utf-8") as f:
        f.write(source)

    result = subprocess.run(
        [
            "gcc",
            "-c",
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror=incompatible-pointer-types",
            "-Werror=pointer-to-int-cast",
            "-Werror=implicit-function-declaration",
            "-Wno-unused-variable",
            "-Wno-unused-but-set-variable",
            "-o",
            os.path.join(tmp_dir, f"{func_name}.o"),
            c_path,
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    return result.returncode == 0, result.stderr


def _source_path_for_binary(bin_path: str) -> str:
    src_stem = re.sub(r"_(gcc|clang|msvc)_.*$", "", os.path.basename(bin_path))
    return os.path.join(src_location, f"{src_stem}.c")


def _build_semantic_harness(bin_path: str, func_name: str, decompiled_text: str) -> str:
    source_path = _source_path_for_binary(bin_path)
    with open(source_path, encoding="utf-8") as f:
        original_source = f.read()

    inputs = ",\n".join(f"        {{ {a}, {b} }}" for a, b in _TEST_INPUTS)
    return textwrap.dedent(
        f"""\
        #include <stdint.h>
        #include <stdio.h>
        #include <stdlib.h>

        volatile int orig_g_sink;
        #define g_sink orig_g_sink
        #define {func_name} orig_{func_name}
        {original_source}
        #undef {func_name}
        #undef g_sink

        #define g_sink dec_g_sink
        #define {func_name} dec_{func_name}
        {_prepare_source(decompiled_text)}
        #undef {func_name}
        #undef g_sink

        int main(void) {{
            static const int32_t cases[][2] = {{
        {inputs}
            }};

            for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {{
                int32_t a = cases[i][0];
                int32_t b = cases[i][1];

                orig_g_sink = 0;
                dec_g_sink = 0;

                uint32_t orig_ret = (uint32_t)orig_{func_name}(a, b);
                uint32_t dec_ret = (uint32_t)dec_{func_name}(a, b);
                uint32_t orig_sink = (uint32_t)orig_g_sink;
                uint32_t dec_sink = (uint32_t)dec_g_sink;

                if (orig_ret != dec_ret || orig_sink != dec_sink) {{
                    fprintf(
                        stderr,
                        "mismatch[%zu]: a=%d b=%d orig_ret=%u dec_ret=%u orig_sink=%u dec_sink=%u\\n",
                        i,
                        a,
                        b,
                        orig_ret,
                        dec_ret,
                        orig_sink,
                        dec_sink
                    );
                    return 1;
                }}
            }}

            return 0;
        }}
        """
    )


def _compile_and_run_semantic_harness(source: str, tmp_dir: str, func_name: str) -> tuple[bool, str]:
    c_path = os.path.join(tmp_dir, f"{func_name}_semantic.c")
    binary_path = os.path.join(tmp_dir, f"{func_name}_semantic")
    with open(c_path, "w", encoding="utf-8") as f:
        f.write(source)

    compile_result = subprocess.run(
        [
            "gcc",
            "-O0",
            "-std=gnu11",
            "-I",
            src_location,
            "-Werror=implicit-function-declaration",
            "-Wno-unused-variable",
            "-Wno-unused-but-set-variable",
            "-o",
            binary_path,
            c_path,
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    if compile_result.returncode != 0:
        return False, compile_result.stderr

    run_result = subprocess.run(
        [binary_path],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    return run_result.returncode == 0, run_result.stderr


@pytest.mark.parametrize("bin_path,func_name,decl_pattern", _TARGETS)
def test_array_pointer_codegen_is_warning_free(bin_path, func_name, decl_pattern, tmp_path):
    if not os.path.isfile(bin_path):
        pytest.skip(f"Missing test binary: {bin_path}")

    text = _get_decompiled(bin_path)[func_name]

    if decl_pattern is not None:
        assert re.search(decl_pattern, text) is not None, text
    assert re.search(r"(?:=|!=|==)\s*&stack_frame\.v\d+\b", text) is None, text

    compiled, stderr = _try_compile(_prepare_source(text), str(tmp_path), func_name)
    assert compiled, stderr
    for pattern in _POINTER_WARNING_PATTERNS:
        assert pattern not in stderr, stderr


@pytest.mark.parametrize("bin_path,func_name,_decl_pattern", _TARGETS)
def test_array_pointer_codegen_matches_source(bin_path, func_name, _decl_pattern, tmp_path):
    if not os.path.isfile(bin_path):
        pytest.skip(f"Missing test binary: {bin_path}")

    source_path = _source_path_for_binary(bin_path)
    if not os.path.isfile(source_path):
        pytest.skip(f"Missing source file: {source_path}")

    text = _get_decompiled(bin_path)[func_name]
    compiled, stderr = _compile_and_run_semantic_harness(
        _build_semantic_harness(bin_path, func_name, text),
        str(tmp_path),
        func_name,
    )
    assert compiled, stderr
