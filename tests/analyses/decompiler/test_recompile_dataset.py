"""Compile regression tests for recompile-dataset stack arrays.

This test file intentionally stays narrow: it covers the eight x86_64 gcc -O1
functions that previously emitted invalid array declarations like
``char cur[4]; cur = &v0;``. The goal is to verify that the decompiler output
recompiles cleanly without masking unrelated semantic failures behind broad
``xfail`` matrices.
"""

from __future__ import annotations

import os
import subprocess
import textwrap

import pytest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

_TARGET_FUNCTIONS = {
    "t3_memory_gcc_O1": (
        "t3_array_copy",
        "t3_array_max",
        "t3_array_of_structs",
        "t3_array_reverse",
        "t3_array_sum",
        "t3_matrix_trace",
        "t3_ptr_walk",
    ),
    "t5_patterns_gcc_O1": ("t5_minmax",),
}

_COMPILE_PREAMBLE = textwrap.dedent("""\
    #include <stdint.h>
    #include <stdbool.h>

    volatile unsigned int g_sink;

""")


def _discover_functions():
    bin_dir = os.path.join(test_location, "x86_64", "recompile_dataset")
    if not os.path.isdir(bin_dir):
        return []

    params = []
    for binary_name, funcs in _TARGET_FUNCTIONS.items():
        bin_path = os.path.join(bin_dir, binary_name)
        if not os.path.isfile(bin_path):
            continue
        for func_name in funcs:
            params.append(
                pytest.param(
                    bin_path,
                    func_name,
                    id=f"x86_64/recompile_dataset/{binary_name}/{func_name}",
                )
            )
    return params


_FUNCTIONS = _discover_functions()
_DECOMPILED_CACHE: dict[str, dict[str, str]] = {}


def _get_decompiled(bin_path: str) -> dict[str, str]:
    if bin_path in _DECOMPILED_CACHE:
        return _DECOMPILED_CACHE[bin_path]

    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
    proj.analyses.CompleteCallingConventions(
        cfg=cfg.model,
        recover_variables=True,
        analyze_callsites=True,
    )

    results: dict[str, str] = {}
    for func in cfg.kb.functions.values():
        if (
            func.name in _TARGET_FUNCTIONS.get(os.path.basename(bin_path), ())
            and not func.is_plt
            and not func.is_simprocedure
        ):
            try:
                dec = proj.analyses.Decompiler(func, cfg=cfg.model)
            except (AttributeError, KeyError, TypeError, ValueError):
                continue
            if dec.codegen and dec.codegen.text:
                results[func.name] = dec.codegen.text

    _DECOMPILED_CACHE[bin_path] = results
    return results


def _prepare_source(text: str) -> str:
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("extern") and "g_sink" in stripped:
            continue
        lines.append(line)
    return _COMPILE_PREAMBLE + "\n".join(lines)


def _try_compile(source: str, tmp_dir: str, func_name: str) -> tuple[bool, str]:
    c_path = os.path.join(tmp_dir, f"{func_name}.c")
    o_path = os.path.join(tmp_dir, f"{func_name}.o")
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
            o_path,
            c_path,
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return result.returncode == 0, result.stderr


@pytest.mark.skipif(not _FUNCTIONS, reason="recompile-dataset binaries not found")
@pytest.mark.parametrize("bin_path,func_name", _FUNCTIONS)
def test_recompile_dataset(bin_path, func_name, tmp_path):
    decompiled = _get_decompiled(bin_path)
    if func_name not in decompiled:
        pytest.skip("no decompilation output")

    compiled, stderr = _try_compile(_prepare_source(decompiled[func_name]), str(tmp_path), func_name)
    assert compiled, f"Compilation failed for {os.path.basename(bin_path)}::{func_name}:\n{stderr}"
