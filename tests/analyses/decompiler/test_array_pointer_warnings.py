from __future__ import annotations

import os
import re
import shutil
import subprocess
import textwrap

import pytest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests", "x86_64", "recompile_dataset")

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

    results = {}
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
            "-Werror",
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


def test_stack_array_regrouping_is_path_independent(tmp_path):
    bin_path = os.path.join(test_location, "t5_patterns_gcc_O1")
    if not os.path.isfile(bin_path):
        pytest.skip(f"Missing test binary: {bin_path}")

    copied_path = tmp_path / "t5_patterns_gcc_O1_copy"
    shutil.copy2(bin_path, copied_path)

    func_names = {"t5_bsearch", "t5_memcpy"}
    original = _decompile_functions(bin_path, func_names)
    copied = _decompile_functions(str(copied_path), func_names)

    assert original == copied
