from __future__ import annotations

import os
import shutil
import subprocess
from functools import lru_cache

import pytest

import angr
from tests.common import bin_location

TEST_DIR = os.path.join(bin_location, "tests", "x86_64", "recompile_dataset")
PREAMBLE = "#include <stdint.h>\n#include <stdbool.h>\n\nvolatile unsigned int g_sink;\n\n"
TARGETS = {
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
CASES = [(binary_name, func_name) for binary_name, funcs in TARGETS.items() for func_name in funcs]


def _prepare_source(text: str) -> str:
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("extern") and "g_sink" in stripped:
            continue
        lines.append(line)
    return PREAMBLE + "\n".join(lines)


@lru_cache(maxsize=None)
def _decompile_binary(binary_name: str) -> dict[str, str]:
    bin_path = os.path.join(TEST_DIR, binary_name)
    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
    proj.analyses.CompleteCallingConventions(
        cfg=cfg.model,
        recover_variables=True,
        analyze_callsites=True,
    )

    results = {}
    for func_name in TARGETS[binary_name]:
        func = cfg.kb.functions.function(name=func_name)
        assert func is not None
        decompilation = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert decompilation.codegen is not None and decompilation.codegen.text is not None
        results[func_name] = decompilation.codegen.text
    return results


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc is not available")
@pytest.mark.parametrize(("binary_name", "func_name"), CASES)
def test_array_pointer_regressions_compile(binary_name: str, func_name: str, tmp_path) -> None:
    text = _decompile_binary(binary_name)[func_name]
    source = _prepare_source(text)
    c_path = tmp_path / f"{func_name}.c"
    obj_path = tmp_path / f"{func_name}.o"
    c_path.write_text(source, encoding="utf-8")

    result = subprocess.run(
        [
            "gcc",
            "-c",
            "-std=gnu11",
            "-Werror=implicit-function-declaration",
            "-Wno-unused-variable",
            "-Wno-unused-but-set-variable",
            "-o",
            str(obj_path),
            str(c_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
