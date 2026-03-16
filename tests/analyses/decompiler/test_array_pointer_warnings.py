from __future__ import annotations

import os
import re
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

_COMPILE_PREAMBLE = """\
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

volatile unsigned int g_sink;

"""

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


def _get_decompiled(bin_path: str) -> dict[str, str]:
    return _decompile_functions(bin_path, _TARGET_FUNCTIONS[bin_path])


def _prepare_source(text: str) -> str:
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("extern") and "g_sink" in stripped:
            continue
        lines.append(line)
    return _COMPILE_PREAMBLE + "\n".join(lines) + "\n"


def _try_compile(source: str, tmp_dir: str, func_name: str) -> tuple[bool, str]:
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


def _compile_shared(source: str, tmp_dir: str, func_name: str) -> tuple[bool, str, str]:
    c_path = os.path.join(tmp_dir, f"{func_name}.c")
    so_path = os.path.join(tmp_dir, f"{func_name}.so")
    with open(c_path, "w", encoding="utf-8") as f:
        f.write(source)

    result = subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-std=gnu11",
            "-O0",
            "-Wno-unused-variable",
            "-Wno-unused-but-set-variable",
            "-o",
            so_path,
            c_path,
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    return result.returncode == 0, result.stderr, so_path


def _i32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _reference_result(func_name: str, a: int, b: int) -> int:
    a = _i32(a)
    b = _i32(b)

    if func_name == "t3_array_sum":
        return _i32(sum(_i32(a + i * b) for i in range(8)))
    if func_name == "t3_array_reverse":
        arr = [_i32(a * (i + 1) + b) for i in range(8)]
        for i in range(4):
            arr[i], arr[7 - i] = arr[7 - i], arr[i]
        return _i32(arr[0] + arr[7])
    if func_name == "t3_array_max":
        return max(_i32((a ^ _i32(i * 0x9E3779B9)) + b) for i in range(8))
    if func_name == "t3_ptr_walk":
        return _i32(sum(_i32(a + i * b) for i in range(8)))
    if func_name == "t3_array_of_structs":
        result = 0
        for i in range(4):
            result = _i32(result + _i32(_i32(a + i) * _i32(b * (i + 1))))
        return result
    if func_name == "t3_matrix_trace":
        return _i32(sum(_i32(a * i + b * i) for i in range(4)))
    if func_name == "t3_array_copy":
        src = [_i32(a + i * b) for i in range(8)]
        return _i32(sum(src[7 - i] for i in range(8)))
    if func_name == "t5_minmax":
        arr = [_i32(a ^ _i32(i * 0x45D9F3B + b)) for i in range(8)]
        return _i32(max(arr) - min(arr))

    raise KeyError(func_name)


def _run_compiled_function(shared_object: str, func_name: str, a: int, b: int) -> tuple[int, int]:
    runner = textwrap.dedent(
        f"""
        import ctypes
        lib = ctypes.CDLL({shared_object!r})
        fn = lib.{func_name}
        fn.argtypes = [ctypes.c_ulonglong, ctypes.c_ulong]
        fn.restype = ctypes.c_longlong
        result = fn({a}, {b})
        sink = ctypes.c_uint.in_dll(lib, "g_sink").value
        print(result)
        print(sink)
        """
    )
    result = subprocess.run(
        ["python3", "-c", runner],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr or f"child exited with code {result.returncode}")
    stdout = result.stdout.splitlines()
    return int(stdout[0]), int(stdout[1])


@pytest.mark.parametrize("bin_path,func_name,decl_pattern", _TARGETS)
def test_array_pointer_codegen_compiles(bin_path, func_name, decl_pattern, tmp_path):
    if not os.path.isfile(bin_path):
        pytest.skip(f"Missing test binary: {bin_path}")

    text = _get_decompiled(bin_path)[func_name]

    if decl_pattern is not None:
        assert re.search(decl_pattern, text) is not None, text

    compiled, stderr = _try_compile(_prepare_source(text), str(tmp_path), func_name)
    assert compiled, stderr


@pytest.mark.parametrize("bin_path,func_name,_decl_pattern", _TARGETS)
def test_array_pointer_codegen_matches_reference(bin_path, func_name, _decl_pattern, tmp_path):
    if not os.path.isfile(bin_path):
        pytest.skip(f"Missing test binary: {bin_path}")

    compiled, stderr, so_path = _compile_shared(
        _prepare_source(_get_decompiled(bin_path)[func_name]), str(tmp_path), func_name
    )
    assert compiled, stderr

    for a, b in ((1, 2), (0xFFFFFFFF, 3)):
        result, sink = _run_compiled_function(so_path, func_name, a, b)
        expected = _reference_result(func_name, a, b)
        assert _i32(result) == expected, (func_name, a, b, result, expected)
        assert _i32(sink) == expected, (func_name, a, b, sink, expected)
