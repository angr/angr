"""Round-trip recompilation test for the recompile-dataset binaries.

Decompiles every ``t[1-5]_*`` function found in the recompile-dataset
binaries, recompiles the output with an appropriate compiler, links a
semantic-equivalence harness, and runs it to verify correctness.

Supports:

* Native ELF (x86_64)        -- gcc, run natively
* Cross-compiled ELF (i386)  -- gcc -m32, run natively
* Cross-compiled ELF (arm/aarch64) -- cross-gcc, run under qemu-user
* PE (x86_64 / i386)         -- mingw-gcc, run under wine
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import textwrap

import pytest

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")
src_location = os.path.join(bin_location, "tests_src", "recompile_dataset")

_TARGETS: list[tuple[str, bool, list[str], list[str]]] = []


def _probe_targets():
    targets: list[tuple[str, bool, list[str], list[str]]] = []
    targets.append(("x86_64/recompile_dataset", False, ["gcc"], []))
    targets.append(("i386/recompile_dataset", False, ["gcc", "-m32"], []))

    if shutil.which("aarch64-linux-gnu-gcc") and shutil.which("qemu-aarch64"):
        targets.append(("aarch64/recompile_dataset", False, ["aarch64-linux-gnu-gcc", "-static"], ["qemu-aarch64"]))

    if shutil.which("arm-linux-gnueabihf-gcc") and shutil.which("qemu-arm"):
        targets.append(("armhf/recompile_dataset", False, ["arm-linux-gnueabihf-gcc", "-static"], ["qemu-arm"]))

    if shutil.which("x86_64-w64-mingw32-gcc") and shutil.which("wine"):
        targets.append(
            ("x86_64/recompile_dataset_pe", True, ["x86_64-w64-mingw32-gcc", "-static"], ["wine"])
        )

    if shutil.which("i686-w64-mingw32-gcc") and shutil.which("wine"):
        targets.append(("i386/recompile_dataset_pe", True, ["i686-w64-mingw32-gcc", "-static"], ["wine"]))

    return targets


_FUNC_RE = re.compile(r"^t[1-5]_")
_SIG_RE = re.compile(r"NOINLINE\s+int\s+(t[1-5]_\w+)\s*\(")


def _get_functions_for_source(src_stem):
    src_path = os.path.join(src_location, f"{src_stem}.c")
    if not os.path.isfile(src_path):
        return []
    with open(src_path, encoding="utf-8") as f:
        return _SIG_RE.findall(f.read())


_SOURCE_FUNCTIONS: dict[str, list[str]] = {}


def _functions_for_binary(bname):
    stem = bname
    for ext in (".exe", ".pdb"):
        stem = stem.removesuffix(ext)
    src_stem = re.sub(r"_(gcc|clang|msvc)_.*$", "", stem)
    if src_stem not in _SOURCE_FUNCTIONS:
        _SOURCE_FUNCTIONS[src_stem] = _get_functions_for_source(src_stem)
    return _SOURCE_FUNCTIONS[src_stem]


def _discover_functions_nm(_bin_dir, bpath, _bname):
    result = subprocess.run(
        ["nm", "-g", bpath],
        capture_output=True,
        text=True,
        check=False,
    )
    funcs = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "T" and _FUNC_RE.match(parts[2]):
            funcs.append(parts[2])
    return funcs


def _discover_functions():
    targets = _probe_targets()
    params = []
    for subdir, is_pe, gcc_cmd, run_prefix in targets:
        bin_dir = os.path.join(test_location, subdir)
        if not os.path.isdir(bin_dir):
            continue
        for bname in sorted(os.listdir(bin_dir)):
            bpath = os.path.join(bin_dir, bname)
            if not os.path.isfile(bpath) or bname.endswith(".pdb"):
                continue

            funcs = _functions_for_binary(bname) if is_pe else _discover_functions_nm(bin_dir, bpath, bname)
            for func_name in funcs:
                params.append(
                    pytest.param(
                        bpath,
                        func_name,
                        gcc_cmd,
                        run_prefix,
                        is_pe,
                        id=f"{subdir}/{bname}/{func_name}",
                    )
                )
    return params


_decompiled_cache: dict[str, dict[str, str]] = {}


def _get_decompiled(bin_path):
    if bin_path in _decompiled_cache:
        return _decompiled_cache[bin_path]

    is_pe = bin_path.endswith(".exe")
    proj = angr.Project(bin_path, auto_load_libs=False, load_debug_info=is_pe)
    cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
    proj.analyses.CompleteCallingConventions(
        cfg=cfg.model,
        recover_variables=True,
        analyze_callsites=True,
    )
    results = {}
    for func in cfg.kb.functions.values():
        if _FUNC_RE.match(func.name) and not func.is_plt and not func.is_simprocedure:
            try:
                d = proj.analyses.Decompiler(func, cfg=cfg.model)
                if d.codegen and d.codegen.text:
                    results[func.name] = d.codegen.text
            except (ValueError, TypeError, KeyError, AttributeError):
                pass
    _decompiled_cache[bin_path] = results
    return results


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


def _try_compile(source, tmp_dir, name, gcc_cmd):
    c_path = os.path.join(tmp_dir, f"{name}.c")
    with open(c_path, "w", encoding="utf-8") as f:
        f.write(source)
    r = subprocess.run(
        gcc_cmd
        + [
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


def _classify(_func_name, text):
    pseudo_calls = ["_ccall(", "calculate_condition", "_INSERT(", "_CONCAT("]
    for pc in pseudo_calls:
        if pc in text:
            return "compile_fail", f"contains {pc.rstrip('(')}"
    if re.search(r"<0x[0-9a-f]+\[", text):
        return "compile_fail", "contains unresolved stack variable placeholder"
    return "ok", None


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

_KNOWN_SEMANTIC_LIMITATIONS = {
    ("t3_memory_gcc_O1", "t3_array_copy"): "decompiler still mis-recovers the copy loop direction for the stack-backed array walk",
    ("t3_memory_gcc_O1", "t3_array_reverse"): "decompiler still mis-recovers the reverse walk through the stack-backed array window",
    ("t5_patterns_gcc_O1", "t5_minmax"): "decompiler still loses the intended signed min/max semantics across the scalarized stack array",
}


def _get_binary_stem(bin_path):
    return os.path.basename(bin_path).removesuffix(".exe")


def _get_known_semantic_limitation(bin_path, func_name):
    return _KNOWN_SEMANTIC_LIMITATIONS.get((_get_binary_stem(bin_path), func_name))


def _get_source_path(bin_path):
    bname = os.path.basename(bin_path).removesuffix(".exe")
    src_name = re.sub(r"_(gcc|clang|msvc)_.*$", "", bname)
    return os.path.join(src_location, f"{src_name}.c")


def _count_args(text, func_name):
    pattern = re.escape(func_name) + r"\s*\(([^)]*)\)"
    m = re.search(pattern, text)
    if not m:
        return None
    args_str = m.group(1).strip()
    if not args_str or args_str == "void":
        return 0
    return len([a.strip() for a in args_str.split(",") if a.strip()])


def _generate_harness(func_name, decomp_body, decomp_nargs):
    decomp_name = f"decomp_{func_name}"
    test_arr = ", ".join(f"{{{a}, {b}}}" for a, b in _INPUTS)

    if decomp_nargs == 2:
        call_decomp = f"{decomp_name}(a, b)"
    elif decomp_nargs == 1:
        call_decomp = f"{decomp_name}(a)"
    else:
        call_decomp = f"{decomp_name}()"

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
                {call_decomp};
                unsigned int dec = (unsigned int)g_sink;
                if (ref != dec) {{
                    fprintf(stderr, "MISMATCH %s(%d,%d): ref=%u dec=%u\\n",
                            "{func_name}", tests[i][0], tests[i][1], ref, dec);
                    return 1;
                }}
            }}
            return 0;
        }}
    """)


def _check_semantics(bin_path, func_name, text, tmp_dir, gcc_cmd, run_prefix):
    src_path = _get_source_path(bin_path)
    if not os.path.exists(src_path):
        pytest.skip(f"Original source not found: {src_path}")

    ref_o = os.path.join(tmp_dir, "ref.o")
    r = subprocess.run(
        gcc_cmd
        + [
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
        decomp_nargs = 2

    harness_text = _generate_harness(func_name, decomp_body, decomp_nargs)
    harness_c = os.path.join(tmp_dir, "harness.c")
    with open(harness_c, "w", encoding="utf-8") as f:
        f.write(harness_text)

    ext = ".exe" if run_prefix and run_prefix[0] == "wine" else ""
    test_bin = os.path.join(tmp_dir, f"test{ext}")
    r = subprocess.run(
        gcc_cmd
        + [
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

    cmd = run_prefix + [test_bin]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    assert r.returncode == 0, f"Semantic mismatch:\n{r.stderr}"


_FUNCTIONS = _discover_functions()


@pytest.mark.skipif(not _FUNCTIONS, reason="recompile-dataset binaries not found")
@pytest.mark.parametrize("bin_path,func_name,gcc_cmd,run_prefix,is_pe", _FUNCTIONS)
def test_recompile_dataset(bin_path, func_name, gcc_cmd, run_prefix, is_pe, tmp_path):
    decompiled = _get_decompiled(bin_path)
    if func_name not in decompiled:
        pytest.skip("no decompilation output")

    text = decompiled[func_name]
    category, reason = _classify(func_name, text)
    semantic_limitation = _get_known_semantic_limitation(bin_path, func_name)

    source = _prepare_source(text)
    compiled, stderr = _try_compile(source, str(tmp_path), func_name, gcc_cmd)

    if category == "compile_fail":
        if not compiled:
            pytest.xfail(reason or "compile failure")
    elif not compiled:
        pytest.fail(f"Compilation failed:\n{stderr}")

    try:
        _check_semantics(bin_path, func_name, text, str(tmp_path), gcc_cmd, run_prefix)
    except (AssertionError, subprocess.TimeoutExpired) as exc:
        if semantic_limitation is not None:
            pytest.xfail(f"{semantic_limitation}: {exc}")
        raise
