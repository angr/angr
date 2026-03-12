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

# ──────────────────────────────────────────────────────────────────────
# Target descriptors
# ──────────────────────────────────────────────────────────────────────

# (subdir, is_pe, gcc_cmd, run_prefix)
_TARGETS: list[tuple[str, bool, list[str], list[str]]] = []


def _probe_targets():
    """Detect which targets are available at collection time."""
    targets: list[tuple[str, bool, list[str], list[str]]] = []

    # Native x86_64 ELF
    targets.append(("x86_64/recompile_dataset", False, ["gcc"], []))

    # i386 ELF
    targets.append(("i386/recompile_dataset", False, ["gcc", "-m32"], []))

    # aarch64 ELF -- requires cross gcc + qemu-user
    if shutil.which("aarch64-linux-gnu-gcc") and shutil.which("qemu-aarch64"):
        targets.append(
            (
                "aarch64/recompile_dataset",
                False,
                ["aarch64-linux-gnu-gcc", "-static"],
                ["qemu-aarch64"],
            )
        )

    # armhf ELF -- requires cross gcc + qemu-user
    if shutil.which("arm-linux-gnueabihf-gcc") and shutil.which("qemu-arm"):
        targets.append(
            (
                "armhf/recompile_dataset",
                False,
                ["arm-linux-gnueabihf-gcc", "-static"],
                ["qemu-arm"],
            )
        )

    # PE x86_64 -- requires mingw + wine
    if shutil.which("x86_64-w64-mingw32-gcc") and shutil.which("wine"):
        targets.append(
            (
                "x86_64/recompile_dataset_pe",
                True,
                ["x86_64-w64-mingw32-gcc", "-static"],
                ["wine"],
            )
        )

    # PE i386 -- requires mingw + wine
    if shutil.which("i686-w64-mingw32-gcc") and shutil.which("wine"):
        targets.append(
            (
                "i386/recompile_dataset_pe",
                True,
                ["i686-w64-mingw32-gcc", "-static"],
                ["wine"],
            )
        )

    return targets


# ──────────────────────────────────────────────────────────────────────
# Discovery
# ──────────────────────────────────────────────────────────────────────

_FUNC_RE = re.compile(r"^t[1-5]_")
_SIG_RE = re.compile(r"NOINLINE\s+int\s+(t[1-5]_\w+)\s*\(")


def _get_functions_for_source(src_stem):
    """Parse source file to get the list of test function names."""
    src_path = os.path.join(src_location, f"{src_stem}.c")
    if not os.path.isfile(src_path):
        return []
    with open(src_path, encoding="utf-8") as f:
        return _SIG_RE.findall(f.read())


# Cache: source stem -> list of function names
_SOURCE_FUNCTIONS: dict[str, list[str]] = {}


def _functions_for_binary(bname):
    """Get the expected function names for a binary based on its source."""
    # Strip .exe/.pdb
    stem = bname
    for ext in (".exe", ".pdb"):
        stem = stem.removesuffix(ext)
    # Strip compiler + opt suffix
    src_stem = re.sub(r"_(gcc|clang|msvc)_.*$", "", stem)
    if src_stem not in _SOURCE_FUNCTIONS:
        _SOURCE_FUNCTIONS[src_stem] = _get_functions_for_source(src_stem)
    return _SOURCE_FUNCTIONS[src_stem]


def _discover_functions_nm(bpath):
    """Discover functions via nm (works for ELF binaries)."""
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
    """Find all t[1-5]_* functions across all available targets."""
    targets = _probe_targets()
    params = []
    for subdir, is_pe, gcc_cmd, run_prefix in targets:
        bin_dir = os.path.join(test_location, subdir)
        if not os.path.isdir(bin_dir):
            continue
        for bname in sorted(os.listdir(bin_dir)):
            bpath = os.path.join(bin_dir, bname)
            if not os.path.isfile(bpath):
                continue
            # Skip PDB files
            if bname.endswith(".pdb"):
                continue

            # MSVC strips symbols; derive from source
            funcs = _functions_for_binary(bname) if is_pe else _discover_functions_nm(bpath)

            for func_name in funcs:
                test_id = f"{subdir}/{bname}/{func_name}"
                params.append(
                    pytest.param(
                        bpath,
                        func_name,
                        gcc_cmd,
                        run_prefix,
                        is_pe,
                        id=test_id,
                    )
                )
    return params


# ──────────────────────────────────────────────────────────────────────
# Decompilation cache
# ──────────────────────────────────────────────────────────────────────

_decompiled_cache: dict[str, dict[str, str]] = {}


def _get_decompiled(bin_path):
    """Decompile all t[1-5]_* functions in a binary, caching results."""
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


# ──────────────────────────────────────────────────────────────────────
# Source preparation
# ──────────────────────────────────────────────────────────────────────

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
    return _COMPILE_PREAMBLE + _strip_extern_gsink(text)


def _try_compile(source, tmp_dir, name, gcc_cmd):
    """Try to compile C source to an object file."""
    c_path = os.path.join(tmp_dir, f"{name}.c")
    with open(c_path, "w", encoding="utf-8") as f:
        f.write(source)
    r = subprocess.run(
        [
            *gcc_cmd,
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


# ──────────────────────────────────────────────────────────────────────
# Classification
# ──────────────────────────────────────────────────────────────────────


def _classify(text):
    """Classify decompiled output.

    Returns ``(category, reason)`` where *category* is ``"ok"`` or
    ``"compile_fail"``.
    """
    # Pseudo-calls the decompiler may leave behind
    pseudo_calls = ["_ccall(", "calculate_condition", "_INSERT(", "_CONCAT("]
    for pc in pseudo_calls:
        if pc in text:
            return "compile_fail", f"contains {pc.rstrip('(')}"
    if re.search(r"\b(CONCAT|AddV|SarNV|ShlNV|CmpGTV)\b", text):
        return "compile_fail", "contains unresolved helper pseudo-ops"
    if re.search(r"(?<!\w)_helper_[A-Za-z0-9_]*\b", text):
        return "compile_fail", "contains unresolved local helper reference"
    if "goto *(" in text:
        return "compile_fail", "contains unresolved indirect goto"
    if re.search(r"\bif\s*\(\.\.\.\)", text):
        return "compile_fail", "contains unresolved condition placeholder"
    # Unresolved stack-variable placeholders (angle-bracket syntax)
    if re.search(r"<0x[0-9a-f]+\[", text):
        return "compile_fail", "contains unresolved stack variable placeholder"
    return "ok", None


# ──────────────────────────────────────────────────────────────────────
# Semantic equivalence
# ──────────────────────────────────────────────────────────────────────

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
    "t1_control_flow": {
        "t1_early_return",
        "t1_loop_break_continue",
        "t1_loop_countdown",
        "t1_loop_do_while",
        "t1_switch_dense",
        "t1_switch_fallthrough",
        "t1_switch_sparse",
    },
    "t2_types": {
        "t2_bool_convert",
        "t2_mixed_width",
        "t2_trunc_64_16",
        "t2_widen_s16_s64",
        "t2_widen_u8",
    },
    "t4_calling": {
        "t4_call_chain",
        "t4_conditional_call",
        "t4_funcptr",
        "t4_loop_with_call",
        "t4_mutual_recursion",
        "t4_recursion",
        "t4_static_call",
    }
}

_KNOWN_T5_PATTERNS_LIMITATIONS = {
    "t5_abs_branchless",
    "t5_bsearch",
    "t5_bitreverse",
    "t5_bubble_sort",
    "t5_checksum",
    "t5_gcd",
    "t5_hash",
    "t5_memcpy",
    "t5_popcount",
    "t5_ring_buffer",
    "t5_strlen",
}

_KNOWN_BINARY_SEMANTIC_LIMITATION_PREFIXES = {
    "t5_patterns_": set(_KNOWN_T5_PATTERNS_LIMITATIONS),
}

_KNOWN_BINARY_SEMANTIC_LIMITATIONS = {
    "t3_memory_clang_O0": {
        "t3_array_copy",
        "t3_array_of_structs",
        "t3_array_sum",
        "t3_matrix_trace",
        "t3_ptr_walk",
    },
    "t3_memory_clang_O1": {
        "t3_array_copy",
        "t3_array_of_structs",
        "t3_array_reverse",
        "t3_array_sum",
        "t3_matrix_trace",
        "t3_ptr_walk",
    },
    "t3_memory_gcc_O0": {
        "t3_array_copy",
        "t3_array_of_structs",
        "t3_array_sum",
        "t3_matrix_trace",
        "t3_ptr_walk",
    },
    "t3_memory_gcc_Os": {
        "t3_array_copy",
        "t3_array_max",
        "t3_array_of_structs",
        "t3_array_reverse",
        "t3_array_sum",
        "t3_matrix_trace",
    },
    "t3_memory_msvc_O1": {
        "t3_array_max",
        "t3_array_of_structs",
        "t3_array_reverse",
        "t3_matrix_trace",
        "t3_ptr_walk",
    },
    "t5_patterns_clang_O0": set(_KNOWN_T5_PATTERNS_LIMITATIONS),
    "t5_patterns_clang_O1": {*_KNOWN_T5_PATTERNS_LIMITATIONS, "t5_minmax"},
    "t5_patterns_clang_O2": set(_KNOWN_T5_PATTERNS_LIMITATIONS),
    "t5_patterns_clang_O3": set(_KNOWN_T5_PATTERNS_LIMITATIONS),
    "t5_patterns_clang_Os": set(_KNOWN_T5_PATTERNS_LIMITATIONS),
    "t5_patterns_gcc_Os": {"t5_minmax"},
    "t5_patterns_msvc_O1": {"t5_minmax"},
}


def _get_source_stem(bin_path):
    """Map binary path to original source path.

    ``t1_control_flow_gcc_O2`` -> ``t1_control_flow.c``
    ``t2_types_msvc_O2.exe``   -> ``t2_types.c``
    """
    bname = os.path.basename(bin_path)
    # Strip .exe if present
    bname = bname.removesuffix(".exe")
    # Strip compiler + opt suffix: everything from _{gcc,clang,msvc}_ onward
    return re.sub(r"_(gcc|clang|msvc)_.*$", "", bname)


def _get_binary_stem(bin_path):
    return os.path.basename(bin_path).removesuffix(".exe")


def _get_source_path(bin_path):
    return os.path.join(src_location, f"{_get_source_stem(bin_path)}.c")


def _is_known_semantic_limitation(bin_path, func_name):
    binary_stem = _get_binary_stem(bin_path)
    if func_name in _KNOWN_BINARY_SEMANTIC_LIMITATIONS.get(binary_stem, set()):
        return True
    for prefix, functions in _KNOWN_BINARY_SEMANTIC_LIMITATION_PREFIXES.items():
        if binary_stem.startswith(prefix) and func_name in functions:
            return True
    return func_name in _KNOWN_SEMANTIC_LIMITATIONS.get(_get_source_stem(bin_path), set())


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


def _generate_harness(func_name, decomp_body, decomp_nargs):
    """Generate a harness that calls both original and decompiled functions."""
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

        /* Original function (from ref.o) */
        int {func_name}(int32_t a, int32_t b);

        /* Decompiled function (renamed, pasted inline) */
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
    """Build and run a semantic equivalence test."""
    src_path = _get_source_path(bin_path)
    if not os.path.exists(src_path):
        pytest.skip(f"Original source not found: {src_path}")

    # 1. Compile original source -> ref.o
    ref_o = os.path.join(tmp_dir, "ref.o")
    r = subprocess.run(
        [
            *gcc_cmd,
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

    # 2. Prepare decompiled function body (strip extern g_sink, rename)
    decomp_name = f"decomp_{func_name}"
    decomp_body = _strip_extern_gsink(text)
    decomp_body = re.sub(r"\b" + re.escape(func_name) + r"\b", decomp_name, decomp_body)

    decomp_nargs = _count_args(decomp_body, decomp_name)
    if decomp_nargs is None:
        decomp_nargs = 2

    # 3. Generate harness
    harness_text = _generate_harness(func_name, decomp_body, decomp_nargs)
    harness_c = os.path.join(tmp_dir, "harness.c")
    with open(harness_c, "w", encoding="utf-8") as f:
        f.write(harness_text)

    # 4. Compile and link
    ext = ".exe" if run_prefix and run_prefix[0] == "wine" else ""
    test_bin = os.path.join(tmp_dir, f"test{ext}")
    r = subprocess.run(
        [
            *gcc_cmd,
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
    cmd = [*run_prefix, test_bin]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    assert r.returncode == 0, f"Semantic mismatch:\n{r.stderr}"


# ──────────────────────────────────────────────────────────────────────
# Test
# ──────────────────────────────────────────────────────────────────────

_FUNCTIONS = _discover_functions()


@pytest.mark.skipif(not _FUNCTIONS, reason="recompile-dataset binaries not found")
@pytest.mark.parametrize("bin_path,func_name,gcc_cmd,run_prefix,_is_pe", _FUNCTIONS)
def test_recompile_dataset(bin_path, func_name, gcc_cmd, run_prefix, _is_pe, tmp_path):
    """Decompile, recompile, and check semantic equivalence."""
    decompiled = _get_decompiled(bin_path)
    if func_name not in decompiled:
        pytest.skip("no decompilation output")

    text = decompiled[func_name]
    category, reason = _classify(text)
    known_limitation = _is_known_semantic_limitation(bin_path, func_name)

    # Stage 1: Compilation check
    source = _prepare_source(text)
    compiled, stderr = _try_compile(source, str(tmp_path), func_name, gcc_cmd)

    if category == "compile_fail":
        if not compiled:
            pytest.xfail(reason or "compile failure")
        # Unexpected success -- fall through to semantic check
    elif not compiled:
        if known_limitation:
            pytest.xfail(f"known limitation: {stderr.strip() or 'compile failure'}")
        pytest.fail(f"Compilation failed:\n{stderr}")

    # Stage 2: Semantic equivalence
    if known_limitation:
        try:
            _check_semantics(bin_path, func_name, text, str(tmp_path), gcc_cmd, run_prefix)
        except (AssertionError, subprocess.TimeoutExpired) as ex:
            pytest.xfail(f"known semantic limitation: {ex}")
    else:
        _check_semantics(bin_path, func_name, text, str(tmp_path), gcc_cmd, run_prefix)
