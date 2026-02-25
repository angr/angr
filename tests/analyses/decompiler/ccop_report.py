#!/usr/bin/env python3
"""Generate an original-C vs decompiled report for all ccop_triggers functions."""

from __future__ import annotations

import os
import re
import sys
import angr

TRIGGERS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ccop_triggers")
BIN_DIRS = {
    "amd64": os.path.join(TRIGGERS_DIR, "bin", "amd64"),
    "i386": os.path.join(TRIGGERS_DIR, "bin", "i386"),
}

# Which opt level to use for the report (O2 produces the most interesting output)
OPT = "O2"


def extract_c_functions(src_path):
    """Extract NOINLINE function bodies from a C source file.

    Returns {func_name: source_text} including the signature and closing brace.
    Handles #ifdef blocks by including the guard as context.
    """
    with open(src_path, encoding="utf-8") as f:
        lines = f.readlines()

    funcs = {}
    i = 0
    ifdef_stack = []

    while i < len(lines):
        line = lines[i]

        # Track #ifdef/#else/#endif for context
        stripped = line.strip()
        if stripped.startswith(("#ifdef", "#ifndef")):
            ifdef_stack.append(stripped)
        elif stripped.startswith("#else"):
            if ifdef_stack:
                top = ifdef_stack[-1]
                ifdef_stack[-1] = f"#else /* !({top.split(None, 1)[-1]}) */"
        elif stripped.startswith("#endif") and ifdef_stack:
            ifdef_stack.pop()

        # Look for NOINLINE function definitions
        if "NOINLINE" in line and "(" in line and line.strip() != "":
            # Try to find function name
            m = re.search(r"NOINLINE\s+\w+\s+(\w+)\s*\(", line)
            if m:
                func_name = m.group(1)
                if func_name == "main":
                    i += 1
                    continue

                # Collect lines until matching closing brace
                brace_depth = 0
                func_lines = []
                # Add ifdef context if any
                if ifdef_stack:
                    func_lines.append(f"  // [{ifdef_stack[-1]}]\n")
                j = i
                while j < len(lines):
                    func_lines.append(lines[j])
                    brace_depth += lines[j].count("{") - lines[j].count("}")
                    if brace_depth <= 0 and "{" in "".join(func_lines):
                        break
                    j += 1
                funcs[func_name] = "".join(func_lines).rstrip()
                i = j + 1
                continue
        i += 1

    return funcs


def decompile_binary(bin_path):
    """Decompile all ccop_* functions in a binary. Returns {name: decompiled_text}."""
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=False)
    cfg = p.analyses.CFGFast(normalize=True, data_references=True)
    p.analyses.CompleteCallingConventions(
        cfg=cfg.model,
        recover_variables=True,
        analyze_callsites=True,
    )

    results = {}
    for func in sorted(cfg.functions.values(), key=lambda f: f.addr):
        if not func.name.startswith("ccop_") or func.is_plt or func.is_simprocedure:
            continue
        dec = p.analyses.Decompiler(func, cfg=cfg.model)
        if dec.codegen is not None and dec.codegen.text is not None:
            results[func.name] = dec.codegen.text.rstrip()
        else:
            results[func.name] = "// <decompilation failed>"

    return results


def find_binary(src_basename, arch):
    """Find the O2 binary for a source file."""
    stem = src_basename.replace(".c", "")
    arch_dir = BIN_DIRS[arch]
    if not os.path.isdir(arch_dir):
        return None

    # Try exact O2 match first, then haswell variant for inc_dec
    candidates = [
        os.path.join(arch_dir, f"{stem}_{OPT}"),
        os.path.join(arch_dir, f"{stem}_{OPT}_haswell"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def has_ccall(text):
    """Check if decompiled text contains unresolved ccall markers."""
    return "calculate_condition" in text or "calculate_rflags_c" in text


def main():
    out = sys.stdout

    src_files = sorted(f for f in os.listdir(TRIGGERS_DIR) if f.startswith("ccop_") and f.endswith(".c"))

    total_funcs = 0
    simplified = 0
    unsimplified = 0
    failed = 0

    for src_file in src_files:
        src_path = os.path.join(TRIGGERS_DIR, src_file)
        c_funcs = extract_c_functions(src_path)

        for arch in ("amd64", "i386"):
            bin_path = find_binary(src_file, arch)
            if bin_path is None:
                continue

            bin_name = os.path.basename(bin_path)
            out.write(f"\n{'=' * 80}\n")
            out.write(f"  {bin_name}  ({arch})  —  {src_file}\n")
            out.write(f"{'=' * 80}\n")

            decomp = decompile_binary(bin_path)

            if not decomp:
                out.write("\n  (no ccop_* functions in this binary)\n")
                continue

            for func_name in sorted(decomp.keys()):
                total_funcs += 1
                dec_text = decomp[func_name]
                has_raw = has_ccall(dec_text)

                if has_raw:
                    unsimplified += 1
                    status = "CCALL"
                elif "decompilation failed" in dec_text:
                    failed += 1
                    status = "FAIL"
                else:
                    simplified += 1
                    status = "OK"

                out.write(f"\n--- {func_name}  [{status}] ---\n")

                # Original C
                if func_name in c_funcs:
                    out.write("\n  [original C]\n\n")
                    for line in c_funcs[func_name].split("\n"):
                        out.write(f"    {line}\n")
                else:
                    out.write("\n  [original C not found — likely #ifdef'd out for this arch]\n")

                # Decompiled
                out.write(f"\n  [decompiled ({arch})]\n\n")
                for line in dec_text.split("\n"):
                    out.write(f"    {line}\n")

                out.write("\n")

    out.write(f"\n{'=' * 80}\n")
    out.write(f"  SUMMARY: {total_funcs} functions total\n")
    out.write(f"    {simplified} simplified (OK)\n")
    out.write(f"    {unsimplified} still contain raw ccall (CCALL)\n")
    out.write(f"    {failed} decompilation failed (FAIL)\n")
    out.write(f"{'=' * 80}\n")


if __name__ == "__main__":
    main()
