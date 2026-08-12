#!/usr/bin/env python
"""Discover and extract the duplicated inlined code in notepad.exe's NPInit.

NPInit is compiled with Warbird string obfuscation: nine copies of a 24-round
ARX decryption stub are inlined into it, each with a freshly randomized round
function. No two copies are identical -- not one of the 36 pairs matches even
after abstracting constants away -- so an exact matcher finds nothing. This
script runs :class:`~angr.analyses.fuzzy_patterns.FuzzyPatternFinder` over the
AIL graph to recover the families, then :class:`PatternDeduplicator` to outline
them and merge whatever is provably identical.

Not a unit test: decompiling NPInit alone takes about a minute, and the binary
is not in the binaries repo. Run it directly:

    python tests/analyses/fuzzy_patterns_npinit_demo.py [core|occurrence] [/path/to/notepad.exe]

Both decompilations are written to /tmp for diffing: ``npinit_before.c`` and
``npinit_after_<granularity>.c``.
"""

from __future__ import annotations

import logging
import sys
import time
from collections import Counter
from pathlib import Path

import angr
from angr.analyses.decompiler.clinic import ClinicStage
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.fuzzy_patterns import AlignParams, FuzzyPatternFinder, PatternDeduplicator
from angr.analyses.fuzzy_patterns.dedup import graph_problems

NPINIT = 0x140013154

# the big-endian byte gather that opens every Warbird round loop; two per copy
WARBIRD_GATHER_PREFIX = "Asn(VR,Or(Mul(Or(Mul("

OUT_DIR = Path("/tmp")


def dump(path: Path, text: str, label: str) -> None:
    """Write a decompilation to disk so the two versions can be diffed."""
    path.write_text(text, encoding="utf-8")
    print(f"[+] wrote {label} decompilation to {path} ({text.count(chr(10))} lines)")


def body_lines(text: str) -> int:
    """Lines of actual code, excluding the typedef and declaration preamble.

    The codegen separates a function's declarations from its body with a blank
    line, so total line counts are dominated by the ~1500 declarations and hide
    what outlining actually removed.
    """
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith(f"int sub_{NPINIT:x}")), 0)
    for i in range(start, len(lines)):
        if not lines[i].strip() and i > start + 1:
            return len(lines) - i
    return len(lines) - start


def main() -> int:
    granularity = sys.argv[1] if len(sys.argv) > 1 else "core"
    bin_path = sys.argv[2] if len(sys.argv) > 2 else "/output/notepad.exe"
    logging.getLogger("angr").setLevel(logging.CRITICAL)

    t0 = time.time()
    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False)
    proj.analyses.CompleteCallingConventions(cfg=cfg, analyze_callsites=True)
    func = cfg.functions[NPINIT]
    print(f"[+] CFG + calling conventions in {time.time() - t0:.0f}s")

    t1 = time.time()
    dec = proj.analyses.Decompiler(func, cfg=cfg.model, show_progressbar=False)
    assert dec.codegen is not None and dec.ail_graph is not None
    before = dec.codegen.text
    print(
        f"[+] decompiled {func.name} in {time.time() - t1:.0f}s: "
        f"{before.count(chr(10))} lines ({body_lines(before)} of body), "
        f"{len(dec.ail_graph)} blocks, {sum(len(b.statements) for b in dec.ail_graph)} statements"
    )
    dump(OUT_DIR / "npinit_before.c", before, "pre-outlining")

    t2 = time.time()
    finder = proj.analyses[FuzzyPatternFinder](func, dec.ail_graph, params=AlignParams(min_identity=0.45))
    print(f"\n[+] FuzzyPatternFinder in {time.time() - t2:.1f}s")
    print(finder.summary(limit=6))

    # ground truth: locate the Warbird copies and see which families cover them
    gathers = [i for i, s in enumerate(finder.stream.shapes) if s.startswith(WARBIRD_GATHER_PREFIX)]
    loops = gathers[::2]
    print(f"\n[+] {len(loops)} Warbird decryption loops in the function")
    for pi, pattern in enumerate(finder.patterns):
        covered = [
            j
            for j, tok in enumerate(loops)
            if any(o.interval.start <= tok < o.interval.end for o in pattern.occurrences)
        ]
        if covered:
            print(f"    pattern {pi} covers Warbird loops {covered} at {pattern.identity:.0%} identity")

    t3 = time.time()
    dedup = proj.analyses[PatternDeduplicator](
        func, dec.ail_graph, finder.patterns, finder.stream, granularity=granularity
    )
    print(f"\n[+] PatternDeduplicator({granularity}) in {time.time() - t3:.1f}s")
    print(dedup.summary().splitlines()[0])
    for group in dedup.result.groups:
        print(
            f"    {group.name}: {group.size} call sites share one function, {len(group.lifted_const_indices)} constants lifted"
        )
    reasons = Counter(reason.split(":")[0].split(" (")[0] for _, reason in dedup.result.skipped)
    for reason, count in reasons.most_common(6):
        print(f"    skipped x{count}: {reason}")

    extracted = [
        j for j, tok in enumerate(loops) if any(r.interval.start <= tok < r.interval.end for r in dedup.result.outlined)
    ]
    print(f"[+] Warbird loops extracted into their own functions: {extracted or 'none'}")

    problems = graph_problems(dedup.result.graph, func.addr)
    print(f"[+] rewritten graph: {len(problems)} structural problems")
    if problems:
        for p in problems[:5]:
            print(f"      {p}")
        return 1
    if not dedup.result.outlined:
        print("[-] nothing was outlined")
        return 0

    t4 = time.time()
    del dec.kb.dec_variables.function_managers[func.addr]
    dec2 = proj.analyses[Decompiler].prep(fail_fast=True)(
        func,
        clinic_graph=dedup.result.graph,
        clinic_start_stage=ClinicStage.POST_CALLSITES,
        clinic_arg_vvars=dec.clinic.arg_vvars,
        cfg=cfg.model,
    )
    assert dec2.codegen is not None
    after = dec2.codegen.text
    print(
        f"[+] parent re-decompiled in {time.time() - t4:.0f}s: body "
        f"{body_lines(before)} -> {body_lines(after)} lines "
        f"({100 * (1 - body_lines(after) / body_lines(before)):.0f}% smaller), "
        f"{len(dedup.result.outlined)} calls to extracted functions"
    )
    # granularity is in the name because the two modes produce different output
    dump(OUT_DIR / f"npinit_after_{granularity}.c", after, "post-outlining")

    # show one extracted callee: this is the duplicated code, now in one place
    biggest = max(dedup.result.outlined, key=lambda r: r.statements)
    print(
        f"\n[+] largest extracted function: {biggest.statements} statements, "
        f"{len(biggest.child_graph)} blocks, {len(biggest.child_args)} arguments, "
        f"from {biggest.src_loc[0]:#x}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
