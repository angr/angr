"""Round-trip gate for the deobf dump format.

Usage:
    python deobf_roundtrip.py <dump.json.gz> <binary> [--expect <reference.c>]

Loads the dump into a fresh Project, asserts the rebuilt graph is structurally identical to the
dump, then runs Decompiler and compares the output against a reference .c.
"""
import argparse
import gzip
import json
import sys

import angr


def structural_check(doc, func):
    """Compare the rebuilt function against the dump it came from."""
    from angr.knowledge_plugins.functions.function import Function

    problems = []
    graph = func.transition_graph

    nodes = [n for n in graph.nodes() if not isinstance(n, Function)]
    funcs = [n for n in graph.nodes() if isinstance(n, Function)]
    if len(nodes) != len(doc["nodes"]):
        problems.append(f"node count {len(nodes)} != {len(doc['nodes'])}")
    in_graph = [c for c in doc["callees"] if c.get("in_graph", True)]
    if len(funcs) != len(in_graph):
        problems.append(f"in-graph callee count {len(funcs)} != {len(in_graph)}")

    by_addr = {n.addr: n for n in nodes}
    for enc in doc["nodes"]:
        addr = int(enc["addr"])
        node = by_addr.get(addr)
        if node is None:
            problems.append(f"node {enc['key']} @ {addr} missing")
            continue
        if node.size != enc["size"]:
            problems.append(f"node {enc['key']}: size {node.size} != {enc['size']}")
        irsb_enc = enc["irsb"]
        if node.irsb is None:
            problems.append(f"node {enc['key']}: no irsb")
            continue
        if len(node.irsb.statements) != len(irsb_enc["statements"]):
            problems.append(
                f"node {enc['key']}: {len(node.irsb.statements)} stmts != {len(irsb_enc['statements'])}"
            )
        else:
            for i, (got, want) in enumerate(zip(node.irsb.statements, irsb_enc["statements"])):
                if got.tag.split("_", 1)[1] != want["t"]:
                    problems.append(f"node {enc['key']} stmt {i}: {got.tag} != {want['t']}")
                    break
        if list(node.irsb.tyenv.types) != list(irsb_enc["tyenv"]):
            problems.append(f"node {enc['key']}: tyenv differs")
        if node.irsb.jumpkind != irsb_enc["jumpkind"]:
            problems.append(f"node {enc['key']}: jumpkind {node.irsb.jumpkind} != {irsb_enc['jumpkind']}")
        if int(irsb_enc["addr"]) != node.irsb.addr:
            problems.append(f"node {enc['key']}: irsb addr differs")

    # Edge multiset, keyed the way the dump records it.
    want_edges = []
    for e in doc["edges"]:
        if e["type"] in ("transition", "exception"):
            want_edges.append((e["type"], e["src"], e["dst"]))
        elif e["type"] in ("call", "syscall"):
            want_edges.append((e["type"], e["src"], e["callee"]))
            if e.get("ret") is not None:
                want_edges.append(("fake_return", e["src"], e["ret"]))
        elif e["type"] == "return":
            want_edges.append(("return", e["callee"], e["dst"]))

    key_of = {}
    for enc in doc["nodes"]:
        key_of[int(enc["addr"])] = enc["key"]
    for enc in doc["callees"]:
        key_of[int(enc["addr"])] = enc["key"]

    got_edges = []
    for src, dst, data in graph.edges(data=True):
        got_edges.append((data.get("type"), key_of.get(src.addr), key_of.get(dst.addr)))

    if sorted(map(str, got_edges)) != sorted(map(str, want_edges)):
        only_got = sorted(set(map(str, got_edges)) - set(map(str, want_edges)))
        only_want = sorted(set(map(str, want_edges)) - set(map(str, got_edges)))
        problems.append(f"edge multiset differs; only-rebuilt={only_got[:5]} only-dump={only_want[:5]}")

    if doc["function"]["startpoint"] is not None:
        want_start = next(n for n in doc["nodes"] if n["key"] == doc["function"]["startpoint"])
        if func.startpoint is None or func.startpoint.addr != int(want_start["addr"]):
            problems.append("startpoint differs")

    want_rets = {int(next(n for n in doc["nodes"] if n["key"] == k)["addr"]) for k in doc["function"]["ret_sites"]}
    got_rets = {n.addr for n in func._ret_sites}
    if got_rets != want_rets:
        problems.append(f"ret_sites differ: only-rebuilt={sorted(got_rets - want_rets)[:3]}")

    return problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("binary")
    ap.add_argument("--expect")
    ap.add_argument("--out", default="roundtrip_result.c")
    ap.add_argument("--rewrite-tmp-sentinel", action="store_true")
    args = ap.parse_args()

    from angr.analyses.vm_deobfuscation.deobf_reader import load_decompilation_input

    doc = json.loads(gzip.open(args.dump, "rb").read().decode("utf-8"))

    proj = angr.Project(args.binary, auto_load_libs=False)
    func, kwargs = load_decompilation_input(proj, args.dump, rewrite_tmp_sentinel=args.rewrite_tmp_sentinel)

    problems = structural_check(doc, func)
    if problems:
        print("STRUCTURAL MISMATCH:")
        for p in problems:
            print("  -", p)
        return 2
    print(f"structural check OK ({len(doc['nodes'])} nodes, {len(doc['edges'])} edges)")

    # Match decompile_deobf.py: a dump is always a devirtualised VM body, and newer angr gates
    # both its VM simplification passes and remove_dead_memdefs on this flag.
    import inspect

    if "vm_deobfuscation" in inspect.signature(proj.analyses.Decompiler._analysis_cls.__init__).parameters:
        kwargs.setdefault("vm_deobfuscation", True)

    dec = proj.analyses.Decompiler(func, **kwargs)
    if dec.codegen is None:
        print("DECOMPILATION PRODUCED NO CODE")
        return 3
    text = dec.codegen.text
    with open(args.out, "w") as fp:
        fp.write(text)
    print(f"decompiled {len(text)} chars -> {args.out}")

    if args.expect:
        want = open(args.expect).read()
        if want == text:
            print("BYTE-IDENTICAL to", args.expect)
            return 0
        print("DIFFERS from", args.expect)
        import difflib

        diff = list(difflib.unified_diff(want.splitlines(), text.splitlines(), "expected", "roundtrip", lineterm=""))
        print(f"  {len(diff)} diff lines; first 40:")
        for line in diff[:40]:
            print("   ", line)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
