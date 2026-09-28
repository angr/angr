#!/usr/bin/env python
"""
Decompile a deobfuscated graph dumped by pushan, using whatever angr this script runs under.

The dump is produced by setting ``project.vm_deob_dump_path`` before running ``VMDeobfuscation``.
It contains the function exactly as it looked immediately before pushan called ``Decompiler``, so
no pushan code is needed here -- only ``deobf_schema.py`` and ``deobf_reader.py`` next to this
script (or importable from ``angr.analyses.vm_deobfuscation``).

    python decompile_deobf.py dump.json.gz ./binary -o out.c
"""

import argparse
import logging
import sys


def _load_reader():
    """Import the reader from the angr tree if present, else from next to this script."""
    try:
        from angr.analyses.vm_deobfuscation.deobf_reader import load_decompilation_input

        return load_decompilation_input
    except ImportError:
        pass

    import os

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from deobf_reader import load_decompilation_input  # pylint:disable=import-error

    return load_decompilation_input


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dump", help="path to the .json.gz produced by vm_deob_dump_path")
    ap.add_argument("binary", help="the binary the dump was made from")
    ap.add_argument("-o", "--out", default="deobf_result.c", help="where to write the decompiled C")
    ap.add_argument(
        "--rewrite-tmp-sentinel",
        action="store_true",
        help='replace the "tmp removed" tyenv sentinel with Ity_I8 (only if the decompiler trips on it)',
    )
    ap.add_argument("--no-kwargs", action="store_true", help="ignore the recorded Decompiler kwargs")
    ap.add_argument(
        "--no-vm-deobfuscation",
        action="store_true",
        help="do not pass vm_deobfuscation=True (skips the extra VM simplification passes)",
    )
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)

    import angr

    load_decompilation_input = _load_reader()

    proj = angr.Project(args.binary, auto_load_libs=False)
    func, kwargs = load_decompilation_input(proj, args.dump, rewrite_tmp_sentinel=args.rewrite_tmp_sentinel)
    print(f"loaded {func.name} @ {func.addr}: {len(func.transition_graph.nodes())} graph nodes", flush=True)

    if args.no_kwargs:
        kwargs = {}
    if not args.no_vm_deobfuscation:
        # A dump is by definition a devirtualised VM body.  Newer angr has extra simplification
        # passes for exactly this shape; _filter_kwargs drops the flag where it does not exist.
        kwargs.setdefault("vm_deobfuscation", True)
    # Drop kwargs this angr version does not accept -- a newer Decompiler may have renamed them.
    kwargs = _filter_kwargs(proj, kwargs)

    dec = proj.analyses.Decompiler(func, **kwargs)
    if dec.codegen is None:
        print("decompilation produced no code", file=sys.stderr)
        return 1

    with open(args.out, "w") as fp:
        fp.write(dec.codegen.text)
    print(f"wrote {len(dec.codegen.text)} chars to {args.out}")
    return 0


def _filter_kwargs(proj, kwargs):
    import inspect

    try:
        sig = inspect.signature(proj.analyses.Decompiler._analysis_cls.__init__)
    except Exception:  # pylint:disable=broad-except
        return kwargs
    accepted = set(sig.parameters)
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values()):
        return kwargs
    dropped = sorted(k for k in kwargs if k not in accepted)
    if dropped:
        print(f"note: this angr's Decompiler does not accept {dropped}; ignoring", flush=True)
    return {k: v for k, v in kwargs.items() if k in accepted}


if __name__ == "__main__":
    sys.exit(main())
