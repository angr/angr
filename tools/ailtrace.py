"""
Measure how much AIL survives each stage of Clinic, for a loaded deobf dump.

Reports the block and statement counts right after VEX->AIL conversion and again at the end of
Clinic, plus what structuring produced. Run in two trees on the same dump and diff, to see where
the pipelines part company.

    python ailtrace.py <dump.json.gz> <binary>
"""
import sys

import angr


def _count(graph):
    if graph is None:
        return None, None
    blocks = list(graph.nodes())
    return len(blocks), sum(len(getattr(b, "statements", []) or []) for b in blocks)


def main():
    dump, binary = sys.argv[1], sys.argv[2]

    from angr.analyses.decompiler.clinic import Clinic
    from angr.analyses.vm_deobfuscation.deobf_reader import load_decompilation_input

    # after VEX -> AIL conversion
    _orig_convert_all = Clinic._convert_all

    def convert_all(self, *a, **kw):
        r = _orig_convert_all(self, *a, **kw)
        blocks = getattr(self, "_blocks_by_addr_and_size", None) or {}
        stmts = sum(len(getattr(b, "statements", []) or []) for b in blocks.values())
        print(f"[ail] after _convert_all      : {len(blocks)} blocks, {stmts} statements", flush=True)
        return r

    Clinic._convert_all = convert_all

    proj = angr.Project(binary, auto_load_libs=False)
    func, kwargs = load_decompilation_input(proj, dump)
    import inspect

    if "vm_deobfuscation" in inspect.signature(proj.analyses.Decompiler._analysis_cls.__init__).parameters:
        kwargs.setdefault("vm_deobfuscation", True)
    print(f"[ail] loaded graph            : {len(func.transition_graph.nodes())} nodes", flush=True)

    dec = proj.analyses.Decompiler(func, **kwargs)

    clinic = dec.clinic
    if clinic is not None:
        for attr in ("graph", "cc_graph"):
            b, s = _count(getattr(clinic, attr, None))
            if b is not None:
                print(f"[ail] clinic.{attr:<18}: {b} blocks, {s} statements", flush=True)

    seq = getattr(dec, "seq_node", None) or getattr(dec, "_sequence_node", None)
    print(f"[ail] structuring produced    : {type(seq).__name__ if seq is not None else 'n/a'}", flush=True)
    text = dec.codegen.text if dec.codegen is not None else ""
    print(f"[ail] codegen                 : {len(text)} chars, {text.count(chr(10))} lines", flush=True)


if __name__ == "__main__":
    main()
