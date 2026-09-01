"""Trace the condition-code Put count through every VMDeobfuscation pass.

Wraps each pass that takes a `cfg` and reports how many PUT(cc_op/cc_dep1/cc_dep2/cc_ndep)
statements exist in the graph before and after it. Run it in two trees and diff the traces to see
which pass stops eliminating them.

    <venv>/bin/python cctrace.py        # run from inside a target directory
"""
import inspect
import os
import runpy
import sys

import pyvex

import angr
from angr.analyses.vm_deobfuscation import VMDeobfuscation

CC_REGS = {"cc_op", "cc_dep1", "cc_dep2", "cc_ndep"}


def _cc_offsets(arch):
    return {arch.registers[r][0] for r in CC_REGS if r in arch.registers}


def _count(cfg, offsets):
    graph = getattr(cfg, "graph", None)
    if graph is None:
        return None
    total = 0
    try:
        nodes = list(graph.nodes())
    except Exception:  # pylint:disable=broad-except
        return None
    for node in nodes:
        irsb = getattr(node, "irsb", None)
        if irsb is None or getattr(irsb, "statements", None) is None:
            continue
        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.stmt.Put) and stmt.offset in offsets:
                total += 1
    return total


def _wrap(name, func):
    def wrapper(self, *args, **kwargs):
        offsets = _cc_offsets(self.project.arch)
        cfg_in = args[0] if args else kwargs.get("cfg")
        before = _count(cfg_in, offsets) if cfg_in is not None else None
        result = func(self, *args, **kwargs)
        after = _count(result, offsets)
        if after is None:
            after = _count(cfg_in, offsets) if cfg_in is not None else None
        if before is not None or after is not None:
            mark = "  <<< CHANGED" if (before != after and before is not None and after is not None) else ""
            print(f"[cc] {name:60s} {before} -> {after}{mark}", flush=True)
        return result

    return wrapper


installed = 0
for _name, _func in list(vars(VMDeobfuscation).items()):
    if not callable(_func) or _name.startswith("__"):
        continue
    try:
        params = list(inspect.signature(_func).parameters)
    except (TypeError, ValueError):
        continue
    if len(params) >= 2 and params[1] == "cfg":
        setattr(VMDeobfuscation, _name, _wrap(_name, _func))
        installed += 1
print(f"[cc] instrumented {installed} passes", flush=True)

overrides = {}
for item in os.environ.get("PUSHAN_OVERRIDES", "").split(","):
    if not item.strip():
        continue
    k, _, v = item.partition("=")
    overrides[k.strip()] = False if v.strip() in ("0", "false", "") else (True if v.strip() in ("1", "true") else v.strip())
if overrides:
    _orig = angr.Project.__init__

    def _patched(self, *a, **kw):
        _orig(self, *a, **kw)
        for k, v in overrides.items():
            setattr(self, k, v)

    angr.Project.__init__ = _patched
    print(f"[cc] project overrides: {overrides}", flush=True)

if os.environ.get("PUSHAN_QUIET"):
    import logging

    logging.Logger.setLevel = lambda self, level: None
    logging.getLogger().setLevel = lambda level: None
    logging.disable(logging.INFO)

sys.argv = ["script.py"]
runpy.run_path("script.py", run_name="__main__")
