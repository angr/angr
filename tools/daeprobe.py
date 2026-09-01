"""Instrument the whole-CFG RDA dead-assignment elimination and report why it does or does not fire.

Prints, for the first few invocations, how many definitions reach each decision point. Run in two
trees and diff to see where the pass diverges.
"""
import os
import runpy
import sys

import angr
from angr.analyses.vm_deobfuscation import VMDeobfuscation
from angr.knowledge_plugins.key_definitions import atoms

NAME = "testing_new_improved_whole_vm_RDA_deadassignment_elimination"
_orig = getattr(VMDeobfuscation, NAME)
_calls = [0]


def probe(self, cfg, proj, keep_sp_changes_dae=False):
    _calls[0] += 1
    n = _calls[0]

    # Re-derive the pass's own inputs so we can report on them, then defer to the real pass.
    import networkx  # noqa: F401
    from angr.analyses.reaching_definitions.subject import Subject
    from angr.knowledge_plugins.key_definitions.constants import OP_AFTER
    from angr.knowledge_plugins.key_definitions.definition import Definition
    from angr.code_location import ExternalCodeLocation

    start_node = None
    for node in cfg.nodes():
        if node.addr == self.vm_start_addr:
            start_node = node
            break

    leaf = []
    for node in list(cfg.graph.nodes()):
        if not node.is_simprocedure and len(list(cfg.graph.successors(node))) == 0:
            leaf.append(("node", (node.addr, node.block_id), OP_AFTER))
        elif node.is_simprocedure and node.name == "exit":
            for pred in list(cfg.graph.predecessors(node)):
                if not (pred.is_simprocedure and pred.name == "exit"):
                    leaf.append(("node", (pred.addr, pred.block_id), OP_AFTER))

    rd = self.project.analyses.ReachingDefinitions(
        subject=Subject((cfg.graph, start_node)),
        track_tmps=True,
        track_consts=False,
        max_iterations=3,
        observation_points=leaf,
    )
    obs = rd.observed_results
    print(f"[dae#{n}] leaf observation points requested: {len(leaf)}", flush=True)
    print(f"[dae#{n}] observed_results: {len(obs)}", flush=True)
    if len(obs) != len(leaf):
        got = set(obs.keys())
        want = set(leaf)
        print(f"[dae#{n}]   requested-but-missing: {len(want - got)}", flush=True)
        for k in list(want - got)[:3]:
            print(f"[dae#{n}]     want {k!r}", flush=True)
        for k in list(got)[:3]:
            print(f"[dae#{n}]     got  {k!r}", flush=True)

    all_defs = list(rd.all_definitions)
    cc_offsets = {self.project.arch.registers[r][0] for r in ("cc_op", "cc_dep1", "cc_dep2", "cc_ndep")
                  if r in self.project.arch.registers}

    tot = real = nouses = reg_nouses = cc_nouses = 0
    for d in all_defs:
        tot += 1
        if isinstance(d.codeloc, ExternalCodeLocation) or d.dummy:
            continue
        real += 1
        if not rd.all_uses.get_uses(d):
            nouses += 1
            if isinstance(d.atom, atoms.Register):
                reg_nouses += 1
                if d.atom.reg_offset in cc_offsets:
                    cc_nouses += 1
    print(f"[dae#{n}] all_defs={tot} real={real} no_uses={nouses} reg_no_uses={reg_nouses} "
          f"cc_no_uses={cc_nouses}", flush=True)

    # How many cc definitions exist at all, and what do their uses look like?
    cc_defs = [d for d in all_defs
               if isinstance(d.atom, atoms.Register) and d.atom.reg_offset in cc_offsets
               and not isinstance(d.codeloc, ExternalCodeLocation) and not d.dummy]
    print(f"[dae#{n}] cc register defs total: {len(cc_defs)}", flush=True)
    for d in cc_defs[:3]:
        uses = rd.all_uses.get_uses(d)
        print(f"[dae#{n}]   {d} -> {len(uses)} uses; sample={list(uses)[:2]}", flush=True)

    if obs:
        vals = list(obs.values())
        merged, _ = vals[0].merge(*vals[1:])
        probed = 0
        for d in cc_defs[:5]:
            try:
                vs = merged.registers.load(d.atom.reg_offset, size=d.atom.size)
                defs_ = set()
                for values in vs.values():
                    for value in values:
                        defs_.update(merged.extract_defs(value))
                print(f"[dae#{n}]   load({d.atom.reg_offset}) -> {len(defs_)} defs; d in defs_ = {d in defs_}",
                      flush=True)
            except Exception as e:  # pylint:disable=broad-except
                print(f"[dae#{n}]   load({d.atom.reg_offset}) RAISED {type(e).__name__}: {e}", flush=True)
            probed += 1

    return _orig(self, cfg, proj, keep_sp_changes_dae)


setattr(VMDeobfuscation, NAME, probe)
print("[dae] probe installed", flush=True)

if os.environ.get("PUSHAN_QUIET"):
    import logging

    logging.Logger.setLevel = lambda self, level: None
    logging.getLogger().setLevel = lambda level: None
    logging.disable(logging.INFO)

sys.argv = ["script.py"]
runpy.run_path("script.py", run_name="__main__")
