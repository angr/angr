"""Compare cc-register liveness in each leaf observation state vs the merged state.

Answers: does the merge drop the cc registers, or were they already absent at the leaves?
"""
import os
import runpy
import sys

import angr
from angr.analyses.vm_deobfuscation import VMDeobfuscation

NAME = "testing_new_improved_whole_vm_RDA_deadassignment_elimination"
_orig = getattr(VMDeobfuscation, NAME)
_calls = [0]


def probe(self, cfg, proj, keep_sp_changes_dae=False):
    _calls[0] += 1
    n = _calls[0]
    if n > 2:
        return _orig(self, cfg, proj, keep_sp_changes_dae)

    from angr.analyses.reaching_definitions.subject import Subject
    from angr.knowledge_plugins.key_definitions.constants import OP_AFTER

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

    arch = self.project.arch
    regs = [(r, arch.registers[r][0], arch.registers[r][1])
            for r in ("cc_op", "cc_dep1", "cc_dep2", "cc_ndep", "rax", "rsp") if r in arch.registers]

    def report(label, state):
        for rname, off, size in regs:
            try:
                vs = state.registers.load(off, size=size)
                defs_ = set()
                for values in vs.values():
                    for value in values:
                        defs_.update(state.extract_defs(value))
                print(f"[m#{n}] {label:26s} {rname:8s} off={off:<4d} OK  defs={len(defs_)}", flush=True)
            except Exception as e:  # pylint:disable=broad-except
                print(f"[m#{n}] {label:26s} {rname:8s} off={off:<4d} {type(e).__name__}: {e}", flush=True)

    obs = list(rd.observed_results.items())
    print(f"[m#{n}] leaves={len(leaf)} observed={len(obs)}", flush=True)
    for i, (k, st) in enumerate(obs):
        report(f"leaf[{i}]", st)
    if obs:
        states = [st for _, st in obs]
        merged, occurred = states[0].merge(*states[1:])
        print(f"[m#{n}] merge_occurred={occurred}", flush=True)
        report("MERGED", merged)

    return _orig(self, cfg, proj, keep_sp_changes_dae)


setattr(VMDeobfuscation, NAME, probe)
print("[m] probe installed", flush=True)

if os.environ.get("PUSHAN_QUIET"):
    import logging

    logging.Logger.setLevel = lambda self, level: None
    logging.getLogger().setLevel = lambda level: None
    logging.disable(logging.INFO)

sys.argv = ["script.py"]
runpy.run_path("script.py", run_name="__main__")
