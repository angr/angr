from __future__ import annotations

import json
import os
import sys

import angr


def main() -> None:
    binary = os.environ.get("ANGR_WASM_TEST_BINARY")
    if binary is None:
        raise SystemExit("Set ANGR_WASM_TEST_BINARY to the x86-64 fauxware test binary")

    assert sys.platform == "emscripten"
    assert angr.capabilities.emscripten
    assert angr.capabilities.vex
    assert angr.capabilities.z3
    assert not angr.capabilities.lmdb
    assert not angr.capabilities.unicorn

    project = angr.Project(binary, auto_load_libs=False)
    block = project.factory.block(project.entry)
    assert block.vex.statements
    assert block.capstone.insns

    simgr = project.factory.simulation_manager()
    simgr.explore(find=lambda state: b"Welcome to the admin console" in state.posix.dumps(1))
    assert simgr.found
    assert b"SOSNEAKY" in simgr.found[0].posix.dumps(0)

    cfg = project.analyses.CFGFast(normalize=True)
    result = {
        "angr": angr.__version__,
        "arch": project.arch.name,
        "cfg_nodes": sum(1 for _ in cfg.graph.nodes()),
        "functions": sum(1 for _ in cfg.functions),
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
