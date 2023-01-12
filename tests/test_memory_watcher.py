import os
import sys
import logging

import angr

import psutil
from common import bin_location


def test_memory_watcher():
    binary = os.path.join(bin_location, "tests", "x86_64", "veritesting_a")
    proj = angr.Project(binary, auto_load_libs=False)
    simgr = proj.factory.simulation_manager()

    memory_watcher = angr.exploration_techniques.MemoryWatcher()
    simgr.use_technique(memory_watcher)

    # Initially build some paths
    while len(simgr.active) < 32 and simgr.active != []:
        simgr.step()

    # Something else went wrong..
    assert simgr.active != []

    # Set fake that memory watcher believes we're too low on memory
    memory_watcher.min_memory = psutil.virtual_memory().total

    previous_active = len(simgr.active)

    # Step once to move things over
    simgr.step()

    assert simgr.active == []
    assert len(getattr(simgr, memory_watcher.memory_stash)) == previous_active


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith("test_")), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], "__call__"):
            all_functions[f]()


if __name__ == "__main__":
    logging.getLogger("angr.exploration_techniques.memory_watcher").setLevel("DEBUG")
    if len(sys.argv) > 1:
        globals()["test_" + sys.argv[1]]()
    else:
        run_all()
