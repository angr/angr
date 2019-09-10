
# Performance tests on concrete code execution without invoking Unicorn engine

import os
import time
import logging

import angr
import claripy

# attempt to turn off claripy debug mode
if hasattr(claripy, "set_debug"):
    claripy.set_debug(False)

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_tight_loop(arch):
    b = angr.Project(os.path.join(test_location, arch, "perf_tight_loops"), auto_load_libs=False)
    state = b.factory.full_init_state(plugins={'registers': angr.state_plugins.SimLightRegisters()},
                                      remove_options={angr.sim_options.COPY_STATES})
    simgr = b.factory.simgr(state)

    # logging.getLogger('angr.sim_manager').setLevel(logging.INFO)

    start = time.time()
    simgr.explore()
    elapsed = time.time() - start

    print("Elapsed %f sec" % elapsed)
    print(simgr)


if __name__ == "__main__":
    test_tight_loop("x86_64")
