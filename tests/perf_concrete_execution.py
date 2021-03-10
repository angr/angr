# Performance tests on concrete code execution without invoking Unicorn engine
# uses a stripped-down SimEngine to only test the essential pieces
# TODO also use a stripped-down memory

import os
import time

import angr
import claripy

# attempt to turn off claripy debug mode
if hasattr(claripy, "set_debug"):
    claripy.set_debug(False)

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


class SkinnyEngine(angr.engines.SimEngineFailure,
                   angr.engines.SimEngineSyscall,
                   angr.engines.HooksMixin,
                   angr.engines.HeavyVEXMixin):
    pass


class InspectorEngine(angr.engines.SimEngineFailure,
                      angr.engines.SimEngineSyscall,
                      angr.engines.HooksMixin,
                      angr.engines.SimInspectMixin,
                      angr.engines.HeavyVEXMixin):
    pass


def test_tight_loop(arch):
    b = angr.Project(os.path.join(test_location, arch, "perf_tight_loops"), auto_load_libs=False)
    state = b.factory.full_init_state(plugins={'registers': angr.state_plugins.SimLightRegisters()},
                                               remove_options={angr.sim_options.COPY_STATES})
    simgr = b.factory.simgr(state)
    engine = SkinnyEngine(b)

    # import logging
    # logging.getLogger('angr.sim_manager').setLevel(logging.INFO)

    start = time.time()
    simgr.explore(engine=engine)
    elapsed = time.time() - start

    print("Elapsed %f sec" % elapsed)
    #print(simgr)


def test_tight_loop_with_inspector(arch):
    b = angr.Project(os.path.join(test_location, arch, "perf_tight_loops"), auto_load_libs=False)
    state = b.factory.full_init_state(plugins={'registers': angr.state_plugins.SimLightRegisters()},
                                               remove_options={angr.sim_options.COPY_STATES})
    state.supports_inspect = True  # force enable inspect without adding any breakpoints
    simgr = b.factory.simgr(state)
    engine = InspectorEngine(b)

    start = time.time()
    simgr.explore(engine=engine)
    elapsed = time.time() - start

    print("Elapsed %f sec" % elapsed)


if __name__ == "__main__":
    test_tight_loop("x86_64")
