from __future__ import annotations
import os
import time

import angr


class InspectorEngine(
    angr.engines.SimEngineFailure,
    angr.engines.SimEngineSyscall,
    angr.engines.HooksMixin,
    angr.engines.SimInspectMixin,
    angr.engines.HeavyVEXMixin,
):
    pass


arch = "x86_64"
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../binaries")
b = angr.Project(os.path.join(test_location, "tests", arch, "perf_tight_loops"), auto_load_libs=False)
state = b.factory.full_init_state(
    plugins={"registers": angr.state_plugins.SimLightRegisters()}, remove_options={angr.sim_options.COPY_STATES}
)
state.supports_inspect = True  # force enable inspect without adding any breakpoints
engine = InspectorEngine(b)


def main():
    simgr = b.factory.simgr(state)
    simgr.explore(engine=engine)


if __name__ == "__main__":
    tstart = time.time()
    main()
    tend = time.time()
    print("Elapsed: %f sec" % (tend - tstart))
