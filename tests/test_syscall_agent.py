import os
import logging

import angr


test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_fauxware(arch="x86_64"):
    p = angr.Project(os.path.join(test_location, arch, "fauxware"),
                     auto_load_libs=True,
                     use_sim_procedures=False)
    state = p.factory.full_init_state(add_options={angr.sim_options.ZERO_FILL_UNCONSTRAINED_MEMORY})
    results = p.factory.simulation_manager(state).explore(find=(0x4006ed, ), avoid=(0x4006aa,0x4006fd, ))
    stdin = results.found[0].posix.dumps(0)
    assert b'\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00' == stdin


if __name__ == "__main__":
    logging.getLogger("angr.bureau.bureau").setLevel(logging.DEBUG)
    test_fauxware()