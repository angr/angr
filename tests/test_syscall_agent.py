import os
import angr


test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_fauxware(arch="x86_64"):
    p = angr.Project(os.path.join(test_location, arch, "fauxware"), auto_load_libs=True, use_sim_procedures=False)
    results = p.factory.simulation_manager().explore()
    stdin = results.found[0].posix.dumps(0)
    assert b'\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00' ==  stdin


if __name__ == "__main__":
    test_fauxware()