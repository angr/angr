import angr

import logging

l = logging.getLogger("angr_tests")

import os

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


def test_memmove():
    # auto_load_libs can't be disabled as the testcase fails
    proj = angr.Project(
        os.path.join(test_location, "x86_64", "memmove"),
        load_options={"auto_load_libs": True},
        exclude_sim_procedures_list=["memmove"],
    )
    explorer = proj.factory.simulation_manager().explore(find=[0x4005D7])
    s = explorer.found[0]
    result = s.solver.eval(s.memory.load(s.registers.load(16, 8), 13), cast_to=bytes)
    assert result == b"very useful.\x00"


def test_memcpy():
    # auto_load_libs can't be disabled as the testcase fails
    proj = angr.Project(
        os.path.join(test_location, "x86_64", "memcpy"),
        load_options={"auto_load_libs": True},
        exclude_sim_procedures_list=["memcpy"],
    )
    explorer = proj.factory.simulation_manager().explore(find=[0x40065A])
    s = explorer.found[0]
    result = s.solver.eval(s.memory.load(s.registers.load(16, 8), 19), cast_to=bytes)
    assert result == b"let's test memcpy!\x00"


def test_memset():
    # auto_load_libs can't be disabled as the testcase fails
    proj = angr.Project(
        os.path.join(test_location, "x86_64", "memset"),
        load_options={"auto_load_libs": True},
        exclude_sim_procedures_list=["memset"],
    )
    explorer = proj.factory.simulation_manager().explore(find=[0x400608])
    s = explorer.found[0]
    result = s.solver.eval(s.memory.load(s.registers.load(16, 8), 50), cast_to=bytes)
    assert result == b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\x00"


if __name__ == "__main__":
    test_memmove()
    test_memcpy()
    test_memset()
