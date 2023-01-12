import angr

import logging

l = logging.getLogger("angr_tests")

import os

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


def test_strncpy():
    # auto_load_libs can't be disabled as the test cases failed.
    strncpy_amd64 = angr.Project(
        os.path.join(test_location, "x86_64", "strncpy"),
        load_options={"auto_load_libs": True},
        exclude_sim_procedures_list=["strncpy"],
    )
    explorer = strncpy_amd64.factory.simulation_manager()
    explorer.explore(find=[0x4005FF])
    s = explorer.found[0]
    result = s.solver.eval(s.memory.load(s.regs.rax, 16), cast_to=bytes)
    assert result == b"why hello there\x00"


def test_strncpy_size():
    # auto_load_libs can't be disabled as the test cases failed.
    strncpy_size_amd64 = angr.Project(
        os.path.join(test_location, "x86_64", "strncpy-size"),
        load_options={"auto_load_libs": True},
        exclude_sim_procedures_list=["strncpy"],
    )
    explorer = strncpy_size_amd64.factory.simulation_manager()
    cfg = strncpy_size_amd64.analyses.CFG(objects=[strncpy_size_amd64.loader.main_object], normalize=True)
    explorer.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=50))
    explorer.explore(find=[0x40064C])
    s = explorer.found[0]
    result = s.solver.eval(s.memory.load(s.regs.rax, 40), cast_to=bytes)
    assert (
        result
        == b"just testing things\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )


def test_strncpy_verify_null():
    # auto_load_libs can't be disabled as the test cases failed.
    strncpy_verify_null_amd64 = angr.Project(
        os.path.join(test_location, "x86_64", "strncpy-verify-null"),
        load_options={"auto_load_libs": True},
        exclude_sim_procedures_list=["strncpy"],
    )
    explorer = strncpy_verify_null_amd64.factory.simulation_manager()
    cfg = strncpy_verify_null_amd64.analyses.CFG(objects=[strncpy_verify_null_amd64.loader.main_object], normalize=True)
    explorer.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=50))
    explorer.explore(find=[0x40064C])
    s = explorer.found[0]
    result = s.solver.eval(s.memory.load(s.regs.rax, 40), cast_to=bytes)
    assert result == b"just testing things\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00AAAAAA\x00"


def test_strstr_and_strncpy():
    # auto_load_libs can't be disabled as the test cases failed.
    strstr_and_strncpy_amd64 = angr.Project(
        os.path.join(test_location, "x86_64", "strstr_and_strncpy"),
        load_options={"auto_load_libs": True},
        exclude_sim_procedures_list=["strstr"],
    )
    explorer = strstr_and_strncpy_amd64.factory.simulation_manager()
    cfg = strstr_and_strncpy_amd64.analyses.CFG(objects=[strstr_and_strncpy_amd64.loader.main_object], normalize=True)
    explorer.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=50))
    explorer.explore(find=[0x400657])
    s = explorer.found[0]
    result = s.solver.eval(s.memory.load(s.regs.rax, 15), cast_to=bytes)
    assert result == b"hi th hi there\x00"


def test_strstr():
    # auto_load_libs can't be disabled as the test cases failed.
    strstr_amd64 = angr.Project(
        os.path.join(test_location, "x86_64", "strstr"),
        load_options={"auto_load_libs": True},
        exclude_sim_procedures_list=["strstr"],
    )
    explorer = strstr_amd64.factory.simulation_manager()
    explorer.explore(find=[0x4005FB])
    s = explorer.found[0]
    result = s.solver.eval(s.memory.load(s.regs.rax, 9), cast_to=bytes)
    assert result == b"hi there\x00"


if __name__ == "__main__":
    test_strncpy()
    test_strncpy_size()
    test_strncpy_verify_null()
    test_strstr_and_strncpy()
    test_strstr()
