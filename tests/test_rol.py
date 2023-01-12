import angr

import logging

l = logging.getLogger("angr.tests.test_rol")

import os

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


def test_rol_x86_64():
    binary_path = os.path.join(test_location, "x86_64", "test_rol.exe")

    proj = angr.Project(binary_path, auto_load_libs=False)

    initial_state = proj.factory.blank_state(addr=0x401000)
    r_rax = initial_state.solver.BVS("rax", 64)
    initial_state.regs.rax = r_rax

    pg = proj.factory.simulation_manager(initial_state)
    pg.explore(find=0x401013, avoid=0x401010)
    found_state = pg.found[0]

    result = found_state.solver.eval(r_rax)
    assert result == 0x37B7AB70


def test_rol_i386():
    binary_path = os.path.join(test_location, "i386", "test_rol.exe")

    proj = angr.Project(binary_path, auto_load_libs=False)

    initial_state = proj.factory.blank_state(addr=0x401000)
    r_eax = initial_state.solver.BVS("eax", 32)
    initial_state.regs.eax = r_eax

    pg = proj.factory.simulation_manager(initial_state)
    pg.explore(find=0x401013, avoid=0x401010)
    found_state = pg.found[0]

    result = found_state.solver.eval(r_eax)
    assert result == 0x37B7AB70


if __name__ == "__main__":
    test_rol_x86_64()
    test_rol_i386()
