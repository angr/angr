import nose
import angr

import logging
l = logging.getLogger("angr_tests")

import os
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

def test_memmove():
    proj = angr.Project(os.path.join(test_location, 'x86_64', 'memmove'), load_options={'auto_load_libs': True}, exclude_sim_procedures_list=['memmove'])
    explorer = proj.factory.simulation_manager().explore(find=[0x4005D7])
    s = explorer.found[0]
    result = s.solver.eval(s.memory.load(s.registers.load(16), 13), cast_to=bytes)
    nose.tools.assert_equal(result, b'very useful.\x00')

def test_memcpy():
    proj = angr.Project(os.path.join(test_location, 'x86_64', 'memcpy'), load_options={'auto_load_libs': True}, exclude_sim_procedures_list=['memcpy'])
    explorer = proj.factory.simulation_manager().explore(find=[0x40065A])
    s = explorer.found[0]
    result = s.solver.eval(s.memory.load(s.registers.load(16), 19), cast_to=bytes)
    nose.tools.assert_equal(result, b"let's test memcpy!\x00")

def test_memset():
    proj = angr.Project(os.path.join(test_location, 'x86_64', 'memset'), load_options={'auto_load_libs': True}, exclude_sim_procedures_list=['memset'])
    explorer = proj.factory.simulation_manager().explore(find=[0x400608])
    s = explorer.found[0]
    result = s.solver.eval(s.memory.load(s.registers.load(16), 50), cast_to=bytes)
    nose.tools.assert_equal(result, b'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\x00')

if __name__ == "__main__":
    test_memmove()
    test_memcpy()
    test_memset()
