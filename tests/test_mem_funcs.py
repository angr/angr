import nose
import angr

import logging
l = logging.getLogger("angr_tests")

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_memmove():
    memmove_amd64 = angr.Project(test_location + "/x86_64/memmove", load_options={'auto_load_libs': True}, exclude_sim_procedures_list=['memmove'])
    explorer = angr.surveyors.Explorer(memmove_amd64, find=[0x4005D7]).run()
    s = explorer.found[0]
    result = s.se.any_str(s.memory.load(s.registers.load(16), 13))
    nose.tools.assert_equals(result, 'very useful.\x00')

def test_memcpy():
    memcpy_amd64 = angr.Project(test_location + "/x86_64/memcpy", load_options={'auto_load_libs': True}, exclude_sim_procedures_list=['memcpy'])
    explorer = angr.surveyors.Explorer(memcpy_amd64, find=[0x40065A]).run()
    s = explorer.found[0]
    result = s.se.any_str(s.memory.load(s.registers.load(16), 19))
    nose.tools.assert_equals(result, "let's test memcpy!\x00")

def test_memset():
    memset_amd64 = angr.Project(test_location + "/x86_64/memset", load_options={'auto_load_libs': True}, exclude_sim_procedures_list=['memset'])
    explorer = angr.surveyors.Explorer(memset_amd64, find=[0x400608]).run()
    s = explorer.found[0]
    result = s.se.any_str(s.memory.load(s.registers.load(16), 50))
    nose.tools.assert_equals(result, 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\x00')

if __name__ == "__main__":
    test_memmove()
    test_memcpy()
    test_memset()
