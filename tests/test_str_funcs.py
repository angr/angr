import nose
import angr

import logging
l = logging.getLogger("angr_tests")

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_strncpy():
    strncpy_amd64 = angr.Project(test_location + "/x86_64/strncpy", load_options={'auto_load_libs': True}, exclude_sim_procedures_list=['strncpy'])
    explorer = angr.surveyors.Explorer(strncpy_amd64, find=[0x4005FF]).run()
    s = explorer.found[0]
    result = s.se.any_str(s.memory.load(s.registers.load(16), 16))
    nose.tools.assert_equals(result, 'why hello there\x00')

def test_strncpy_size():
    strncpy_size_amd64 = angr.Project(test_location + "/x86_64/strncpy-size", load_options={'auto_load_libs': True}, exclude_sim_procedures_list=['strncpy'])
    explorer = angr.surveyors.Explorer(strncpy_size_amd64,max_repeats=50, find=[0x40064C]).run()
    s = explorer.found[0]
    result = s.se.any_str(s.memory.load(s.registers.load(16), 40))
    nose.tools.assert_equals(result, 'just testing things\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

def test_strncpy_verify_null():
    strncpy_verify_null_amd64 = angr.Project(test_location + "/x86_64/strncpy-verify-null", load_options={'auto_load_libs': True}, exclude_sim_procedures_list=['strncpy'])
    explorer = angr.surveyors.Explorer(strncpy_verify_null_amd64,max_repeats=50, find=[0x40064C]).run()
    s = explorer.found[0]
    result = s.se.any_str(s.memory.load(s.registers.load(16), 40))
    nose.tools.assert_equals(result, 'just testing things\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00AAAAAA\x00')

def test_strstr_and_strncpy():
    strstr_and_strncpy_amd64 = angr.Project(test_location + "/x86_64/strstr_and_strncpy", load_options={'auto_load_libs': True}, exclude_sim_procedures_list=['strstr'])
    explorer = angr.surveyors.Explorer(strstr_and_strncpy_amd64, max_repeats=50, find=[0x400657]).run()
    s = explorer.found[0]
    result = s.se.any_str(s.memory.load(s.registers.load(16), 15))
    nose.tools.assert_equals(result, 'hi th hi there\x00')

def test_strstr():
    strstr_amd64 = angr.Project(test_location + "/x86_64/strstr", load_options={'auto_load_libs': True}, exclude_sim_procedures_list=['strstr'])
    explorer = angr.surveyors.Explorer(strstr_amd64, find=[0x4005FB]).run()
    s = explorer.found[0]
    result = s.se.any_str(s.memory.load(s.registers.load(16), 9))
    nose.tools.assert_equals(result, 'hi there\x00')

if __name__ == "__main__":
    test_strncpy()
    test_strncpy_size()
    test_strncpy_verify_null()
    test_strstr_and_strncpy()
    test_strstr()
