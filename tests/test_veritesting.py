import sys

import nose
import angr

import logging
l = logging.getLogger('angr_tests.veritesting')

import os
location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

addresses_veritesting_a = {
    'x86_64': 0x400674
}

addresses_veritesting_b = {
    'x86_64': 0x4006af
}

def run_veritesting_a(arch):
    # TODO: Added timeout control, since a failed state merging will result in running for a long time

    #logging.getLogger('angr.analyses.sse').setLevel(logging.DEBUG)

    proj = angr.Project(os.path.join(location, arch, "veritesting_a"),
                        load_options={'auto_load_libs': False},
                        use_sim_procedures=True
                        )
    ex = proj.factory.simulation_manager(veritesting=True)
    ex.explore(find=addresses_veritesting_a[arch])
    nose.tools.assert_not_equal(len(ex.found), 0)
    # Make sure the input makes sense
    for f in ex.found:
        input_str = f.plugins['posix'].dumps(0)
        nose.tools.assert_equal(input_str.count(b'B'), 10)

def run_veritesting_b(arch):
    #logging.getLogger('angr.analyses.sse').setLevel(logging.DEBUG)

    proj = angr.Project(os.path.join(location, arch, "veritesting_b"),
                        load_options={'auto_load_libs': False},
                        use_sim_procedures=True
                        )
    ex = proj.factory.simulation_manager()
    ex.use_technique(angr.exploration_techniques.Veritesting(enable_function_inlining=True))
    ex.explore(find=addresses_veritesting_b[arch])
    nose.tools.assert_not_equal(len(ex.found), 0)
    # Make sure the input makes sense
    for f in ex.found:
        input_str = f.plugins['posix'].dumps(0)
        nose.tools.assert_equal(input_str.count(b'B'), 35)

def test_veritesting_a():
    # This is the most basic test

    for arch in addresses_veritesting_a:
        yield run_veritesting_a, arch

def test_veritesting_b():
    # Advanced stuff - it tests for the ability to inline simple functions
    # as well as simple syscalls like read/write

    for arch in addresses_veritesting_b:
        yield run_veritesting_b, arch

if __name__ == "__main__":
    #logging.getLogger('angr.analyses.veritesting').setLevel(logging.DEBUG)

    if len(sys.argv) > 1:
        for test_func, arch_name in globals()['test_%s' % sys.argv[1]]():
            test_func(arch_name)

    else:
        for test_func, arch_name in test_veritesting_a():
            test_func(arch_name)
        for test_func, arch_name in test_veritesting_b():
            test_func(arch_name)
