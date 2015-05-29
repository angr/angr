
import sys
import os
import logging

import nose.tools

import angr

l = logging.getLogger('angr_tests.veritesting')

location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

addresses_veritesting_a = {
    'x86_64': 0x400674
}

addresses_veritesting_b = {
    'x86_64': 0x4006af
}

def run_veritesting_a(arch):
    # TODO: Added timeout control, since a failed state merging will result in running for a long time

    logging.getLogger('angr.analyses.sse').setLevel(logging.DEBUG)

    proj = angr.Project(os.path.join(os.path.join(location, arch), "veritesting_a"),
                        load_options={'auto_load_libs': False},
                        use_sim_procedures=True
                        )
    ex = proj.surveyors.Explorer(find=(addresses_veritesting_a[arch], ), enable_veritesting=True)
    r = ex.run()
    nose.tools.assert_not_equal(len(r.found), 0)
    # Make sure the input makes sense
    input_str = r.found[0].state.plugins['posix'].dumps(0)
    nose.tools.assert_equal(input_str.count('B'), 10)

def run_veritesting_b(arch):
    logging.getLogger('angr.analyses.sse').setLevel(logging.DEBUG)

    proj = angr.Project(os.path.join(os.path.join(location, arch), "veritesting_b"),
                        load_options={'auto_load_libs': False},
                        use_sim_procedures=True
                        )
    ex = proj.surveyors.Explorer(find=(addresses_veritesting_b[arch], ), enable_veritesting=True)
    r = ex.run()
    nose.tools.assert_not_equal(len(r.found), 0)
    # Make sure the input makes sense
    input_str = r.found[0].state.plugins['posix'].dumps(0)
    nose.tools.assert_equal(input_str.count('B'), 10)

def test_veritesting_a():
    """
    This is the most basic test
    """

    logging.getLogger('angr.analyses.sse').setLevel(logging.DEBUG)

    for arch in addresses_veritesting_a.keys():
        yield run_veritesting_a, arch

def test_veritesting_b():
    """
    Advanced stuff - it tests for the ability to inline simple functions as well as simple syscalls like read/write
    """

    for arch in addresses_veritesting_b.keys():
        yield run_veritesting_b, arch


if __name__ == "__main__":
    if len(sys.argv) > 1:
        func_name = 'test_' + sys.argv[1]
        if func_name in globals() and hasattr(globals()[func_name], '__call__'):
            f = globals()[func_name]
            for func, arch in f():
                func(arch)

        else:
            raise ValueError('Function %s does not exist' % func_name)

    else:
        g = globals()
        for func_name, f in g.items():
            if func_name.startswith('test_') and hasattr(f, '__call__'):
                for func, arch in f():
                    func(arch)
