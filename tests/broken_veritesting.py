
import os
import logging

import nose.tools

import angr

l = logging.getLogger('angr_tests.veritesting')

location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

addresses_veritesting_a = {
    'x86_64': 0x40066d
}

def run_veritesting_a(arch):
    proj = angr.Project(os.path.join(os.path.join(location, arch), "veritesting_a"))
    ex = proj.surveyors.Explorer(find=(0x40066d, ), enable_veritesting=True)
    r = ex.run()
    nose.tools.assert_not_equal(len(r.found), 0)

def test_veritesting_a():
    """
    This is the most basic test
    """

    for arch in addresses_veritesting_a.keys():
        yield run_veritesting_a, arch


if __name__ == "__main__":
    g = globals()
    for func_name, f in g.items():
        if func_name.startswith('test_') and hasattr(f, '__call__'):
            for func, arch in f():
                func(arch)
