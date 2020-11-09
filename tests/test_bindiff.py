import nose
import angr

import logging
l = logging.getLogger("angr.tests.test_bindiff")

import os
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

# todo make a better test
def test_bindiff_x86_64():
    binary_path_1 = os.path.join(test_location, 'x86_64', 'bindiff_a')
    binary_path_2 = os.path.join(test_location, 'x86_64', 'bindiff_b')
    b = angr.Project(binary_path_1, load_options={"auto_load_libs": False})
    b2 = angr.Project(binary_path_2, load_options={"auto_load_libs": False})
    bindiff = b.analyses.BinDiff(b2)

    identical_functions = bindiff.identical_functions
    differing_functions = bindiff.differing_functions
    unmatched_functions = bindiff.unmatched_functions
    # check identical functions
    nose.tools.assert_in((0x40064c, 0x40066a), identical_functions)
    # check differing functions
    nose.tools.assert_in((0x400616, 0x400616), differing_functions)
    # check unmatched functions
    nose.tools.assert_less_equal(len(unmatched_functions[0]), 1)
    nose.tools.assert_less_equal(len(unmatched_functions[1]), 2)
    # check for no major regressions
    nose.tools.assert_greater(len(identical_functions), len(differing_functions))
    nose.tools.assert_less(len(differing_functions), 4)

    # check a function diff
    fdiff = bindiff.get_function_diff(0x400616, 0x400616)
    block_matches = { (a.addr, b.addr) for a, b in fdiff.block_matches }
    nose.tools.assert_in((0x40064a, 0x400668), block_matches)
    nose.tools.assert_in((0x400616, 0x400616), block_matches)
    nose.tools.assert_in((0x40061e, 0x40061e), block_matches)

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()

if __name__ == "__main__":
    logging.getLogger("angr.analyses.bindiff").setLevel(logging.DEBUG)

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
