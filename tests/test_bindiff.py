import nose
import angr

import logging
l = logging.getLogger("angr.tests.test_bindiff")

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))


def test_bindiff_x86_64():
    binary_path_1 = test_location + "/x86_64/bindiff_a"
    binary_path_2 = test_location + "/x86_64/bindiff_b"
    b = angr.Project(binary_path_1, load_options={"auto_load_libs": False})
    b2 = angr.Project(binary_path_2, load_options={"auto_load_libs": False})
    bindiff = b.analyses.BinDiff(b2)

    identical_functions = bindiff.identical_functions
    differing_functions = bindiff.differing_functions
    unmatched_functions = bindiff.unmatched_functions
    # check identical functions
    nose.tools.assert_in((0x40064c, 0x40066a), identical_functions)
    nose.tools.assert_in((0x400689, 0x4006a7), identical_functions)
    # check differing functions
    nose.tools.assert_in((0x400616, 0x400616), differing_functions)
    # check unmatched functions
    nose.tools.assert_equal(unmatched_functions, (set(), {0x4006b7}))
    # check for no major regressions
    nose.tools.assert_greater(len(identical_functions), len(differing_functions))

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()

if __name__ == "__main__":
    logging.getLogger("angr.surveyors.Explorer").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.bindiff").setLevel(logging.DEBUG)

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()