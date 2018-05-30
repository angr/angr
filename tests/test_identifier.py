import angr
import nose

import os
bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries'))

import logging

def test_comparison_identification():
    true_symbols = {0x804a3d0: 'strncmp', 0x804a0f0: 'strcmp', 0x8048e60: 'memcmp', 0x8049f40: 'strcasecmp'}

    p = angr.Project(os.path.join(bin_location, "tests", "i386", "identifiable"))
    idfer = p.analyses.Identifier(require_predecessors=False)

    seen = dict()
    for addr, symbol in idfer.run():
        seen[addr] = symbol

    for addr, symbol in true_symbols.items():
        nose.tools.assert_equal(true_symbols[addr], seen[addr])

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()

if __name__ == "__main__":
    logging.getLogger("identifier").setLevel("DEBUG")
    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
