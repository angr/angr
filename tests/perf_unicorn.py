
import sys
import os
import time

import angr
import angr.options as so

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../'))

def perf_unicorn_0():
    p = angr.Project(os.path.join(test_location, 'binaries', 'tests', 'x86_64', 'perf_unicorn_0'))

    s_unicorn = p.factory.entry_state(add_options=so.unicorn | {so.STRICT_PAGE_ACCESS}, remove_options={so.LAZY_SOLVES}) # unicorn

    pg_unicorn = p.factory.path_group(s_unicorn)

    start = time.time()
    pg_unicorn.run()
    elapsed = time.time() - start

    print "Elapsed %f sec" % elapsed
    print pg_unicorn.one_deadended

def perf_unicorn_1():
    p = angr.Project(os.path.join(test_location, 'binaries', 'tests', 'x86_64', 'perf_unicorn_1'))

    s_unicorn = p.factory.entry_state(add_options=so.unicorn | {so.STRICT_PAGE_ACCESS}, remove_options={so.LAZY_SOLVES}) # unicorn

    pg_unicorn = p.factory.path_group(s_unicorn)

    start = time.time()
    pg_unicorn.run()
    elapsed = time.time() - start

    print "Elapsed %f sec" % elapsed
    print pg_unicorn.one_deadended

if __name__ == "__main__":

    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            print 'perf_' + arg
            globals()['perf_' + arg]()

    else:
        for fk, fv in globals().items():
            if fk.startswith('perf_') and callable(fv):
                print fk
                res = fv()
