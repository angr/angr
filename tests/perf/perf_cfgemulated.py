import os
import time

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../binaries")
p = angr.Project(os.path.join(test_location, "tests", "x86_64", "true"), auto_load_libs=False)
funcs = list(p.analyses.CFGFast().functions.keys())


def main():
    p.analyses.CFGEmulated(starts=funcs, call_depth=0)


if __name__ == "__main__":
    tstart = time.time()
    main()
    tend = time.time()
    print("Elapsed: %f sec" % (tend - tstart))
