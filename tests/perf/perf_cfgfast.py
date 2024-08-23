from __future__ import annotations
import os
import time

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../binaries")
p = angr.Project(os.path.join(test_location, "tests", "x86_64", "libc.so.6"), auto_load_libs=False)


def main():
    p.analyses.CFGFast()


if __name__ == "__main__":
    tstart = time.time()
    main()
    tend = time.time()
    print("Elapsed: %f sec" % (tend - tstart))
