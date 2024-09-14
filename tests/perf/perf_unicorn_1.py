from __future__ import annotations
import os
import time

import angr
from angr import options as so

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../binaries")
p = angr.Project(os.path.join(test_location, "tests", "x86_64", "perf_unicorn_1"))
s_unicorn = p.factory.entry_state(
    add_options=so.unicorn | {so.STRICT_PAGE_ACCESS}, remove_options={so.LAZY_SOLVES}
)  # unicorn


def main():
    sm_unicorn = p.factory.simulation_manager(s_unicorn)
    sm_unicorn.run()


if __name__ == "__main__":
    tstart = time.time()
    main()
    tend = time.time()
    print("Elapsed: %f sec" % (tend - tstart))
