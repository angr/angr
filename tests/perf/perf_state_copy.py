#!/usr/bin/env python3
from __future__ import annotations

import os
import time

import angr
import claripy

bvs = claripy.BVS("foo", 8)

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../binaries")
state = angr.Project(
    os.path.join(test_location, "tests", "x86_64", "fauxware"), main_opts={"base_addr": 0x400000}, auto_load_libs=True
).factory.full_init_state(add_options={angr.options.REVERSE_MEMORY_NAME_MAP})


def cycle(s):
    s = s.copy()
    s.memory.store(0x400000, bvs)
    return s


def main():
    s = cycle(state)
    for _ in range(20000):
        s = cycle(s)


if __name__ == "__main__":
    tstart = time.time()
    main()
    tend = time.time()
    print("Elapsed: %f sec" % (tend - tstart))
