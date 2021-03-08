#!/usr/bin/env python3

import os
import time

import angr
import claripy

bvs = claripy.BVS('foo', 8)

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

def cycle(state):
    state = state.copy()
    state.memory.store(0x400000, bvs)
    return state

def main():
    state = angr.Project(os.path.join(test_location, 'x86_64', 'fauxware'), main_opts={'base_addr': 0x400000}, auto_load_libs=True).factory.full_init_state(add_options={angr.options.REVERSE_MEMORY_NAME_MAP})
    for _ in range(20000):
        state = cycle(state)

if __name__ == '__main__':
    tstart = time.time()
    main()
    tend = time.time()
    print('Elapsed: %f sec' % (tend - tstart))
