
import os
import sys
import logging

import nose.tools

import angr
from angr.sim_type import SimTypePointer, SimTypeChar

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests'))

def test_call_function_brancher():
    p = angr.Project(os.path.join(test_location, 'x86_64', 'brancher'), auto_load_libs=False)

    sm = p.factory.simgr()

    # initialize the exploration technique
    dfs = angr.exploration_techniques.DFS()
    sm.use_technique(dfs)

    while sm.active:
        assert len(sm.active) == 1
        sm.step()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()

    else:
        g = globals().copy()

        for k, v in g.iteritems():
            if k.startswith("test_") and hasattr(v, '__call__'):
                v()
