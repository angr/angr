
import os
import sys
import logging

import nose.tools

import angr
import simuvex

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests'))

def test_execute_address_brancher():

    p = angr.Project(os.path.join(test_location, 'x86_64', 'brancher'), load_options={'auto_load_libs': False})

    pg = p.factory.path_group()

    # initialize the exploration technique
    dm = angr.exploration_techniques.Determinist()
    goal = angr.exploration_techniques.ExecuteAddressGoal(0x400594)
    dm.add_goal(goal)
    pg.use_technique(dm)

    pg.explore(find=(0x4005b4,))

    nose.tools.assert_greater(len(pg.deprioritized), 0)

    # TODO: finish this test case


if __name__ == "__main__":

    logging.getLogger('angr.exploration_techniques.determinist').setLevel(logging.DEBUG)

    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()

    else:
        g = globals().copy()

        for k, v in g.iteritems():
            if k.startswith("test_") and hasattr(v, '__call__'):
                v()
