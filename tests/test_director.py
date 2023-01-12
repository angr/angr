# pylint: disable=missing-class-docstring,disable=no-self-use
import os
import logging
import unittest

import angr
from angr.sim_type import SimTypePointer, SimTypeChar

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


class TestDirector(unittest.TestCase):
    def test_execute_address_brancher(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "brancher"), load_options={"auto_load_libs": False})

        pg = p.factory.simulation_manager()

        # initialize the exploration technique
        dm = angr.exploration_techniques.Director(num_fallback_states=1)
        goal = angr.exploration_techniques.ExecuteAddressGoal(0x400594)
        dm.add_goal(goal)
        pg.use_technique(dm)

        pg.explore(find=(0x4005B4,))

        assert len(pg.deprioritized) > 0

    def test_call_function_brancher(self):
        class NonLocal:
            the_state = None
            the_goal = None

        def goal_reached_callback(goal, p, pg):  # pylint:disable=unused-argument
            NonLocal.the_state = p
            NonLocal.the_goal = goal

        p = angr.Project(os.path.join(test_location, "x86_64", "brancher"), load_options={"auto_load_libs": False})

        pg = p.factory.simulation_manager()

        # initialize the exploration technique
        dm = angr.exploration_techniques.Director(
            cfg_keep_states=True, goal_satisfied_callback=goal_reached_callback, num_fallback_states=1
        )
        _ = p.analyses.CFG()
        puts_func = p.kb.functions.function(name="puts")
        goal = angr.exploration_techniques.CallFunctionGoal(puts_func, [(SimTypePointer(SimTypeChar()), ">=20")])
        dm.add_goal(goal)
        pg.use_technique(dm)

        pg.explore(find=(0x40059E,))

        assert len(pg.deprioritized) > 0
        assert len(pg.found) > 0
        assert NonLocal.the_state is not None
        assert NonLocal.the_goal is goal


if __name__ == "__main__":
    logging.getLogger("angr.exploration_techniques.director").setLevel(logging.DEBUG)
    unittest.main()
