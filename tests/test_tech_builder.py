# pylint: disable=missing-class-docstring,no-self-use,line-too-long

import logging
import os
import unittest

import angr

log = logging.getLogger("angr_tests.test_proxy")
location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


class TestTechBuilder(unittest.TestCase):
    def test_tech_builder(self):
        # pylint:disable=unused-argument
        class Foo:
            @staticmethod
            def setup(*args, **kwargs):
                log.debug("setup() triggered!")

            @staticmethod
            def step_state(*args, **kwargs):
                log.debug("step_state() triggered!")

            @staticmethod
            def step(simgr, stash, *args, **kwargs):
                log.debug("step() triggered!")
                return simgr.step(stash=stash, **kwargs)

            @staticmethod
            def filter(*args, **kwargs):
                log.debug("filter() triggered!")

            @staticmethod
            def complete(*args, **kwargs):
                log.debug("complete() triggered!")
                return True

        p = angr.Project(os.path.join(location, "x86_64", "fauxware"), load_options={"auto_load_libs": False})

        foo = Foo()
        proxy_tech = angr.exploration_techniques.TechniqueBuilder(
            setup=foo.setup,
            step_state=foo.step_state,
            step=foo.step,
            filter=foo.filter,
            complete=foo.complete,
        )

        pg = p.factory.simulation_manager()
        pg.use_technique(proxy_tech)
        pg.run()


if __name__ == "__main__":
    unittest.main()
