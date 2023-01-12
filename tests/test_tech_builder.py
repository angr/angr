import angr

import logging

l = logging.getLogger("angr_tests.test_proxy")

import os

location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


def test_tech_builder():
    class Foo:
        @staticmethod
        def setup(*args, **kwargs):
            l.debug("setup() triggered!")

        @staticmethod
        def step_state(*args, **kwargs):
            l.debug("step_state() triggered!")
            return None

        @staticmethod
        def step(simgr, stash, *args, **kwargs):
            l.debug("step() triggered!")
            return simgr.step(stash=stash, **kwargs)

        @staticmethod
        def filter(*args, **kwargs):
            l.debug("filter() triggered!")
            return None

        @staticmethod
        def complete(*args, **kwargs):
            l.debug("complete() triggered!")
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
    test_tech_builder()
