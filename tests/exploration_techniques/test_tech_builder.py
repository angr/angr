#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.exploration_techniques"  # pylint:disable=redefined-builtin

import logging
import os
import unittest

import angr

from ..common import bin_location


test_location = os.path.join(bin_location, "tests")
log = logging.getLogger("angr_tests.test_proxy")


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

        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), load_options={"auto_load_libs": False})

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
