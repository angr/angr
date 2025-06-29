from __future__ import annotations
import os
import unittest

import angr
from angr import options as so

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../binaries")


def test_unicorn_0(benchmark):
    p = angr.Project(os.path.join(test_location, "tests", "x86_64", "perf_unicorn_0"))
    s_unicorn = p.factory.entry_state(
        add_options=so.unicorn | {so.STRICT_PAGE_ACCESS}, remove_options={so.LAZY_SOLVES}
    )  # unicorn
    sm_unicorn = p.factory.simulation_manager(s_unicorn)

    benchmark(sm_unicorn.run)


def test_unicorn_1(benchmark):
    p = angr.Project(os.path.join(test_location, "tests", "x86_64", "perf_unicorn_1"))
    s_unicorn = p.factory.entry_state(
        add_options=so.unicorn | {so.STRICT_PAGE_ACCESS}, remove_options={so.LAZY_SOLVES}
    )  # unicorn
    sm_unicorn = p.factory.simulation_manager(s_unicorn)

    benchmark(sm_unicorn.run)


if __name__ == "__main__":
    unittest.main()
