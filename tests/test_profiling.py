import os
from unittest import TestCase, main

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


class TestProfiling(TestCase):
    def test_project_created(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False, profile=True)
        assert proj.profiler is not None
        assert len(proj.profiler.events) == 1

    def test_profiling_dumps


if __name__ == "__main__":
    main()
