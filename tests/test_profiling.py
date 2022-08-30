import os
from io import BytesIO
from unittest import TestCase, main

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


class TestProfiling(TestCase):
    def test_project_created(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False, profile=True)
        assert proj.profiler is not None
        assert len(proj.profiler.events) == 1

    def test_profiling_dumps(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False, profile=True)
        assert proj.profiler is not None
        mem_file = BytesIO()

        proj.profiler.dump(mem_file)
        assert mem_file.tell() > 0
        mem_file.seek(0, 0)
        proj.profiler.events = [ ]
        proj.profiler.load(mem_file)

        assert proj.profiler.events

    def test_profiling_state_creation(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False, profile=True)
        assert proj.profiler is not None
        simgr = proj.factory.simgr()

        simgr.explore()
        assert len(proj.profiler.events) == 182


if __name__ == "__main__":
    main()
