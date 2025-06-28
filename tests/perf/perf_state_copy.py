from __future__ import annotations
import os
import pytest
import unittest

import angr
import claripy

bvs = claripy.BVS("foo", 8)

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../binaries")


def cycle(s):
    s = s.copy()
    s.memory.store(0x400000, bvs)
    return s


class TestPerfStateCopy(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.state = angr.Project(
            os.path.join(test_location, "tests", "x86_64", "fauxware"),
            main_opts={"base_addr": 0x400000},
            auto_load_libs=True,
        ).factory.full_init_state(add_options={angr.options.REVERSE_MEMORY_NAME_MAP})

    @pytest.mark.benchmark
    def test_main(self):
        s = cycle(self.state)
        for _ in range(20000):
            s = cycle(s)


if __name__ == "__main__":
    unittest.main()
