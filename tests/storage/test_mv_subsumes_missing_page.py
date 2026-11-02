from __future__ import annotations

import unittest

from angr import SimState, claripy
from angr.storage.memory_mixins import MultiValuedMemory
from tests.common import minimal_project


class TestMVSubsumesMissingPage(unittest.TestCase):
    def test_page_only_in_other(self):
        s0 = SimState(project=minimal_project("AMD64"), mode="symbolic", plugins={"memory": MultiValuedMemory()})
        s0.memory.store(0x100, claripy.BVV(1, 32))
        s1 = s0.copy()
        s1.memory.store(0x5000, claripy.BVV(2, 32))
        assert s1.memory.subsumes(s0.memory) is True
        assert s0.memory.subsumes(s1.memory) is False


if __name__ == "__main__":
    unittest.main()
