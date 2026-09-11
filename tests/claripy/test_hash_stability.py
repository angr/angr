from __future__ import annotations

import subprocess
import sys
import unittest

from angr import claripy

HASH_SCRIPT = """\
import angr
from angr import claripy

x = claripy.BVS("x", 64, explicit_name=True)
y = claripy.BVS("y", 64, explicit_name=True)
for ast in (x, y, x + y, (x - 48).ULE(9), claripy.Or((x - 48).ULE(9), (x - 43).ULE(2))):
    print(hash(ast))
"""


def _asts():
    x = claripy.BVS("x", 64, explicit_name=True)
    y = claripy.BVS("y", 64, explicit_name=True)
    return (x, y, x + y, (x - 48).ULE(9), claripy.Or((x - 48).ULE(9), (x - 43).ULE(2)))


class TestHashStability(unittest.TestCase):
    """Two processes hash the same expression to the same number."""

    def test_hashes_agree_with_another_process(self):
        """angr reads these hashes back out. The decompiler names sympy symbols after them and
        sympy orders the operands of a disjunction by symbol name, so a hash that varies per
        process makes decompiled C depend on which process produced it.
        """
        here = [hash(ast) for ast in _asts()]

        result = subprocess.run(
            [sys.executable, "-c", HASH_SCRIPT],
            capture_output=True,
            text=True,
            timeout=300,
            check=True,
        )
        there = [int(line) for line in result.stdout.split()]

        self.assertEqual(here, there)


if __name__ == "__main__":
    unittest.main()
