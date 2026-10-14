# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.ailment"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr import ailment
from angr.ailment.expression import Tmp
from angr.ailment.statement import Assignment

# 420e5c  dmulu.l r4, r5   -- SLEIGH writes the 64-bit product to one wide unique and reads a
# 420e5e  sts     MACL, r1     32-bit half of it back for each of MACL and MACH, all under the
# 420e60  sts     MACH, r2     first instruction. The two sts are register moves.
# Derived the way tests/common.py derives bin_location. Importing it from here instead would be
# the first `import tests` of a --collect-only run -- tests/ailment sorts before tests/analyses and
# has no __init__.py, so pytest has only tests/ailment on sys.path at that point, and the "tests"
# that binds is not this one. That poisons every later tests.* import: 337 collection errors.
_binaries = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "..", "binaries")
TEST_BINARY = os.path.join(_binaries, "tests", "sh4", "test-instr_sh4")
BLOCK_ADDR = 0x420E5C
# The instruction bound is load-bearing. The natural block here is 8 instructions and contains two
# shifts of its own, so without it test_the_two_halves_of_a_widening_multiply_differ finds a Shr and
# passes on the unfixed converter. Three is a readable window; one would do.
BLOCK_INSNS = 3


def _convert():
    """Convert the three-instruction block above to AIL. SuperH has no VEX lifter, so this goes
    through pypcode and the p-code converter."""
    project = angr.Project(TEST_BINARY, auto_load_libs=False)
    block = project.factory.block(BLOCK_ADDR, num_inst=BLOCK_INSNS)
    return ailment.IRSBConverter.convert(block.vex, ailment.Manager())


def _tmp_indices(block):
    """Return the tmp indices this block defines and the ones it reads, nested reads included."""
    defined, used = set(), set()

    def collect(expr):
        if isinstance(expr, Tmp):
            used.add(expr.tmp_idx)
        for operand in getattr(expr, "operands", None) or ():
            collect(operand)
        for arg in getattr(expr, "args", None) or ():
            collect(arg)
        inner = getattr(expr, "operand", None)
        if inner is not None:
            collect(inner)

    for stmt in block.statements:
        dst = getattr(stmt, "dst", None)
        if isinstance(dst, Tmp):
            defined.add(dst.tmp_idx)
        if isinstance(stmt, Assignment):
            collect(stmt.src)
    return defined, used


class TestPcodeConverter(unittest.TestCase):
    def test_partial_read_of_a_wide_unique_names_the_defining_tmp(self):
        """
        A SLEIGH multiply writes one wide value into unique space and the following instruction reads
        half of it. The converter remaps unique-space addresses to tmp indices, and the partial read
        used to name the parent by its unique-space address instead of its remapped index, producing a
        tmp that no statement defines. Nothing rejects that until the decompiler indexes it.
        """
        block = _convert()

        defined, used = _tmp_indices(block)
        assert used, "the block should read at least one tmp"
        assert not (used - defined), f"tmp read without a definition: {sorted(used - defined)}"

    def test_the_two_halves_of_a_widening_multiply_differ(self):
        """
        The high half of a little-endian wide unique lives at the higher address, so extracting it needs
        a shift. Computing that offset the big-endian way returns the low half for both halves, which
        decompiles to two identical assignments instead of MACH and MACL.
        """
        block = _convert()

        halves = [str(stmt.src) for stmt in block.statements if isinstance(stmt, Assignment)]
        shifted = [h for h in halves if "Shr" in h]
        assert shifted, f"neither half of the product is shifted: {halves}"


if __name__ == "__main__":
    unittest.main()
