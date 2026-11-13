# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.ailment"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr import ailment
from angr.ailment.expression import Register, Tmp
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

# 200079a  mac.l @r0+, @r0+  -- the same shape on a big-endian SuperH, where SLEIGH puts the high
# half of the product at the wide unique's own address rather than four bytes above it.
BE_TEST_BINARY = os.path.join(_binaries, "tests", "sh4", "hello_32x_sh2be")
BE_BLOCK_ADDR = 0x200079A
BE_BLOCK_INSNS = 1

FIXTURES = ((TEST_BINARY, BLOCK_ADDR, BLOCK_INSNS), (BE_TEST_BINARY, BE_BLOCK_ADDR, BE_BLOCK_INSNS))


def _convert(binary=TEST_BINARY, addr=BLOCK_ADDR, insns=BLOCK_INSNS):
    """Convert one of the blocks above to AIL. SuperH has no VEX lifter, so this goes through
    pypcode and the p-code converter."""
    project = angr.Project(binary, auto_load_libs=False)
    block = project.factory.block(addr, num_inst=insns)
    return project.arch, ailment.IRSBConverter.convert(block.vex, ailment.Manager())


def _tmp_widths(block):
    """Return the width each tmp is defined with, and the widths each one is read at, nested
    reads included."""
    defined, used = {}, {}

    def collect(expr):
        if isinstance(expr, Tmp):
            used.setdefault(expr.tmp_idx, set()).add(expr.bits)
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
            defined[dst.tmp_idx] = dst.bits
        if isinstance(stmt, Assignment):
            collect(stmt.src)
    return defined, used


def _assignment_to(arch, block, reg_name):
    offset = arch.get_register_offset(reg_name)
    for stmt in block.statements:
        if isinstance(stmt, Assignment) and isinstance(stmt.dst, Register) and stmt.dst.reg_offset == offset:
            return stmt
    raise AssertionError(f"no assignment to {reg_name} in {[str(s) for s in block.statements]}")


class TestPcodeConverter(unittest.TestCase):
    def test_partial_read_of_a_wide_unique_names_the_defining_tmp(self):
        """
        A SLEIGH multiply writes one wide value into unique space and the following instruction reads
        half of it. The converter remaps unique-space addresses to tmp indices, and the partial read
        used to name the parent by its unique-space address instead of its remapped index, producing a
        tmp that no statement defines. Nothing rejects that until the decompiler indexes it.
        """
        _, block = _convert()

        defined, used = _tmp_widths(block)
        assert used, "the block should read at least one tmp"
        missing = set(used) - set(defined)
        assert not missing, f"tmp read without a definition: {sorted(missing)}"

    def test_the_two_halves_of_a_widening_multiply_differ(self):
        """
        The high half of a little-endian wide unique lives at the higher address, so extracting it needs
        a shift. Computing that offset the big-endian way returns the low half for both halves, which
        decompiles to two identical assignments instead of MACH and MACL.
        """
        _, block = _convert()

        halves = [str(stmt.src) for stmt in block.statements if isinstance(stmt, Assignment)]
        shifted = [h for h in halves if "Shr" in h]
        assert shifted, f"neither half of the product is shifted: {halves}"

    def test_a_tmp_is_read_at_the_width_it_is_defined_with(self):
        """
        The converter reached the shift path only when the read started above the wide unique's own
        address. A read that starts at that address but is narrower took the whole-tmp path instead
        and came out as a bare tmp of the read's width, so the same tmp index appeared defined at 64
        bits and read at 32.
        """
        for binary, addr, insns in FIXTURES:
            with self.subTest(binary=os.path.basename(binary)):
                _, block = _convert(binary, addr, insns)

                defined, used = _tmp_widths(block)
                mismatched = {i: (defined[i], w) for i, w in used.items() if i in defined and w != {defined[i]}}
                assert not mismatched, f"tmp read at a width it was not defined with: {mismatched}"

    def test_mach_gets_the_high_half_in_either_byte_order(self):
        """
        Both of these multiplies put the product's high half in MACH and its low half in MACL. Which
        end of the wide unique the high half sits at depends on the byte order, so on a big-endian
        target MACH was read straight off the unique's own address and got the low half unshifted.
        """
        for binary, addr, insns in FIXTURES:
            with self.subTest(binary=os.path.basename(binary)):
                arch, block = _convert(binary, addr, insns)

                mach = str(_assignment_to(arch, block, "mach").src)
                macl = str(_assignment_to(arch, block, "macl").src)
                assert "Shr" in mach, f"MACH is not shifted out of the wide unique: {mach}"
                assert "Shr" not in macl, f"MACL is shifted, so it is not the low half: {macl}"


if __name__ == "__main__":
    unittest.main()
