# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.ailment"  # pylint:disable=redefined-builtin

import unittest

import archinfo

import angr
from angr import ailment
from angr.ailment.expression import Tmp
from angr.ailment.statement import Assignment


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
        # dmulu.l r1,r2 ; sts mach,r3 ; sts macl,r4 ; rts ; nop
        code = bytes.fromhex("15320a031a040b000900")
        arch = archinfo.ArchPcode("SuperH4:LE:32:default")
        project = angr.load_shellcode(code, arch=arch, load_address=0x1000, engine=angr.engines.UberEnginePcode)

        block = ailment.IRSBConverter.convert(project.factory.block(0x1000).vex, ailment.Manager(arch=arch))

        defined, used = _tmp_indices(block)
        assert used, "the block should read at least one tmp"
        assert not (used - defined), f"tmp read without a definition: {sorted(used - defined)}"

    def test_the_two_halves_of_a_widening_multiply_differ(self):
        """
        The high half of a little-endian wide unique lives at the higher address, so extracting it needs
        a shift. Computing that offset the big-endian way returns the low half for both halves, which
        decompiles to two identical assignments instead of MACH and MACL.
        """
        code = bytes.fromhex("15320a031a040b000900")
        arch = archinfo.ArchPcode("SuperH4:LE:32:default")
        project = angr.load_shellcode(code, arch=arch, load_address=0x1000, engine=angr.engines.UberEnginePcode)

        block = ailment.IRSBConverter.convert(project.factory.block(0x1000).vex, ailment.Manager(arch=arch))

        halves = [str(stmt.src) for stmt in block.statements if isinstance(stmt, Assignment)]
        shifted = [h for h in halves if "Shr" in h]
        assert shifted, f"neither half of the product is shifted: {halves}"


if __name__ == "__main__":
    unittest.main()
