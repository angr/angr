#!/usr/bin/env python3
# pylint: disable=missing-class-docstring
from __future__ import annotations
from unittest import main, TestCase

from archinfo import ArchMIPS32

from angr.calling_conventions import SimRegArg
from angr.knowledge_plugins.key_definitions.atoms import Atom, Register


class TestAtoms(TestCase):
    def test_from_argument_instantiate_a_Register_when_given_a_SimRegArg(self):
        argument = SimRegArg("r0", 4)
        arch = ArchMIPS32()

        result = Atom.from_argument(argument, arch)

        self.assertTrue(isinstance(result, Register))
        self.assertEqual(result.reg_offset, arch.registers["r0"][0])
        self.assertEqual(result.size, 4)


if __name__ == "__main__":
    main()
