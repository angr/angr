from unittest import TestCase

from angr.calling_conventions import SimRegArg
from angr.knowledge_plugins.key_definitions.atoms import Atom, Register


class TestAtoms(TestCase):
    def test_from_argument_instanciate_a_Register_when_given_a_SimRegArg(self):
        argument = SimRegArg('r0', 4)
        registers = { 'r0': (8, 4) }

        result = Atom.from_argument(argument, registers)

        self.assertTrue(isinstance(result, Register))
        self.assertEqual(result.reg_offset, 8)
        self.assertEqual(result.size, 4)
