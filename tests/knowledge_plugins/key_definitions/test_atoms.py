from unittest import TestCase

from angr.calling_conventions import SimRegArg
from angr.knowledge_plugins.key_definitions.atoms import Atom, Register
from archinfo import ArchMIPS32

class TestAtoms(TestCase):
    def test_from_argument_instanciate_a_Register_when_given_a_SimRegArg(self):
        argument = SimRegArg("r0", 4)
        arch = ArchMIPS32()

        result = Atom.from_argument(argument, arch)

        self.assertTrue(isinstance(result, Register))
        self.assertEqual(result.reg_offset, arch.registers['r0'][0])
        self.assertEqual(result.size, 4)
