#!/usr/bin/env python3
# pylint: disable=missing-class-docstring
from __future__ import annotations

import pickle
from unittest import TestCase, main

from archinfo import ArchMIPS32, ArchX86

from angr.calling_conventions import SimCCCdecl, SimRegArg
from angr.code_location import CodeLocation
from angr.knowledge_plugins.key_definitions.atoms import Atom, Register
from angr.knowledge_plugins.key_definitions.definition import Definition


class TestAtoms(TestCase):
    def test_from_argument_instantiate_a_Register_when_given_a_SimRegArg(self):
        argument = SimRegArg("r0", 4)
        arch = ArchMIPS32()

        result = Atom.from_argument(argument, arch)

        self.assertTrue(isinstance(result, Register))
        self.assertEqual(result.reg_offset, arch.registers["r0"][0])
        self.assertEqual(result.size, 4)

    def test_from_argument_rejects_a_register_the_architecture_does_not_have(self):
        # cdecl returns a float at the top of the x87 stack and names that location "st0". VEX models
        # the stack as fpreg indexed by the run-time value of ftop, so "st0" resolves only against a
        # state and ArchX86.registers has no entry for it.
        arch = ArchX86()
        fp_return_val = SimCCCdecl(arch).FP_RETURN_VAL
        assert isinstance(fp_return_val, SimRegArg)
        self.assertEqual(fp_return_val.reg_name, "st0")
        self.assertNotIn("st0", arch.registers)

        with self.assertRaises(ValueError):
            Atom.from_argument(fp_return_val, arch, full_reg=True)
        with self.assertRaises(ValueError):
            Atom.from_argument(fp_return_val, arch)

    def test_cached_hash_not_carried_across_pickling(self):
        # The cached hash folds in per-process-salted hashes (e.g. of register
        # name strings), so persisting it makes it stale when unpickled in
        # another process. It must be dropped on pickling and recomputed lazily.
        arch = ArchMIPS32()
        register = Atom.from_argument(SimRegArg("r0", 4), arch)
        codeloc = CodeLocation(0x400000, 0)
        definition = Definition(register, codeloc)

        for obj in (register, codeloc, definition):
            hash(obj)  # populate the cache
            self.assertIsNotNone(obj._hash)  # pylint: disable=protected-access
            clone = pickle.loads(pickle.dumps(obj))
            self.assertIsNone(clone._hash)  # pylint: disable=protected-access
            self.assertEqual(hash(clone), hash(obj))


if __name__ == "__main__":
    main()
