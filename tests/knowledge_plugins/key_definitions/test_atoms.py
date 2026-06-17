#!/usr/bin/env python3
# pylint: disable=missing-class-docstring
from __future__ import annotations

import pickle
from unittest import TestCase, main

from archinfo import ArchMIPS32

from angr.calling_conventions import SimRegArg
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
