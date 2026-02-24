#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins"  # pylint:disable=redefined-builtin

import os
import pickle
import unittest

import angr

from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestVariableManager(unittest.TestCase):
    def test_variable_manager_internal_pickle(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        vm = p.kb.variables

        # Create a VariableManagerInternal and generate some variable idents
        vmi = vm.get_function_manager(0x400000)
        ident0 = vmi.next_variable_ident("stack")
        ident1 = vmi.next_variable_ident("stack")
        ident2 = vmi.next_variable_ident("register")
        assert ident0 == "is_0"
        assert ident1 == "is_1"
        assert ident2 == "ir_0"

        # Pickle round-trip
        data = pickle.dumps(vmi)
        vmi2 = pickle.loads(data)

        # The counters should continue from where they left off
        ident3 = vmi2.next_variable_ident("stack")
        ident4 = vmi2.next_variable_ident("register")
        assert ident3 == "is_2"
        assert ident4 == "ir_1"


if __name__ == "__main__":
    unittest.main()
