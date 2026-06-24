#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins"  # pylint:disable=redefined-builtin

import os
import pickle
import unittest

import networkx

import angr
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestVariableManager(unittest.TestCase):
    def test_unify_variables_tolerates_non_candidate_phi_subvariable(self):
        # A phi sub-variable may be a global SimMemoryVariable that is not itself a
        # recovered variable (e.g. a local assigned from a global on one path). Such
        # a sub-variable is absent from the congruence classes, and unify_variables()
        # must not choke on it. Regression test for a KeyError in unify().
        p = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        vmi = p.kb.variables.get_function_manager(0x400000)

        # Two recovered stack locals at the same slot -> they appear in get_variables().
        sv_a = SimStackVariable(-0x20, 4, base="bp", ident=vmi.next_variable_ident("stack"))
        sv_b = SimStackVariable(-0x20, 4, base="bp", ident=vmi.next_variable_ident("stack"))
        vmi.set_variable("stack", -0x20, sv_a)
        vmi.set_variable("stack", -0x20, sv_b)

        # A global load that is *not* a recovered variable (absent from get_variables()).
        gv = SimMemoryVariable(0x601000, 4, ident=vmi.next_variable_ident("global"))

        # A stack phi over the two locals, with the global merged in as a third source.
        phi = vmi.make_phi_node(0x400100, sv_a, sv_b)
        vmi.make_phi_node(0x400100, phi, gv)
        assert isinstance(phi, SimStackVariable)
        assert gv in vmi.get_phi_subvariables(phi)
        assert gv not in vmi.get_variables()

        # Must not raise (previously: KeyError on the global sub-variable).
        vmi.unify_variables(interference=networkx.Graph())

        # The stack locals are unified; the non-candidate global is left alone.
        assert vmi.unified_variable(sv_a) is not None
        assert vmi.unified_variable(gv) is None

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
