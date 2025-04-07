#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
from angr.sim_type import SimTypeFloat
from angr.analyses.typehoon.typevars import (
    TypeVariable,
    DerivedTypeVariable,
    Subtype,
    FuncIn,
    FuncOut,
    Load,
    Store,
    HasField,
)
from angr.analyses.typehoon.typeconsts import Int32, Struct, Pointer64, Float32, Float64
from angr.analyses.typehoon.translator import TypeTranslator

from tests.common import bin_location


test_location = os.path.join(bin_location, "tests")


class TestTypehoon(unittest.TestCase):
    def test_smoketest(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "linked_list"), auto_load_libs=False)
        cfg = p.analyses.CFG(data_references=True, normalize=True)

        main_func = cfg.kb.functions["sum"]

        vr = p.analyses.VariableRecoveryFast(main_func)
        p.analyses.CompleteCallingConventions()

        # import pprint
        tcons = vr.type_constraints
        # pprint.pprint(vr._outstates[0x4005b2].typevars._typevars)
        # pprint.pprint(tcons)

        _ = p.analyses.Typehoon(tcons, vr.func_typevar, var_mapping=vr.var_to_typevars)
        # pprint.pprint(t.simtypes_solution)

        # convert function blocks to AIL blocks
        # clinic = p.analyses.Clinic(main_func)

        # t = p.analyses.Typehoon(main_func) #, clinic)
        # print(t)

    def test_type_inference_byte_pointer_cast(self):
        proj = angr.Project(os.path.join(test_location, "i386", "type_inference_1"), auto_load_libs=False)
        cfg = proj.analyses.CFG(data_references=True, normalize=True)
        main_func = cfg.kb.functions["main"]
        proj.analyses.VariableRecoveryFast(main_func)
        proj.analyses.CompleteCallingConventions()

        dec = proj.analyses.Decompiler(main_func)
        assert "->field_0 = 10;" in dec.codegen.text
        assert "->field_4 = 20;" in dec.codegen.text
        assert "->field_8 = 808464432;" in dec.codegen.text
        assert "->field_c = 0;" in dec.codegen.text

    def test_function_call_argument_type_propagation(self):
        # ensure that UNICODE_STRING is propagated to stack variables from calls to RtlInitUnicodeString
        proj = angr.Project(os.path.join(test_location, "x86_64", "windows", "sioctl.sys"), auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        main_func = cfg.kb.functions[0x140006000]
        proj.analyses.VariableRecoveryFast(main_func)
        proj.analyses.CompleteCallingConventions()

        dec = proj.analyses.Decompiler(main_func, cfg=cfg.model)
        assert dec.codegen.text.count("UNICODE_STRING v") == 2

    def test_type_inference_basic_case_0(self):
        func_f = TypeVariable(name="F")
        v0 = TypeVariable(name="v0")
        type_constraints = {func_f: {Subtype(v0, Int32())}}
        proj = angr.load_shellcode(b"\x90\x90", "AMD64")
        typehoon = proj.analyses.Typehoon(
            type_constraints,
            func_f,
        )

        assert isinstance(typehoon.solution[v0], Int32)

    def test_type_inference_basic_case_1(self):
        func_f = TypeVariable(name="F")
        func_close = TypeVariable(name="close")
        t0 = TypeVariable(name="t0")
        t1 = TypeVariable(name="t1")
        t2 = TypeVariable(name="t2")
        type_constraints = {
            func_f: {
                Subtype(DerivedTypeVariable(func_f, FuncIn(0)), t2),
                Subtype(t1, t0),
                Subtype(t2, t0),
                Subtype(DerivedTypeVariable(t0, None, labels=[Load(), HasField(32, 0)]), t1),
                Subtype(DerivedTypeVariable(t0, None, labels=[Load(), HasField(32, 4)]), Int32()),
                Subtype(Int32(), DerivedTypeVariable(func_f, FuncOut(0))),
            },
            func_close: set(),
        }
        proj = angr.load_shellcode(b"\x90\x90", "AMD64")
        typehoon = proj.analyses.Typehoon(type_constraints, func_f)

        # print(typehoon.simtypes_solution)
        # print(typehoon.structs)
        t0_solution = typehoon.solution[t0]
        assert isinstance(t0_solution, Pointer64)
        assert isinstance(t0_solution.basetype, Struct)
        assert 0 in t0_solution.basetype.fields
        assert 4 in t0_solution.basetype.fields
        assert isinstance(t0_solution.basetype.fields[0], Pointer64)
        assert t0_solution.basetype.fields[0].basetype is t0_solution.basetype
        assert isinstance(t0_solution.basetype.fields[4], Int32)

    def test_type_inference_transitive(self):
        # a <: b <: c ==> a <: c
        func_f = TypeVariable(name="F")
        t0 = TypeVariable(name="T0")
        t1 = TypeVariable(name="T1")
        t2 = DerivedTypeVariable(t1, None, labels=[Store(), HasField(64, 0)])

        type_constraints = {
            func_f: {
                Subtype(Float64(), t0),
                Subtype(t0, t2),
            },
        }
        proj = angr.load_shellcode(b"\x90\x90", "AMD64")
        typehoon = proj.analyses.Typehoon(type_constraints, func_f)
        soln = typehoon.solution

        assert isinstance(soln[t0], Float64)
        assert isinstance(soln[t1], Pointer64)
        assert isinstance(soln[t1].basetype, Float64)
        assert isinstance(soln[t2], Float64)

    def test_struct_with_multiple_same_typed_members(self):
        func_f = TypeVariable(name="F")
        t0 = TypeVariable(name="T0")
        type_constraints = {
            func_f: {
                Subtype(DerivedTypeVariable(t0, None, labels=[Store(), HasField(64, 0)]), t0),
                Subtype(DerivedTypeVariable(t0, None, labels=[Store(), HasField(64, 8)]), t0),
            },
        }
        proj = angr.load_shellcode(b"\x90\x90", "AMD64")
        typehoon = proj.analyses.Typehoon(type_constraints, func_f)

        sol = typehoon.solution[t0]
        assert isinstance(sol, Pointer64)
        assert isinstance(sol.basetype, Struct)
        assert len(sol.basetype.fields) == 2
        assert 0 in sol.basetype.fields
        assert 8 in sol.basetype.fields
        assert isinstance(sol.basetype.fields[0], Pointer64)
        assert sol.basetype.fields[0].basetype == sol.basetype
        assert isinstance(sol.basetype.fields[8], Pointer64)
        assert sol.basetype.fields[8].basetype == sol.basetype


class TestTypeTranslator(unittest.TestCase):
    def test_tc2simtype(self):
        tx = TypeTranslator()
        tc = Float32()
        (st, _) = tx.tc2simtype(tc)
        assert isinstance(st, SimTypeFloat)

    def test_simtype2tc(self):
        tx = TypeTranslator()
        st = SimTypeFloat()
        tc = tx.simtype2tc(st)
        assert isinstance(tc, Float32)


if __name__ == "__main__":
    unittest.main()
