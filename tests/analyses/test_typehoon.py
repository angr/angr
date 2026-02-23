#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest
from collections import OrderedDict

import archinfo

import angr
from angr.sim_type import SimTypeFloat, SimTypePointer, SimStruct, SimTypeInt, SimTypeBottom
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

from tests.common import bin_location, print_decompilation_result

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
        assert dec.codegen is not None and dec.codegen.text is not None
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
        assert dec.codegen is not None and dec.codegen.text is not None
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

    def test_solving_cascading_type_constraints(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "decompiler", "tiny_aes_test.elf"), auto_load_libs=False)
        cfg = p.analyses.CFG(data_references=True, normalize=True)

        func = cfg.kb.functions["Cipher"]
        p.analyses.CompleteCallingConventions()
        dec = p.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None
        print(dec.codegen.text)

        # no masking should exist in the decompilation; all redundant variable type casts are removed
        assert "& 0x" not in dec.codegen.text

        assert dec.clinic is not None and dec.clinic.typehoon is not None
        assert 0 < max(dec.clinic.typehoon.eqclass_constraints_count) < 350

    def test_equivalence_class_computation_budgit_cgc_insert(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "decompiler", "BudgIT"), auto_load_libs=False)
        cfg = p.analyses.CFG(data_references=True, normalize=True)
        p.analyses.CompleteCallingConventions()
        func = cfg.kb.functions[0x403140]
        dec = p.analyses.Decompiler(func, cfg=cfg.model)
        assert (
            dec.codegen is not None
            and dec.codegen.text is not None
            and dec.clinic is not None
            and dec.clinic.typehoon is not None
        )

        # it has exactly one struct class that looks like the following:
        # struct struct_0 {
        #     struct struct_0 *field_0;
        #     struct struct_0 *field_8;
        # };
        sols = dec.clinic.typehoon.simtypes_solution
        tvs = [
            tv
            for tv in sols
            if not isinstance(tv, DerivedTypeVariable) and tv.name is None and isinstance(sols[tv], SimTypePointer)
        ]
        assert len(tvs) == 3
        assert sols[tvs[1]] == sols[tvs[2]]
        sol = sols[tvs[1]]
        assert isinstance(sol, SimTypePointer)
        assert isinstance(sol.pts_to, SimStruct)
        assert len(sol.pts_to.fields) == 2
        assert "field_0" in sol.pts_to.fields and "field_8" in sol.pts_to.fields
        field_0 = sol.pts_to.fields["field_0"]
        assert isinstance(field_0, SimTypePointer)
        assert isinstance(field_0.pts_to, SimStruct)
        assert field_0.pts_to == sol.pts_to
        field_8 = sol.pts_to.fields["field_8"]
        assert isinstance(field_8, SimTypePointer)
        assert isinstance(field_8.pts_to, SimStruct)
        assert field_8.pts_to == sol.pts_to

    def test_equivalence_class_computation_budgit_cgc_remove(self):
        p = angr.Project(os.path.join(test_location, "x86_64", "decompiler", "BudgIT"), auto_load_libs=False)
        cfg = p.analyses.CFG(data_references=True, normalize=True)
        p.analyses.CompleteCallingConventions()
        func = cfg.kb.functions[0x4030F0]
        dec = p.analyses.Decompiler(func, cfg=cfg.model)
        assert (
            dec.codegen is not None
            and dec.codegen.text is not None
            and dec.clinic is not None
            and dec.clinic.typehoon is not None
        )
        print_decompilation_result(dec)
        assert "->field_0 = NULL;\n" in dec.codegen.text
        assert "->field_8 = NULL;\n" in dec.codegen.text

        # it has five struct classes (I would love to have one, but we don't have enough information to force that):
        #
        # typedef struct struct_2 {
        #     struct struct_0 *field_0;
        #     struct struct_1 *field_8;
        # } struct_2;
        #
        # typedef struct struct_3 {
        #     char padding_0[8];
        #     struct struct_4 *field_8;
        # } struct_3;
        #
        # typedef struct struct_0 {
        #     char padding_0[8];
        #     struct struct_1 *field_8;
        # } struct_0;
        #
        # typedef struct struct_1 {
        #     struct struct_0 *field_0;
        # } struct_1;
        #
        # typedef struct struct_4 {
        #     struct struct_3 *field_0;
        # } struct_4;
        sols = dec.clinic.typehoon.simtypes_solution
        tvs = sorted(
            [
                tv
                for tv in sols
                if not isinstance(tv, DerivedTypeVariable) and tv.name is None and isinstance(sols[tv], SimTypePointer)
            ],
            key=lambda x: x.idx,
        )
        assert len(tvs) == 4  # the last two tvs are for the NULL pointers
        sol = sols[tvs[1]]
        assert isinstance(sol, SimTypePointer)
        assert isinstance(sol.pts_to, SimStruct)
        assert len(sol.pts_to.fields) == 2
        assert "field_0" in sol.pts_to.fields and "field_8" in sol.pts_to.fields
        field_0 = sol.pts_to.fields["field_0"]
        assert isinstance(field_0, SimTypePointer)
        assert isinstance(field_0.pts_to, SimStruct)
        assert len(field_0.pts_to.fields) == 2
        assert "field_8" in field_0.pts_to.fields
        field_0_field_8 = field_0.pts_to.fields["field_8"]
        assert isinstance(field_0_field_8, SimTypePointer)
        assert isinstance(field_0_field_8.pts_to, SimStruct)
        field_8 = sol.pts_to.fields["field_8"]
        assert isinstance(field_8, SimTypePointer)
        assert isinstance(field_8.pts_to, SimStruct)
        assert len(field_8.pts_to.fields) == 1
        assert "field_0" in field_8.pts_to.fields
        field_8_field_0 = field_8.pts_to.fields["field_0"]
        assert isinstance(field_8_field_0, SimTypePointer)
        assert isinstance(field_8_field_0.pts_to, SimStruct)
        assert field_0.pts_to == field_8_field_0.pts_to
        assert field_8.pts_to == field_0_field_8.pts_to

    def test_global_variable_type(self):
        bin_path = os.path.join(test_location, "x86_64", "g_game.o")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(data_references=True, normalize=True)
        proj.analyses.CompleteCallingConventions()

        # Test bodyqueslot from G_CheckSpot
        func = cfg.kb.functions["G_CheckSpot"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        bodyqueslot_addr = proj.loader.find_symbol("bodyqueslot").rebased_addr
        cexterns = {cvar.variable.addr: cvar.variable_type for cvar in dec.codegen.cexterns}
        assert isinstance(cexterns[bodyqueslot_addr], SimTypeInt)

        # Test displayplayer from G_Responder
        func = cfg.kb.functions["G_Responder"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        displayplayer_addr = proj.loader.find_symbol("displayplayer").rebased_addr
        cexterns = {cvar.variable.addr: cvar.variable_type for cvar in dec.codegen.cexterns}
        assert isinstance(cexterns[displayplayer_addr], SimTypeInt)

        # Test joyxmove, mousex, and gametic from G_DoLoadLevel
        func = cfg.kb.functions["G_DoLoadLevel"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        joyxmove_addr = proj.loader.find_symbol("joyxmove").rebased_addr
        mousex_addr = proj.loader.find_symbol("mousex").rebased_addr
        gametic_addr = proj.loader.find_symbol("gametic").rebased_addr
        cexterns = {cvar.variable.addr: cvar.variable_type for cvar in dec.codegen.cexterns}
        assert isinstance(cexterns[joyxmove_addr], SimTypeInt)
        assert isinstance(cexterns[mousex_addr], SimTypeInt)
        assert isinstance(cexterns[gametic_addr], SimTypeInt)

    def test_type_inference_with_custom_label(self):
        bin_path = os.path.join(test_location, "x86_64", "windows", "ipnathlp.dll")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(fail_fast=True, normalize=True)

        func = cfg.functions[0x18003CA70]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert (
            dec.codegen is not None
            and dec.codegen.text is not None
            and dec.clinic is not None
            and dec.clinic.typehoon is not None
        )
        # print(dec.codegen.text)
        sols = dec.clinic.typehoon.simtypes_solution
        all_sols = {v.label for v in sols.values()}
        assert "HKEY" in all_sols
        assert "PWSTR" in all_sols
        assert "HANDLE" in all_sols


class TestTypeTranslator(unittest.TestCase):
    def test_tc2simtype(self):
        tx = TypeTranslator(archinfo.arch_from_id("x86"))
        tc = Float32()
        st, _ = tx.tc2simtype(tc)
        assert isinstance(st, SimTypeFloat)

    def test_simtype2tc(self):
        tx = TypeTranslator(archinfo.arch_from_id("x86"))
        st = SimTypeFloat()
        tc = tx.simtype2tc(st)
        assert isinstance(tc, Float32)

    def test_lift_recursive_struct(self):
        arch = archinfo.arch_from_id("amd64")
        fields = OrderedDict({"ptr": SimTypePointer(SimTypeBottom())})
        st = SimStruct(fields, name="test_struct")
        assert isinstance(st.fields["ptr"], SimTypePointer)
        st.fields["ptr"].pts_to = st
        st = st.with_arch(arch)
        tx = TypeTranslator(arch)
        tc = tx.simtype2tc(st)
        assert isinstance(tc, Struct)
        assert 0 in tc.fields
        assert isinstance(tc.fields[0], Pointer64)
        assert 0 in tc.field_names
        assert tc.field_names[0] == "ptr"


if __name__ == "__main__":
    unittest.main()
