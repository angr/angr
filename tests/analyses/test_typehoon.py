#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import re
import unittest
from collections import OrderedDict

import archinfo

import angr
from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.typehoon.simple_solver import SimpleSolver
from angr.analyses.typehoon.translator import TypeTranslator
from angr.analyses.typehoon.typeconsts import Float32, Float64, Int32, Pointer64, Struct
from angr.analyses.typehoon.typevars import (
    DerivedTypeVariable,
    FuncIn,
    FuncOut,
    HasField,
    Load,
    Store,
    Subtype,
    TypeVariable,
)
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import (
    SimStruct,
    SimTypeArray,
    SimTypeBottom,
    SimTypeChar,
    SimTypeFloat,
    SimTypeFunction,
    SimTypeInt,
    SimTypePointer,
    TypeRef,
)
from angr.sim_variable import SimStackVariable
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
        assert "->field_8 = 0x30303030;" in dec.codegen.text
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
        print_decompilation_result(dec)
        assert dec.codegen.text.count("UNICODE_STRING v") == 2

    def test_type_inference_auto_update_and_back_propagation(self):
        bin_path = os.path.join(test_location, "x86_64", "bomb")
        proj = angr.Project(bin_path)
        cfg = proj.analyses.CFG(normalize=True)

        func_phase2 = cfg.kb.functions["phase_2"]
        assert func_phase2.prototype_source == PrototypeSource.NONE

        proj.analyses.CompleteCallingConventions()

        # let's decompile phase_2 first
        func_phase2 = cfg.kb.functions["phase_2"]
        print(func_phase2.prototype)
        print(func_phase2.prototype_source)
        assert func_phase2.prototype_source == PrototypeSource.CCA_LOW
        func_read6numbers = cfg.kb.functions["read_six_numbers"]
        assert func_read6numbers.prototype_source == PrototypeSource.CCA_LOW
        dec_phase2 = proj.analyses.Decompiler(
            func_phase2, fail_fast=True, options=[("constrain_callee_prototypes", True)]
        )
        print_decompilation_result(dec_phase2)
        assert dec_phase2.codegen is not None and dec_phase2.codegen.text is not None
        assert func_phase2.prototype_source == PrototypeSource.CCA_DECOMPILER

        # (char*, char*) -> ?
        assert func_read6numbers.prototype_source == PrototypeSource.CALLSITE_DECOMPILER
        assert isinstance(func_read6numbers.prototype, SimTypeFunction)
        assert len(func_read6numbers.prototype.args) == 2
        print(func_read6numbers.prototype)
        assert isinstance(func_read6numbers.prototype.args[0], SimTypePointer) and isinstance(
            func_read6numbers.prototype.args[0].pts_to, SimTypeChar
        )
        assert isinstance(func_read6numbers.prototype.args[1], SimTypePointer) and isinstance(
            func_read6numbers.prototype.args[1].pts_to, SimTypeChar
        )

        # decompile read_six_numbers, and its prototype should be updated to (char*, uint32_t*)
        dec_read6numbers = proj.analyses.Decompiler(
            func_read6numbers, fail_fast=True, options=[("constrain_callee_prototypes", True)]
        )
        assert dec_read6numbers.codegen is not None and dec_read6numbers.codegen.text is not None
        print_decompilation_result(dec_read6numbers)
        assert func_read6numbers.prototype_source == PrototypeSource.CCA_DECOMPILER
        assert isinstance(func_read6numbers.prototype, SimTypeFunction)
        assert len(func_read6numbers.prototype.args) == 2
        assert isinstance(func_read6numbers.prototype.args[0], SimTypePointer) and isinstance(
            func_read6numbers.prototype.args[0].pts_to, SimTypeChar
        )
        assert (
            isinstance(func_read6numbers.prototype.args[1], SimTypePointer)
            and isinstance(func_read6numbers.prototype.args[1].pts_to, SimTypeInt)
            and func_read6numbers.prototype.args[1].pts_to.signed is True
        )

        # decompile phase_2 again, and we should see an unsigned int [6] on the stack
        dec_phase2 = proj.analyses.Decompiler(
            func_phase2, fail_fast=True, options=[("constrain_callee_prototypes", True)]
        )
        assert dec_phase2.codegen is not None and dec_phase2.codegen.text is not None
        print_decompilation_result(dec_phase2)
        assert re.search(r"  int v\d+\[6];", dec_phase2.codegen.text) is not None

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

    def _decompile_function_scoped(self, proj, func_addr: int, func_size: int):
        # scope the CFG to the target function so tests on large (static) binaries stay fast
        cfg = proj.analyses.CFGFast(
            regions=[(func_addr, func_addr + func_size + 0x80)],
            function_starts=[func_addr],
            normalize=True,
        )
        proj.analyses.CompleteCallingConventions(cfg=cfg, kb=cfg.kb, recover_variables=True)
        func = cfg.kb.functions.get_by_addr(func_addr)
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, kb=cfg.kb)
        assert dec.codegen is not None and dec.codegen.text is not None
        return dec

    def _assert_extern_is_function_pointer(self, proj, func_symbol: str, global_symbol: str) -> SimTypePointer:
        func_sym = proj.loader.find_symbol(func_symbol)
        global_sym = proj.loader.find_symbol(global_symbol)
        assert func_sym is not None and global_sym is not None
        dec = self._decompile_function_scoped(proj, func_sym.rebased_addr, func_sym.size or 0x1000)
        cexterns = {cvar.variable.addr: cvar.variable_type for cvar in dec.codegen.cexterns}
        ext_ty = cexterns.get(global_sym.rebased_addr)
        assert isinstance(ext_ty, SimTypePointer), (
            f"{global_symbol} in {func_symbol}: expected a function pointer, got {ext_ty!r}"
        )
        assert isinstance(ext_ty.pts_to, SimTypeFunction), (
            f"{global_symbol} in {func_symbol}: expected a function pointer, got {ext_ty!r}"
        )
        return ext_ty

    def test_fnptr_global_guarded_call(self):
        # a global holding a function pointer that is null-checked before the indirect call
        # (`if (g) g();`). the whole-cell load from the null check must not stop the solver
        # from typing the global as a function pointer.
        bin_path = os.path.join(test_location, "x86_64", "elf_with_static_libc_ubuntu_2004")
        proj = angr.Project(bin_path, auto_load_libs=False)
        self._assert_extern_is_function_pointer(proj, "_dl_scope_free", "_dl_wait_lookup_done")
        self._assert_extern_is_function_pointer(proj, "add_to_global_resize", "_dl_wait_lookup_done")

    def test_fnptr_global_guarded_call_large_function(self):
        # same guarded pattern, but inside a large function with a complex CFG
        bin_path = os.path.join(test_location, "x86_64", "elf_with_static_libc_ubuntu_2004")
        proj = angr.Project(bin_path, auto_load_libs=False)
        self._assert_extern_is_function_pointer(proj, "_dl_close_worker.part.0", "_dl_wait_lookup_done")

    def test_fnptr_global_guarded_call_static_binary(self):
        bin_path = os.path.join(test_location, "x86_64", "static")
        proj = angr.Project(bin_path, auto_load_libs=False)
        self._assert_extern_is_function_pointer(proj, "_dl_scope_free", "_dl_wait_lookup_done")

    def test_fnptr_global_with_used_return_value(self):
        # the result of the indirect call is used, so the recovered function type must carry
        # a non-void return type (`ptr = (*_dl_error_catch_tsd)();`)
        bin_path = os.path.join(test_location, "x86_64", "static")
        proj = angr.Project(bin_path, auto_load_libs=False)
        ext_ty = self._assert_extern_is_function_pointer(proj, "_dl_signal_error", "_dl_error_catch_tsd")
        returnty = ext_ty.pts_to.returnty
        assert returnty is not None and not isinstance(returnty, SimTypeBottom)

    def test_fnptr_global_unused_return_is_void(self):
        # binutils/elfedit update_elf_header: `byte_put(&g, output_elf_machine, 2)` -- a global
        # function pointer called with arguments whose return value is discarded. With arguments
        # supplying the FuncIn evidence, the unused result drops the FuncOut edge, so the recovered
        # function type has no output slot and renders as returning void.
        bin_path = os.path.join(test_location, "x86_64", "elfedit_gcc17_O0")
        proj = angr.Project(bin_path, auto_load_libs=False)
        ext_ty = self._assert_extern_is_function_pointer(proj, "update_elf_header", "byte_put")
        assert ext_ty.pts_to.args  # called with arguments
        assert isinstance(ext_ty.pts_to.returnty, SimTypeBottom)  # result discarded -> void

    def test_fnptr_global_with_used_return_value_static_global(self):
        # binutils/elfedit byte_get_signed: `v = byte_get(...)` -- the indirect call's result is
        # used, so the recovered function type must carry a concrete (non-void) return type.
        bin_path = os.path.join(test_location, "x86_64", "elfedit_gcc17_O0")
        proj = angr.Project(bin_path, auto_load_libs=False)
        ext_ty = self._assert_extern_is_function_pointer(proj, "byte_get_signed", "byte_get")
        returnty = ext_ty.pts_to.returnty
        assert returnty is not None and not isinstance(returnty, SimTypeBottom)

    def test_fnptr_global_argumentless_guarded_call(self):
        # binutils/elfedit xexit: `if (_xexit_cleanup) _xexit_cleanup();` -- an argument-less
        # guarded global call. With no arguments the FuncOut edge is the sole evidence that the
        # cell holds a function pointer, so it is kept and the cell still types as a fnptr.
        bin_path = os.path.join(test_location, "x86_64", "elfedit_gcc17_O0")
        proj = angr.Project(bin_path, auto_load_libs=False)
        ext_ty = self._assert_extern_is_function_pointer(proj, "xexit", "_xexit_cleanup")
        assert not ext_ty.pts_to.args  # argument-less call

    def test_fnptr_parameter_recovered_iterator(self):
        # coreutils/sort hash_do_for_each: the second parameter is a callback called indirectly
        # (`a1(iter->field_0, ...)`), so it must be recovered as a function-pointer parameter
        # (verified at args[1]).
        bin_path = os.path.join(test_location, "x86_64", "sort_gcc17_O0")
        proj = angr.Project(bin_path, auto_load_libs=False)
        func_sym = proj.loader.find_symbol("hash_do_for_each")
        dec = self._decompile_function_scoped(proj, func_sym.rebased_addr, func_sym.size or 0x1000)
        proto = dec.clinic.function.prototype
        fnptr_args = [
            arg for arg in proto.args if isinstance(arg, SimTypePointer) and isinstance(arg.pts_to, SimTypeFunction)
        ]
        assert fnptr_args, f"expected a function-pointer parameter, got {proto}"

    def test_fnptr_parameter_recovered_comparator(self):
        # coreutils/sort heapify_down: the comparator parameter is called indirectly
        # (`a3(...) < 0`), so it must be recovered as a function-pointer parameter (verified at
        # args[3]).
        bin_path = os.path.join(test_location, "x86_64", "sort_gcc17_O0")
        proj = angr.Project(bin_path, auto_load_libs=False)
        func_sym = proj.loader.find_symbol("heapify_down")
        dec = self._decompile_function_scoped(proj, func_sym.rebased_addr, func_sym.size or 0x1000)
        proto = dec.clinic.function.prototype
        fnptr_args = [
            arg for arg in proto.args if isinstance(arg, SimTypePointer) and isinstance(arg.pts_to, SimTypeFunction)
        ]
        assert fnptr_args, f"expected a function-pointer parameter, got {proto}"

    def test_fnptr_struct_field_call_stays_struct(self):
        # coreutils/sort hash_lookup: a function pointer stored in a field of the first parameter
        # is called (`a0->field_38(...)`); the parameter itself must remain a struct pointer, not
        # collapse to a function pointer.
        bin_path = os.path.join(test_location, "x86_64", "sort_gcc17_O0")
        proj = angr.Project(bin_path, auto_load_libs=False)
        func_sym = proj.loader.find_symbol("hash_lookup")
        dec = self._decompile_function_scoped(proj, func_sym.rebased_addr, func_sym.size or 0x1000)
        arg0 = dec.clinic.function.prototype.args[0]
        assert isinstance(arg0, SimTypePointer)
        struct_ty = arg0.pts_to.type if isinstance(arg0.pts_to, TypeRef) else arg0.pts_to
        assert isinstance(struct_ty, SimStruct)
        assert not isinstance(arg0.pts_to, SimTypeFunction)

    # -- optimized (-O2) counterparts --------------------------------------------------
    # The same function-pointer typing must hold at -O2, where inlining and optimized
    # register setup change the surrounding code. Not every category survives -O2 (e.g. a
    # global fnptr call no longer keeps its recovered argument list), but global void/used
    # returns, parameter callbacks, and struct-field dispatch all still recover correctly.

    def test_fnptr_global_argumentless_guarded_call_o2(self):
        # binutils/elfedit -O2 xexit: `if (_xexit_cleanup) _xexit_cleanup();` still types the
        # argument-less guarded global as a function pointer.
        bin_path = os.path.join(test_location, "x86_64", "elfedit_gcc17_O2")
        proj = angr.Project(bin_path, auto_load_libs=False)
        ext_ty = self._assert_extern_is_function_pointer(proj, "xexit", "_xexit_cleanup")
        assert not ext_ty.pts_to.args

    def test_fnptr_global_with_used_return_value_o2(self):
        # binutils/elfedit -O2 byte_get_signed: `v = byte_get()` -- return value used, so the
        # recovered function type carries a concrete (non-void) return type.
        bin_path = os.path.join(test_location, "x86_64", "elfedit_gcc17_O2")
        proj = angr.Project(bin_path, auto_load_libs=False)
        ext_ty = self._assert_extern_is_function_pointer(proj, "byte_get_signed", "byte_get")
        returnty = ext_ty.pts_to.returnty
        assert returnty is not None and not isinstance(returnty, SimTypeBottom)

    def test_fnptr_parameter_recovered_iterator_o2(self):
        # coreutils/sort -O2 hash_do_for_each: the callback parameter called indirectly is still
        # recovered as a function-pointer parameter (verified at args[1]).
        bin_path = os.path.join(test_location, "x86_64", "sort_gcc17_O2")
        proj = angr.Project(bin_path, auto_load_libs=False)
        func_sym = proj.loader.find_symbol("hash_do_for_each")
        dec = self._decompile_function_scoped(proj, func_sym.rebased_addr, func_sym.size or 0x1000)
        proto = dec.clinic.function.prototype
        fnptr_args = [
            arg for arg in proto.args if isinstance(arg, SimTypePointer) and isinstance(arg.pts_to, SimTypeFunction)
        ]
        assert fnptr_args, f"expected a function-pointer parameter, got {proto}"

    def test_fnptr_parameter_recovered_multiarg_o2(self):
        # coreutils/sort -O2 __xargmatch_internal: a callback parameter invoked with several
        # arguments (`a5(v8, ..., v13)`) is recovered as a function-pointer parameter (args[5]).
        bin_path = os.path.join(test_location, "x86_64", "sort_gcc17_O2")
        proj = angr.Project(bin_path, auto_load_libs=False)
        func_sym = proj.loader.find_symbol("__xargmatch_internal")
        dec = self._decompile_function_scoped(proj, func_sym.rebased_addr, func_sym.size or 0x1000)
        proto = dec.clinic.function.prototype
        fnptr_args = [
            arg for arg in proto.args if isinstance(arg, SimTypePointer) and isinstance(arg.pts_to, SimTypeFunction)
        ]
        assert fnptr_args, f"expected a function-pointer parameter, got {proto}"

    def test_fnptr_struct_field_call_stays_struct_o2(self):
        # coreutils/sort -O2 hash_lookup: a called function-pointer struct field must leave the
        # enclosing parameter a struct pointer, not collapse it to a function pointer.
        bin_path = os.path.join(test_location, "x86_64", "sort_gcc17_O2")
        proj = angr.Project(bin_path, auto_load_libs=False)
        func_sym = proj.loader.find_symbol("hash_lookup")
        dec = self._decompile_function_scoped(proj, func_sym.rebased_addr, func_sym.size or 0x1000)
        arg0 = dec.clinic.function.prototype.args[0]
        assert isinstance(arg0, SimTypePointer)
        struct_ty = arg0.pts_to.type if isinstance(arg0.pts_to, TypeRef) else arg0.pts_to
        assert isinstance(struct_ty, SimStruct)
        assert not isinstance(arg0.pts_to, SimTypeFunction)

    # -- additional coverage: local, positive struct-field, and negative/boundary cases --

    @staticmethod
    def _is_fnptr(ty) -> bool:
        return isinstance(ty, SimTypePointer) and isinstance(ty.pts_to, SimTypeFunction)

    def test_fnptr_local_variable_recovered(self):
        # file uncompressbuf: a function pointer held in a STACK LOCAL (not a parameter, not a
        # global) and called indirectly must be recovered as a function-pointer local.
        bin_path = os.path.join(test_location, "x86_64", "file_gcc17_O0")
        proj = angr.Project(bin_path, auto_load_libs=False)
        func_sym = proj.loader.find_symbol("uncompressbuf")
        assert func_sym is not None
        dec = self._decompile_function_scoped(proj, func_sym.rebased_addr, func_sym.size or 0x1000)
        vm = dec.clinic.variable_kb.variables[func_sym.rebased_addr]
        fnptr_stack_locals = [
            v for v in vm.get_variables() if isinstance(v, SimStackVariable) and self._is_fnptr(vm.get_variable_type(v))
        ]
        assert fnptr_stack_locals, "expected at least one stack-local function pointer"
        # and it is genuinely a local: no parameter carries a function-pointer type
        proto = dec.clinic.function.prototype
        assert not any(self._is_fnptr(arg) for arg in proto.args), (
            f"expected no function-pointer parameters, got {proto}"
        )

    def test_fnptr_struct_field_typed_as_function_pointer(self):
        # coreutils/sort hash_lookup: positive complement of the stays-struct test -- the struct
        # FIELD holding the called function pointer must itself be typed as a function pointer.
        bin_path = os.path.join(test_location, "x86_64", "sort_gcc17_O0")
        proj = angr.Project(bin_path, auto_load_libs=False)
        func_sym = proj.loader.find_symbol("hash_lookup")
        assert func_sym is not None
        dec = self._decompile_function_scoped(proj, func_sym.rebased_addr, func_sym.size or 0x1000)
        arg0 = dec.clinic.function.prototype.args[0]
        assert isinstance(arg0, SimTypePointer)
        struct_ty = arg0.pts_to.type if isinstance(arg0.pts_to, TypeRef) else arg0.pts_to
        assert isinstance(struct_ty, SimStruct)
        fnptr_fields = [f for f in struct_ty.fields.values() if self._is_fnptr(f)]
        assert fnptr_fields, f"expected a function-pointer field, got {struct_ty.fields}"

    def test_fnptr_devirtualized_global_stays_int(self):
        # libtiff/tiffinfo TIFFError: even though _TIFFerrorHandler is indirectly called here,
        # angr resolves (devirtualizes) the target to a direct call, so the cell itself carries
        # no indirect-call evidence and must NOT be promoted to a function pointer -- this pins
        # the devirtualization boundary of the fix.
        bin_path = os.path.join(test_location, "x86_64", "tiffinfo_gcc17_O0")
        proj = angr.Project(bin_path, auto_load_libs=False)
        func_sym = proj.loader.find_symbol("TIFFError")
        global_sym = proj.loader.find_symbol("_TIFFerrorHandler")
        assert func_sym is not None and global_sym is not None
        dec = self._decompile_function_scoped(proj, func_sym.rebased_addr, func_sym.size or 0x1000)
        cexterns = {cv.variable.addr: cv.variable_type for cv in dec.codegen.cexterns}
        ext_ty = cexterns.get(global_sym.rebased_addr)
        assert ext_ty is not None
        assert not self._is_fnptr(ext_ty), f"expected an integer, got {ext_ty!r}"

    def test_fnptr_uncalled_global_stays_int(self):
        # libtiff/tiffinfo TIFFSetErrorHandler: `old = _TIFFerrorHandler; _TIFFerrorHandler = arg;
        # return old;` -- the fnptr-valued global is only loaded and stored, never called
        # indirectly, so with no call evidence the cell must stay an integer.
        bin_path = os.path.join(test_location, "x86_64", "tiffinfo_gcc17_O0")
        proj = angr.Project(bin_path, auto_load_libs=False)
        func_sym = proj.loader.find_symbol("TIFFSetErrorHandler")
        global_sym = proj.loader.find_symbol("_TIFFerrorHandler")
        assert func_sym is not None and global_sym is not None
        dec = self._decompile_function_scoped(proj, func_sym.rebased_addr, func_sym.size or 0x1000)
        cexterns = {cv.variable.addr: cv.variable_type for cv in dec.codegen.cexterns}
        ext_ty = cexterns.get(global_sym.rebased_addr)
        assert ext_ty is not None
        assert not self._is_fnptr(ext_ty), f"expected an integer, got {ext_ty!r}"

    def test_fnptr_global_guarded_hook_call(self):
        # glibc's __after_morecore_hook: `if (__after_morecore_hook) (*__after_morecore_hook)();`
        # exercised from two different functions, one of them a gcc isra clone
        bin_path = os.path.join(test_location, "x86_64", "static")
        proj = angr.Project(bin_path, auto_load_libs=False)
        self._assert_extern_is_function_pointer(proj, "top_check", "__after_morecore_hook")
        self._assert_extern_is_function_pointer(proj, "systrim.isra.1", "__after_morecore_hook")

    def test_fnptr_parameter_recovered(self):
        # a function pointer passed as a parameter and called indirectly must be recovered as a
        # function-pointer parameter (glibc _dl_catch_error's `operate` callback)
        bin_path = os.path.join(test_location, "x86_64", "static")
        proj = angr.Project(bin_path, auto_load_libs=False)
        func_sym = proj.loader.find_symbol("_dl_catch_error")
        dec = self._decompile_function_scoped(proj, func_sym.rebased_addr, func_sym.size or 0x1000)
        proto = dec.clinic.function.prototype
        fnptr_args = [
            arg for arg in proto.args if isinstance(arg, SimTypePointer) and isinstance(arg.pts_to, SimTypeFunction)
        ]
        assert fnptr_args, f"expected a function-pointer parameter, got {proto}"

    def test_fnptr_global_guarded_call_with_arguments(self):
        # guarded indirect call through a memory operand (`call *g(%rip)`) with arguments
        bin_path = os.path.join(test_location, "x86_64", "ALLSTAR_389-dsgw_csearch")
        proj = angr.Project(bin_path, auto_load_libs=False)
        self._assert_extern_is_function_pointer(proj, "et_cmp", "et_cmp_fn")

    def test_fnptr_struct_param_field0_call_keeps_indirection(self):
        # a struct-pointer PARAMETER whose function-pointer field at offset 0 is called
        # (`p->f(x)`) with no other access through the pointer. the parameter holds a pointer
        # VALUE, not a constant global cell, so the global-cell base-typevar redirect must not
        # apply: the parameter keeps both levels of indirection (a pointer to the cell that
        # holds the function pointer) instead of collapsing into the function pointer itself,
        # which would render the non-compilable `(*(long long *)a0)(a1)`.
        bin_path = os.path.join(test_location, "x86_64", "fnptr_struct_param_gcc17_O0")
        proj = angr.Project(bin_path, auto_load_libs=False)
        func_sym = proj.loader.find_symbol("case_field0")
        assert func_sym is not None
        dec = self._decompile_function_scoped(proj, func_sym.rebased_addr, func_sym.size or 0x1000)
        arg0 = dec.clinic.function.prototype.args[0]
        assert isinstance(arg0, SimTypePointer)
        pointee = arg0.pts_to.type if isinstance(arg0.pts_to, TypeRef) else arg0.pts_to
        assert not isinstance(pointee, SimTypeFunction), f"parameter lost an indirection level: {arg0!r}"
        is_fnptr_cell = isinstance(pointee, SimTypePointer) and isinstance(pointee.pts_to, SimTypeFunction)
        is_struct_with_fnptr_field = isinstance(pointee, SimStruct) and any(
            isinstance(f, SimTypePointer) and isinstance(f.pts_to, SimTypeFunction) for f in pointee.fields.values()
        )
        assert is_fnptr_cell or is_struct_with_fnptr_field, (
            f"expected a pointer to a function-pointer cell, got {arg0!r}"
        )

    def test_fnptr_struct_param_called_field_survives(self):
        # a multi-field struct-pointer parameter: another field is also accessed, so the
        # solver keeps the parameter a struct pointer -- and the CALLED field at offset 0
        # must still be typed as a function pointer instead of vanishing into padding
        # (`idx->padding_0(a1)`), which happens when the load-access marker of the call
        # target is discarded even though the base is a pointer value and not a global cell.
        bin_path = os.path.join(test_location, "x86_64", "fnptr_struct_param_gcc17_O0")
        proj = angr.Project(bin_path, auto_load_libs=False)
        func_sym = proj.loader.find_symbol("case_multifield")
        assert func_sym is not None
        dec = self._decompile_function_scoped(proj, func_sym.rebased_addr, func_sym.size or 0x1000)
        arg0 = dec.clinic.function.prototype.args[0]
        assert isinstance(arg0, SimTypePointer)
        struct_ty = arg0.pts_to.type if isinstance(arg0.pts_to, TypeRef) else arg0.pts_to
        assert isinstance(struct_ty, SimStruct), f"expected a struct pointer, got {arg0!r}"
        fnptr_fields = [
            f
            for f in struct_ty.fields.values()
            if isinstance(f, SimTypePointer) and isinstance(f.pts_to, SimTypeFunction)
        ]
        assert fnptr_fields, f"called function-pointer field vanished: {struct_ty.fields}"

    def test_struct_pointer_with_called_field_stays_struct(self):
        # negative case: a pointer to a structure with several accessed fields must remain a
        # struct pointer even when one of its fields holds a called function pointer; the
        # whole-cell-access exemption only applies when nothing but the cell itself is accessed.
        bin_path = os.path.join(test_location, "x86_64", "dir_gcc_-O0")
        proj = angr.Project(bin_path, auto_load_libs=False)
        func_sym = proj.loader.find_symbol("_obstack_begin_worker")
        dec = self._decompile_function_scoped(proj, func_sym.rebased_addr, func_sym.size or 0x1000)
        func = dec.clinic.function
        arg0 = func.prototype.args[0]
        assert isinstance(arg0, SimTypePointer)
        assert not isinstance(arg0.pts_to, SimTypeFunction)
        struct_ty = arg0.pts_to
        if isinstance(struct_ty, TypeRef):
            struct_ty = struct_ty.type
        assert isinstance(struct_ty, SimStruct)
        assert len(struct_ty.fields) >= 3

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

    def test_fn_inprogress_cleared_when_subtranslation_raises(self):
        # If translating a Function's param/return types raises, the Function must still be
        # removed from the _fn_inprogress cycle-guard set. Otherwise a later translation of a
        # structurally-equal Function is misdetected as a cycle and collapses to void.
        from angr.analyses.typehoon import translator as translator_module
        from angr.analyses.typehoon import typeconsts

        class PoisonTC(typeconsts.TypeConstant):
            def __repr__(self, memo=None):
                return "POISON"

        calls = []

        def poison_handler(translator_self, tc):
            calls.append(tc)
            if len(calls) == 1:
                raise ValueError("simulated sub-translation failure")
            return SimTypeInt(signed=True).with_arch(translator_self.arch)

        translator_module.TypeConstHandlers[PoisonTC] = poison_handler
        try:
            tx = TypeTranslator(archinfo.arch_from_id("amd64"))
            fn1 = typeconsts.Function([PoisonTC()], [Int32()])
            fn2 = typeconsts.Function([PoisonTC()], [Int32()])
            assert fn1 == fn2 and hash(fn1) == hash(fn2)

            with self.assertRaises(ValueError):
                tx.tc2simtype(fn1)

            st, _ = tx.tc2simtype(fn2)
            assert isinstance(st, SimTypeFunction), f"expected SimTypeFunction, got {st!r}"
        finally:
            del translator_module.TypeConstHandlers[PoisonTC]


class TestSimpleSolverLatticeOps(unittest.TestCase):
    """Tests for the SimType-level lattice operations SimpleSolver.join_simtypes / meet_simtypes."""

    arch = archinfo.arch_from_id("amd64")

    def test_join_signed_unsigned_int(self):
        # join(signed int, unsigned int) -> int (their common Int32 supertype)
        joined = SimpleSolver.join_simtypes(
            SimTypeInt(signed=True).with_arch(self.arch),
            SimTypeInt(signed=False).with_arch(self.arch),
            self.arch,
        )
        assert isinstance(joined, SimTypeInt)

    def test_join_same_pointer(self):
        # join(char *, char *) -> char *
        joined = SimpleSolver.join_simtypes(
            SimTypePointer(SimTypeChar()).with_arch(self.arch),
            SimTypePointer(SimTypeChar()).with_arch(self.arch),
            self.arch,
        )
        assert isinstance(joined, SimTypePointer)
        assert isinstance(joined.pts_to, SimTypeChar)

    def test_join_same_struct_pointer_preserves_struct(self):
        # join(struct A *, struct A *) -> struct A *
        s = SimStruct({"a": SimTypeInt()}, name="A").with_arch(self.arch)
        joined = SimpleSolver.join_simtypes(
            SimTypePointer(s).with_arch(self.arch),
            SimTypePointer(s).with_arch(self.arch),
            self.arch,
        )
        assert isinstance(joined, SimTypePointer)
        assert isinstance(joined.pts_to, SimStruct)
        assert joined.pts_to.name == "A"

    def test_join_distinct_struct_pointers_to_void(self):
        # join(struct A *, struct B *) -> void * (no common struct supertype)
        sa = SimStruct({"a": SimTypeInt()}, name="A").with_arch(self.arch)
        sb = SimStruct({"b": SimTypeInt()}, name="B").with_arch(self.arch)
        joined = SimpleSolver.join_simtypes(
            SimTypePointer(sa).with_arch(self.arch),
            SimTypePointer(sb).with_arch(self.arch),
            self.arch,
        )
        assert isinstance(joined, SimTypePointer)
        assert isinstance(joined.pts_to, SimTypeBottom)

    def test_join_incompatible_scalars_is_bottom(self):
        # join(char, int): the only common supertype is the generic Int, which has no precise SimType -> bottom
        joined = SimpleSolver.join_simtypes(
            SimTypeChar().with_arch(self.arch),
            SimTypeInt().with_arch(self.arch),
            self.arch,
        )
        assert isinstance(joined, SimTypeBottom)

    def test_meet_identical_type(self):
        # meet(char, char) -> char
        met = SimpleSolver.meet_simtypes(
            SimTypeChar(signed=True).with_arch(self.arch),
            SimTypeChar(signed=True).with_arch(self.arch),
            self.arch,
        )
        assert isinstance(met, SimTypeChar)

    def test_meet_incompatible_is_bottom(self):
        # meet(signed int, unsigned int): no common subtype on the lattice -> bottom
        met = SimpleSolver.meet_simtypes(
            SimTypeInt(signed=True).with_arch(self.arch),
            SimTypeInt(signed=False).with_arch(self.arch),
            self.arch,
        )
        assert isinstance(met, SimTypeBottom)


class TestFunctionArgTypeNormalization(unittest.TestCase):
    """Tests for Clinic._flatten_pointer_to_array, the call-site argument type normalization filter."""

    arch = archinfo.arch_from_id("amd64")

    def test_pointer_to_array_becomes_pointer(self):
        # type[N] * -> type *
        ty = SimTypePointer(SimTypeArray(SimTypeInt(), 4)).with_arch(self.arch)
        flattened = Clinic._flatten_pointer_to_array(ty)
        assert isinstance(flattened, SimTypePointer)
        assert isinstance(flattened.pts_to, SimTypeInt)

    def test_plain_pointer_unchanged(self):
        ty = SimTypePointer(SimTypeChar()).with_arch(self.arch)
        flattened = Clinic._flatten_pointer_to_array(ty)
        assert flattened is ty

    def test_non_pointer_unchanged(self):
        ty = SimTypeInt().with_arch(self.arch)
        flattened = Clinic._flatten_pointer_to_array(ty)
        assert flattened is ty

    def test_array_pointers_of_different_lengths_join_after_filter(self):
        # int[4] * and int[8] * normalize to int *, which then join to int *
        t1 = Clinic._flatten_pointer_to_array(SimTypePointer(SimTypeArray(SimTypeInt(), 4)).with_arch(self.arch))
        t2 = Clinic._flatten_pointer_to_array(SimTypePointer(SimTypeArray(SimTypeInt(), 8)).with_arch(self.arch))
        joined = SimpleSolver.join_simtypes(t1, t2, self.arch)
        assert isinstance(joined, SimTypePointer)
        assert isinstance(joined.pts_to, SimTypeInt)


if __name__ == "__main__":
    unittest.main()
