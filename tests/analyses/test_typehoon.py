#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest

import angr
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
from angr.analyses.typehoon.typeconsts import Int32

from ..common import bin_location


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

        _ = p.analyses.Typehoon(tcons)
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
        proj = angr.Project(os.path.join(test_location, "x86_64", "windows", "sioctl.sys"), auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        main_func = cfg.kb.functions[0x140006000]
        proj.analyses.VariableRecoveryFast(main_func)
        proj.analyses.CompleteCallingConventions()

        dec = proj.analyses.Decompiler(main_func)
        print(dec.codegen.text)

    def test_type_inference_basic_case_0(self):
        func_f = TypeVariable(name="F")
        v0 = TypeVariable(name="v0")
        type_constraints = {func_f: {Subtype(v0, Int32())}}
        proj = angr.load_shellcode(b"\x90\x90", "AMD64")
        typehoon = proj.analyses.Typehoon(type_constraints)

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
            # func_close: set(),
        }
        proj = angr.load_shellcode(b"\x90\x90", "AMD64")
        typehoon = proj.analyses.Typehoon(type_constraints)

        print(typehoon.simtypes_solution)
        print(typehoon.structs)


if __name__ == "__main__":
    # unittest.main()
    TestTypehoon().test_type_inference_basic_case_1()
