# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest
from collections import OrderedDict

import angr
from angr import default_cc
from angr.sim_type import (
    SimStruct,
    SimTypeArray,
    SimTypeChar,
    SimTypeFunction,
    SimTypeInt,
    SimTypeLongLong,
    SimTypePointer,
)
from tests.common import WORKER, bin_location, print_decompilation_result

test_location = os.path.join(bin_location, "tests")


class TestDecompilerTypes(unittest.TestCase):
    def test_mapping_int64_to_basic_type(self):
        proj = angr.Project(
            os.path.join(
                test_location, "x86_64", "windows", "7995a0325b446c462bdb6ae10b692eee2ecadd8e888e9d7729befe4412007afb"
            ),
            auto_load_libs=False,
        )
        cfg = proj.analyses.CFG(
            normalize=True,
            show_progressbar=True,
            regions=[(0x14004C100, 0x14004C100 + 0x1000)],
            start_at_entry=False,
        )

        func = proj.kb.functions[0x14004C100]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.codegen.text is not None

        # these prototypes are created when decompiling the function above (their caller)
        proto_0 = proj.kb.functions[0x1402004F8].prototype
        assert proto_0 is not None
        assert proto_0.args
        assert proto_0.args[0].size is not None and proto_0.args[0].size > 0
        proto_1 = proj.kb.functions[0x140200518].prototype
        assert proto_1 is not None
        assert proto_1.args
        assert proto_1.args[-1].size is not None and proto_1.args[-1].size > 0

    def test_guid_stackvar_assignment(self):
        bin_path = os.path.join(
            test_location, "x86_64", "windows", "03fb29dab8ab848f15852a37a1c04aa65289c0160d9200dceff64d890b3290dd"
        )
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)
        func = cfg.functions[0x132B0]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        # find the Guid variable
        guid_var = re.search(r"Guid (?P<var>v\d+);", dec.codegen.text)
        assert guid_var is not None
        guid_varname = guid_var.group("var")

        assert f"{guid_varname}.Data1 = " in dec.codegen.text
        assert f"{guid_varname}.Data2 = " in dec.codegen.text
        assert f"{guid_varname}.Data3 = " in dec.codegen.text
        for i in range(8):
            assert f"{guid_varname}.Data4[{i}] = " in dec.codegen.text

    def test_clinic_callee_type_rewrite_should_skip_plt_functions(self):
        bin_path = os.path.join(test_location, "x86_64", "1after909")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)
        proj.analyses.CompleteCallingConventions()

        strcmp_plt = cfg.functions.function(name="strcmp", plt=True)
        assert strcmp_plt is not None
        assert strcmp_plt.prototype is not None
        assert strcmp_plt.is_prototype_guessed is False
        old_proto = strcmp_plt.prototype.copy()

        func = cfg.functions["verify_password"]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        assert strcmp_plt.prototype is not None
        assert strcmp_plt.is_prototype_guessed is False
        assert old_proto == strcmp_plt.prototype

    def test_variable_type_zero_array_size(self):
        bin_path = os.path.join(test_location, "x86_64", "1after909")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)
        proj.analyses.CompleteCallingConventions()

        func = cfg.functions["verify_password"]
        assert func is not None
        dec = proj.analyses.Decompiler(func, cfg=cfg)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)

        # take the stack variable v2; it should be a char array of size 64
        assert dec.func.addr in dec.kb.dec_variables
        varman = dec.kb.dec_variables.get_function_manager(func.addr)
        var2 = next(iter(varman.find_variables_by_stack_offset(-0x58)))
        assert var2 is not None
        var2 = varman.unified_variable(var2)
        assert var2 is not None
        ty = varman.get_variable_type(var2)
        assert isinstance(ty, SimTypeArray) and isinstance(ty.elem_type, SimTypeChar) and ty.length == 64

        # set it to an array of size 0
        varman.set_variable_type(var2, SimTypeArray(SimTypeChar(), 0).with_arch(proj.arch), mark_manual=True)

        # decompile again; should not crash!
        new_dec = proj.analyses.Decompiler(func, fail_fast=True, regen_clinic=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(new_dec)
        assert f"char {var2.name}[0];" in new_dec.codegen.text

        # set it to an integer
        varman.set_variable_type(var2, SimTypeInt().with_arch(proj.arch), mark_manual=True)

        # decompile again; should not crash!
        new_dec = proj.analyses.Decompiler(func, fail_fast=True, regen_clinic=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(new_dec)
        assert f"int {var2.name};" in new_dec.codegen.text

    def test_prototype_ignores_arg_types_wider_than_the_arg(self):
        bin_path = os.path.join(test_location, "i386", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = proj.kb.functions["authenticate"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.clinic is not None

        arg0 = dec.clinic.arg_list[0]
        assert arg0.size == 4
        big = SimStruct({"a": SimTypeInt(), "pad": SimTypeArray(SimTypeChar(), 4000)}, name="big").with_arch(proj.arch)
        proj.kb.dec_variables[func.addr].set_variable_type(arg0, big)
        dec.clinic._make_function_prototype(dec.clinic.arg_list)

        assert func.prototype is not None
        assert func.prototype.args[0].with_arch(proj.arch).size == 32

    def test_arg_stored_into_struct_first_member_stays_scalar_in_prototype(self):
        # caller(long x) stores x into the first member of a stack struct S and passes &s to callee(struct S *)
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "struct_ref_first_member")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(recover_variables=False)
        arch = proj.arch
        callee, caller, top = (proj.kb.functions[name] for name in ("callee", "caller", "top"))
        struct = SimStruct(
            {"a": SimTypeLongLong(), "b": SimTypeLongLong(), "c": SimTypeLongLong(), "d": SimTypeLongLong()}, name="S"
        ).with_arch(arch)
        callee.prototype = SimTypeFunction([SimTypePointer(struct)], SimTypeLongLong()).with_arch(arch)

        # the stack slot holding x is only S.a: x (and rdi) must stay scalar, while the stack object is still an S
        dec = proj.analyses.Decompiler(caller, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        proto = caller.prototype
        assert proto is not None and len(proto.args) == 1
        assert not isinstance(proto.args[0], SimStruct)
        assert proto.args[0].with_arch(arch).size == 64
        assert re.search(r"\bS v\d+;", dec.codegen.text) is not None
        assert re.search(r"callee\(&v\d+\)", dec.codegen.text) is not None
        # the stores write the struct's members
        assert re.search(r"\bv\d+\.a = a0;", dec.codegen.text) is not None, dec.codegen.text
        for member, value in (("b", 0), ("c", 1), ("d", 2)):
            assert re.search(rf"\bv\d+\.{member} = {value};", dec.codegen.text) is not None, dec.codegen.text
        assert len(re.findall(r"^\s+\S+ v\d+;  // \[bp", dec.codegen.text, re.MULTILINE)) == 1, dec.codegen.text

        dec = proj.analyses.Decompiler(top, cfg=cfg.model, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "caller(a0 + 1)" in dec.codegen.text

    def test_struct_first_member_accessed_around_call_stays_scalar(self):
        # reread() reads s.a back after callee(&s); loop() writes s.a before callee(&s) in a loop
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "struct_ref_after_call")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(recover_variables=False)
        arch = proj.arch
        struct = SimStruct(
            {"a": SimTypeLongLong(), "b": SimTypeLongLong(), "c": SimTypeLongLong(), "d": SimTypeLongLong()}, name="S"
        ).with_arch(arch)
        callee = proj.kb.functions["callee"]
        callee.prototype = SimTypeFunction([SimTypePointer(struct)], SimTypeLongLong()).with_arch(arch)

        for name in ("reread", "loop"):
            func = proj.kb.functions[name]
            dec = proj.analyses.Decompiler(func, cfg=cfg.model, fail_fast=True)
            assert dec.codegen is not None and dec.codegen.text is not None
            print_decompilation_result(dec)
            proto = func.prototype
            assert proto is not None and proto.returnty is not None
            for ty in (proto.returnty, *proto.args):
                assert not isinstance(ty, SimStruct), name
                assert ty.with_arch(arch).size == 64, name
            # only the stack object is an S
            assert len(re.findall(r"^\s+S \w+;", dec.codegen.text, re.MULTILINE)) == 1, name
            if name == "reread":
                # the read after the call reads the struct's first member
                assert re.search(r"return v\d+\.a;", dec.codegen.text) is not None
            else:
                # the write in the loop writes the struct's first member
                assert re.search(r"\bv\d+\.a = \w+;", dec.codegen.text) is not None, dec.codegen.text

    def test_mutually_recursive_known_structs_are_defined_once(self):
        # a known struct is rendered as defined: one typedef per name, with the recursive references intact
        bin_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(show_progressbar=not WORKER, fail_fast=True, normalize=True)
        proj.analyses.CompleteCallingConventions()

        alpha = SimStruct({}, name="Alpha")
        beta = SimStruct({}, name="Beta")
        alpha.fields = OrderedDict({"beta": SimTypePointer(beta), "x": SimTypeInt()})
        beta.fields = OrderedDict({"alpha": SimTypePointer(alpha), "y": SimTypeInt()})

        callee = cfg.functions["authenticate"]
        callee.calling_convention = default_cc(proj.arch.name, platform=proj.simos.name)(proj.arch)
        callee.prototype = SimTypeFunction([SimTypePointer(alpha), SimTypePointer(beta)], SimTypeInt()).with_arch(
            proj.arch
        )

        dec = proj.analyses.Decompiler(cfg.functions["main"], cfg=cfg, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(dec)
        text = dec.codegen.text

        for name in ("Alpha", "Beta"):
            assert text.count(f"typedef struct {name} {{") == 1
        assert "struct Beta *beta;" in text
        assert "struct Alpha *alpha;" in text
        assert "void* beta;" not in text
        assert "void* alpha;" not in text


if __name__ == "__main__":
    unittest.main()
