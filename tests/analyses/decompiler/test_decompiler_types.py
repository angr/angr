# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest
import re

import angr
from angr.sim_type import SimTypeArray, SimTypeChar, SimTypeInt

from tests.common import bin_location, WORKER, print_decompilation_result

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
        assert dec._variable_kb is not None
        varman = dec._variable_kb.variables.get_function_manager(func.addr)
        var2 = next(iter(varman.find_variables_by_stack_offset(-0x58)))
        assert var2 is not None
        var2 = varman.unified_variable(var2)
        assert var2 is not None
        ty = varman.get_variable_type(var2)
        assert isinstance(ty, SimTypeArray) and isinstance(ty.elem_type, SimTypeChar) and ty.length == 64

        # set it to an array of size 0
        varman.set_variable_type(var2, SimTypeArray(SimTypeChar(), 0).with_arch(proj.arch), mark_manual=True)

        # decompile again; should not crash!
        new_dec = proj.analyses.Decompiler(func, variable_kb=dec._variable_kb, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(new_dec)
        assert f"char {var2.name}[0];" in new_dec.codegen.text

        # set it to an integer
        varman.set_variable_type(var2, SimTypeInt().with_arch(proj.arch), mark_manual=True)

        # decompile again; should not crash!
        new_dec = proj.analyses.Decompiler(func, variable_kb=dec._variable_kb, fail_fast=True)
        assert dec.codegen is not None and dec.codegen.text is not None
        print_decompilation_result(new_dec)
        assert f"int {var2.name};" in new_dec.codegen.text


if __name__ == "__main__":
    unittest.main()
