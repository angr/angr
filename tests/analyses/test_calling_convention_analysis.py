#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import logging
import os
import unittest
from functools import wraps

import archinfo

import angr
from angr.calling_conventions import (
    SimStackArg,
    SimRegArg,
    SimCCCdecl,
    SimCCSystemVAMD64,
)
from angr.analyses.complete_calling_conventions import CallingConventionAnalysisMode
from angr.sim_type import SimTypeFunction, SimTypeInt, SimTypeLongLong, SimTypeBottom, SimTypeFloat
from tests.common import bin_location, requires_binaries_private


test_location = os.path.join(bin_location, "tests")


def cca_mode(modes: str):
    def wrapper(func):
        @wraps(func)
        def inner(*args, **kwargs):
            for mode_str in modes.split(","):
                mode = CallingConventionAnalysisMode[mode_str.upper()]
                func(*args, mode=mode, **kwargs)

        return inner

    return wrapper


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestCallingConventionAnalysis(unittest.TestCase):
    def _run_fauxware(self, arch, function_and_cc_list):
        binary_path = os.path.join(test_location, arch, "fauxware")
        fauxware = angr.Project(binary_path, auto_load_libs=False)

        cfg = fauxware.analyses.CFG()

        for func_name, expected_cc in function_and_cc_list:
            authenticate = cfg.functions[func_name]
            _ = fauxware.analyses.VariableRecoveryFast(authenticate)

            cc_analysis = fauxware.analyses.CallingConvention(authenticate, cfg=cfg.model, analyze_callsites=True)
            cc = cc_analysis.cc

            assert cc == expected_cc

    def _run_cgc(self, binary_name):
        pass
        # binary_path = os.path.join(bin_location, '..', 'binaries-private', 'cgc_qualifier_event', 'cgc', binary_name)
        # project = angr.Project(binary_path, auto_load_libs=False)
        #
        # categorization = project.analyses.FunctionCategorizationAnalysis()

        # tag_manager = categorization.function_tag_manager
        # print "INPUT:", map(hex, tag_manager.input_functions())
        # print "OUTPUT:", map(hex, tag_manager.output_functions())

    def test_fauxware_i386(self):
        self._run_fauxware("i386", [("authenticate", SimCCCdecl(archinfo.arch_from_id("i386")))])

    def test_fauxware_x86_64(self):
        amd64 = archinfo.arch_from_id("amd64")
        self._run_fauxware(
            "x86_64",
            [
                (
                    "authenticate",
                    SimCCSystemVAMD64(
                        amd64,
                    ),
                ),
            ],
        )

    @requires_binaries_private
    def test_cgc_binary1(self):
        self._run_cgc("002ba801_01")

    @requires_binaries_private
    def test_cgc_binary2(self):
        self._run_cgc("01cf6c01_01")

    #
    # Full-binary calling convention analysis
    #

    def check_arg(self, arg, expected_str):
        if isinstance(arg, SimRegArg):
            arg_str = f"r_{arg.reg_name}"
        else:
            raise TypeError(f"Unsupported argument type {type(arg)}.")
        return arg_str == expected_str

    def check_args(self, func_name, args, expected_arg_strs):
        assert len(args) == len(expected_arg_strs), (
            f"Wrong number of arguments for function {func_name}. " f"Got {len(args)}, expect {len(expected_arg_strs)}."
        )

        for idx, (arg, expected_arg_str) in enumerate(zip(args, expected_arg_strs)):
            r = self.check_arg(arg, expected_arg_str)
            assert r, f"Incorrect argument {idx} for function {func_name}. " f"Got {arg}, expect {expected_arg_str}."

    def _a(self, funcs, func_name):
        func = funcs[func_name]
        return func.calling_convention.arg_locs(func.prototype)

    @cca_mode("fast,variables")
    def test_x8664_dir_gcc_O0(self, *, mode):
        binary_path = os.path.join(test_location, "x86_64", "dir_gcc_-O0")
        proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)

        cfg = proj.analyses.CFG()  # fill in the default kb

        proj.analyses.CompleteCallingConventions(mode=mode, recover_variables=True)

        funcs = cfg.kb.functions

        # check args
        expected_args = {
            "c_ispunct": ["r_rdi"],
            "file_failure": ["r_rdi", "r_rsi", "r_rdx"],
            "to_uchar": ["r_rdi"],
            "dot_or_dotdot": ["r_rdi"],
            "emit_mandatory_arg_note": [],
            "emit_size_note": [],
            "emit_ancillary_info": ["r_rdi"],
            "emit_try_help": [],
            "dev_ino_push": ["r_rdi", "r_rsi"],
            "main": ["r_rdi", "r_rsi"],
            "queue_directory": ["r_rdi", "r_rsi", "r_rdx"],
        }

        for func_name, args in expected_args.items():
            self.check_args(func_name, self._a(funcs, func_name), args)

    @cca_mode("fast,variables")
    def test_armel_fauxware(self, *, mode):
        binary_path = os.path.join(test_location, "armel", "fauxware")
        proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)

        cfg = proj.analyses.CFG()  # fill in the default kb

        proj.analyses.CompleteCallingConventions(mode=mode, recover_variables=True)

        funcs = cfg.kb.functions

        # check args
        expected_args = {
            "main": ["r_r0", "r_r1"],
            "accepted": [],
            "rejected": [],
            "authenticate": ["r_r0", "r_r1"],
            # or "authenticate": ["r_r0", "r_r1", "r_r2"]
            # TECHNICALLY WRONG but what are you gonna do about it
            # details: open(3) can take either 2 or 3 args. we use the 2 arg version but we have the 3 arg version
            # hardcoded in angr. the third arg is still "live" from the function start.
        }

        for func_name, args in expected_args.items():
            self.check_args(func_name, self._a(funcs, func_name), args)

    @cca_mode("fast,variables")
    def test_x8664_void(self, *, mode):
        binary_path = os.path.join(test_location, "x86_64", "types", "void")
        proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)

        cfg = proj.analyses.CFG()

        proj.analyses.CompleteCallingConventions(
            mode=mode, recover_variables=True, cfg=cfg.model, analyze_callsites=True
        )

        funcs = cfg.kb.functions

        groundtruth = {
            "func_1": None,
            "func_2": None,
            "func_3": "rax",
            "func_4": None,
            "func_5": None,
            "func_6": "rax",
        }

        for func in funcs.values():
            if func.is_simprocedure or func.is_alignment:
                continue
            if func.calling_convention is None:
                continue
            if func.name in groundtruth:
                r = groundtruth[func.name]
                if r is None:
                    assert isinstance(func.prototype.returnty, SimTypeBottom)
                else:
                    ret_val = func.calling_convention.return_val(func.prototype.returnty)
                    assert isinstance(ret_val, SimRegArg)
                    assert ret_val.reg_name == r

    def test_x86_saved_regs(self):
        # Calling convention analysis should be able to determine calling convention of functions with registers
        # saved on the stack.
        binary_path = os.path.join(test_location, "cgc", "NRFIN_00036")
        proj = angr.Project(binary_path, auto_load_libs=False)

        cfg = proj.analyses.CFG()
        func = cfg.functions[0x80494F0]  # int2str

        proj.analyses.VariableRecoveryFast(func)
        cca = proj.analyses.CallingConvention(func)
        cc = cca.cc
        prototype = cca.prototype

        assert cc is not None, (
            "Calling convention analysis failed to determine the calling convention of function " "0x80494f0."
        )
        assert isinstance(cc, SimCCCdecl)
        assert prototype is not None
        assert len(prototype.args) == 3
        arg_locs = cc.arg_locs(prototype)
        assert arg_locs[0] == SimStackArg(4, 4)
        assert arg_locs[1] == SimStackArg(8, 4)
        assert arg_locs[2] == SimStackArg(12, 4)

        func_exit = cfg.functions[0x804A1A9]  # exit

        proj.analyses.VariableRecoveryFast(func_exit)
        cca = proj.analyses.CallingConvention(func_exit)
        cc = cca.cc
        prototype = cca.prototype

        assert func_exit.returning is False
        assert cc is not None, (
            "Calling convention analysis failed to determine the calling convention of function " "0x804a1a9."
        )
        assert isinstance(cc, SimCCCdecl)
        assert prototype is not None
        assert len(prototype.args) == 1
        assert cc.arg_locs(prototype)[0] == SimStackArg(4, 4)

    def test_callsite_inference_amd64(self):
        # Calling convention analysis should be able to determine calling convention of a library function by
        # analyzing its callsites.
        binary_path = os.path.join(test_location, "x86_64", "decompiler", "morton")
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(data_references=True, normalize=True)

        func = cfg.functions.function(name="mosquitto_publish", plt=True)
        assert func is not None
        proj.analyses.VariableRecoveryFast(func)
        cca = proj.analyses.CallingConvention(func, analyze_callsites=True)
        assert cca.prototype is not None
        assert len(cca.prototype.args) == 6

    def test_x64_return_value_used(self):
        binary_path = os.path.join(test_location, "x86_64", "cwebp-0.3.1-feh-original")
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True, force_complete_scan=False)
        func = proj.kb.functions.get_by_addr(0x4046E0)
        proj.analyses.VariableRecoveryFast(func)
        cca = proj.analyses.CallingConvention(func=func, cfg=cfg.model, analyze_callsites=True)

        assert cca.prototype is not None
        assert cca.prototype.returnty is not None

    def test_armhf_thumb_movcc(self):
        binary_path = os.path.join(test_location, "armhf", "amp_challenge_07.gcc")
        proj = angr.Project(binary_path, auto_load_libs=False)
        _ = proj.analyses.CFGFast(normalize=True, data_references=True, regions=[(0xFEC94, 0xFEF60)])
        f = proj.kb.functions[0xFEC95]
        proj.analyses.VariableRecoveryFast(f)
        cca = proj.analyses.CallingConvention(f)

        assert cca.prototype is not None
        assert cca.cc is not None
        assert isinstance(cca.prototype, SimTypeFunction)
        assert len(cca.prototype.args) == 2

    def test_armhf_thumb_floats(self):
        binary_path = os.path.join(test_location, "armhf", "float_int_conversion.elf")
        proj = angr.Project(binary_path, auto_load_libs=False)
        _ = proj.analyses.CFGFast(normalize=True, data_references=True)
        proj.analyses.CompleteCallingConventions()

        assert proj.kb.functions["float_to_int"].prototype is not None
        assert proj.kb.functions["float_to_int"].prototype.args == (SimTypeFloat(),)
        assert proj.kb.functions["float_to_int"].prototype.returnty == SimTypeInt()
        assert proj.kb.functions["int_to_float"].prototype is not None
        assert proj.kb.functions["int_to_float"].prototype.args == (SimTypeInt(),)
        assert proj.kb.functions["int_to_float"].prototype.returnty == SimTypeFloat()
        assert proj.kb.functions["increment_float"].prototype is not None
        assert proj.kb.functions["increment_float"].prototype.args == (SimTypeFloat(), SimTypeFloat())
        assert proj.kb.functions["increment_float"].prototype.returnty == SimTypeFloat()
        assert proj.kb.functions["float_to_rounded_float"].prototype is not None
        assert proj.kb.functions["float_to_rounded_float"].prototype.args == (SimTypeFloat(),)
        assert proj.kb.functions["float_to_rounded_float"].prototype.returnty == SimTypeFloat()
        assert proj.kb.functions["compare_floats"].prototype is not None
        assert set(proj.kb.functions["compare_floats"].prototype.args) == {SimTypeFloat(), SimTypeFloat(), SimTypeInt()}
        assert proj.kb.functions["compare_floats"].prototype.returnty == SimTypeInt()

    @cca_mode("fast,variables")
    def manual_test_workers(self, *, mode):
        binary_path = os.path.join(test_location, "x86_64", "1after909")
        proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)

        cfg = proj.analyses.CFG(normalize=True)  # fill in the default kb

        _ = proj.analyses.CompleteCallingConventions(
            mode=mode, cfg=cfg.model, recover_variables=True, workers=4, show_progressbar=True
        )

        for func in cfg.functions.values():
            assert func.is_prototype_guessed is True

    @cca_mode("fast,variables")
    def test_tail_calls(self, *, mode):
        for opt_level in (1, 2):
            binary_path = os.path.join(test_location, "x86_64", f"tailcall-O{opt_level}")
            proj = angr.Project(binary_path, auto_load_libs=False)

            proj.analyses.CFG(normalize=True)
            proj.analyses.CompleteCallingConventions(mode=mode, recover_variables=True)

            for func in ["target", "direct", "plt"]:
                # expected prototype: (int) -> long long
                # technically should be (int) -> int, but the compiler loads all 64 bits and then truncates
                proto = proj.kb.functions[func].prototype
                assert proto is not None
                assert len(proto.args) == 1
                assert isinstance(proto.args[0], SimTypeInt)
                assert isinstance(proto.returnty, SimTypeLongLong)

    def test_ls_gcc_O0_timespec_cmp(self):
        binary_path = os.path.join(test_location, "x86_64", "decompiler", "ls_gcc_O0")
        proj = angr.Project(binary_path, auto_load_libs=False)

        proj.analyses.CFG(normalize=True)
        proj.analyses.VariableRecoveryFast(proj.kb.functions["timespec_cmp"])
        cca = proj.analyses.CallingConvention(proj.kb.functions["timespec_cmp"])

        assert cca.prototype is not None
        assert len(cca.prototype.args) == 4

    @cca_mode("fast,variables")
    def test_run_multiple_times(self, *, mode):
        binary_path = os.path.join(test_location, "x86_64", "fauxware")
        proj = angr.Project(binary_path, auto_load_libs=False)

        proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions(mode=mode, recover_variables=True)

        expected_prototype = proj.kb.functions["main"].prototype
        proj.analyses.CompleteCallingConventions(mode=mode, recover_variables=True)
        assert proj.kb.functions["main"].prototype == expected_prototype

        proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions(mode=mode, recover_variables=True)
        assert proj.kb.functions["main"].prototype == expected_prototype

    @cca_mode("fast,variables")
    def test_test_three_arguments(self, *, mode):
        binary_path = os.path.join(test_location, "x86_64", "test.o")
        proj = angr.Project(binary_path, auto_load_libs=False)

        cfg = proj.analyses.CFG(normalize=True)
        # the node 0x401226 must be in its own function
        node = cfg.model.get_any_node(0x401226)
        assert node is not None
        assert node.function_address == 0x401226

        proj.analyses.CompleteCallingConventions(mode=mode, recover_variables=True)

        assert proj.kb.functions["test_syntax_error"].prototype is not None
        assert proj.kb.functions["test_syntax_error"].prototype.variadic is True
        assert proj.kb.functions["expr"].prototype is not None
        assert len(proj.kb.functions["expr"].prototype.args) == 0

    def test_windows_partial_input_variable_overwrite(self):
        binary_path = os.path.join(test_location, "x86_64", "netfilter_b64.sys")
        proj = angr.Project(binary_path, auto_load_libs=False)

        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.VariableRecoveryFast(proj.kb.functions[0x140001A90])
        cc = proj.analyses.CallingConvention(cfg.kb.functions[0x140001A90])
        assert cc.cc is not None
        assert cc.prototype is not None
        assert len(cc.prototype.args) == 3

    def test_windows_call_return_register_overwrite(self):
        binary_path = os.path.join(test_location, "x86_64", "windows", "CorsairLLAccess64.sys")
        proj = angr.Project(binary_path, auto_load_libs=False)

        cfg = proj.analyses.CFG(normalize=True)
        func = cfg.kb.functions[0x1400014D0]
        proj.analyses.VariableRecoveryFast(func)
        cc = proj.analyses.CallingConvention(func)
        assert cc.cc is not None
        assert cc.prototype is not None
        assert len(cc.prototype.args) == 6

    @cca_mode("fast,variables")
    def test_cdecl_nonconsecutive_stack_args(self, *, mode):
        binary_path = os.path.join(test_location, "i386", "calling_convention_0.o")
        proj = angr.Project(binary_path, auto_load_libs=False)

        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions(mode=mode, recover_variables=True)

        func0 = cfg.kb.functions["sub_12000"]
        assert isinstance(func0.calling_convention, SimCCCdecl)
        assert func0.prototype is not None
        assert len(func0.prototype.args) == 4

        func1 = cfg.kb.functions["sub_119320"]
        assert isinstance(func1.calling_convention, SimCCCdecl)
        assert func1.prototype is not None
        assert len(func1.prototype.args) == 2

        func2 = cfg.kb.functions["sub_8D9F0"]
        assert isinstance(func2.calling_convention, SimCCCdecl)
        assert func2.prototype is not None
        assert len(func2.prototype.args) == 4

    @cca_mode("fast,variables")
    def test_call_sites_arguments_csplit(self, *, mode):
        binary_path = os.path.join(test_location, "x86_64", "csplit.o")
        proj = angr.Project(binary_path, auto_load_libs=False)

        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions(mode=mode, recover_variables=True)
        func0 = cfg.kb.functions["check_for_offset"]
        assert isinstance(func0.calling_convention, SimCCSystemVAMD64)
        assert func0.prototype is not None
        assert len(func0.prototype.args) == 3

        func1 = cfg.kb.functions["xstrtoimax"]
        assert isinstance(func1.calling_convention, SimCCSystemVAMD64)
        assert func1.prototype is not None
        assert len(func1.prototype.args) == 5

        func2 = cfg.kb.functions["remove_line"]
        assert isinstance(func2.calling_convention, SimCCSystemVAMD64)
        assert func2.prototype is not None
        assert len(func2.prototype.args) == 0

        func3 = cfg.kb.functions["dump_rest_of_file"]
        assert isinstance(func3.calling_convention, SimCCSystemVAMD64)
        assert func3.prototype is not None
        assert len(func3.prototype.args) == 0

    @cca_mode("fast,variables")
    def test_call_sites_arguments_test(self, *, mode):
        binary_path = os.path.join(test_location, "x86_64", "test.o")
        proj = angr.Project(binary_path, auto_load_libs=False)

        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions(mode=mode, recover_variables=True)

        func0 = cfg.kb.functions["term"]
        assert isinstance(func0.calling_convention, SimCCSystemVAMD64)
        assert func0.prototype is not None
        assert len(func0.prototype.args) == 0

        func1 = cfg.kb.functions["unary_operator"]
        assert isinstance(func1.calling_convention, SimCCSystemVAMD64)
        assert func1.prototype is not None
        assert len(func1.prototype.args) == 0

        func2 = cfg.kb.functions["advance"]
        assert isinstance(func2.calling_convention, SimCCSystemVAMD64)
        assert func2.prototype is not None
        assert len(func2.prototype.args) == 1

        # external function
        func3 = cfg.kb.functions["quote"]
        assert isinstance(func3.calling_convention, SimCCSystemVAMD64)
        assert func3.prototype is not None
        assert len(func3.prototype.args) == 1

        func4 = cfg.kb.functions["posixtest"]
        assert isinstance(func4.calling_convention, SimCCSystemVAMD64)
        assert func4.prototype is not None
        assert len(func4.prototype.args) == 1

    @cca_mode("fast,variables")
    def test_call_sites_arguments_copy(self, *, mode):
        binary_path = os.path.join(test_location, "x86_64", "copy.o")
        proj = angr.Project(binary_path, auto_load_libs=False)

        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions(mode=mode, recover_variables=True)

        func0 = cfg.kb.functions["punch_hole"]
        assert isinstance(func0.calling_convention, SimCCSystemVAMD64)
        assert func0.prototype is not None
        assert len(func0.prototype.args) == 3

        func1 = cfg.kb.functions["can_write_any_file"]
        assert isinstance(func1.calling_convention, SimCCSystemVAMD64)
        assert func1.prototype is not None
        assert len(func1.prototype.args) == 0

    @cca_mode("fast,variables")
    def test_call_sites_arguments_mv(self, *, mode):
        binary_path = os.path.join(test_location, "x86_64", "mv.o")
        proj = angr.Project(binary_path, auto_load_libs=False)

        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions(mode=mode, recover_variables=True)

        # external function
        func0 = cfg.kb.functions["last_component"]
        assert isinstance(func0.calling_convention, SimCCSystemVAMD64)
        assert func0.prototype is not None
        assert len(func0.prototype.args) == 1

        # external function
        func1 = cfg.kb.functions["strip_trailing_slashes"]
        assert isinstance(func1.calling_convention, SimCCSystemVAMD64)
        assert func1.prototype is not None
        assert len(func1.prototype.args) == 1

    @cca_mode("fast,variables")
    def test_call_sites_arguments_df(self, *, mode):
        binary_path = os.path.join(test_location, "x86_64", "df.o")
        proj = angr.Project(binary_path, auto_load_libs=False)

        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions(mode=mode, recover_variables=True)

        func0 = cfg.kb.functions["alloc_table_row"]
        assert isinstance(func0.calling_convention, SimCCSystemVAMD64)
        assert func0.prototype is not None
        assert len(func0.prototype.args) == 0

        func1 = cfg.kb.functions["get_header"]
        assert isinstance(func1.calling_convention, SimCCSystemVAMD64)
        assert func1.prototype is not None
        assert len(func1.prototype.args) == 0

        func2 = cfg.kb.functions["get_field_list"]
        assert isinstance(func2.calling_convention, SimCCSystemVAMD64)
        assert func2.prototype is not None
        assert len(func2.prototype.args) == 0

        func3 = cfg.kb.functions["alloc_field"]
        assert isinstance(func3.calling_convention, SimCCSystemVAMD64)
        assert func3.prototype is not None
        assert len(func3.prototype.args) == 2

    @cca_mode("fast,variables")
    def test_cdecl_nonconsecutive_stack_args_2(self, *, mode):
        binary_path = os.path.join(
            test_location, "i386", "windows", "48460c9633d06cad3e3b41c87de04177d129906610c5bbdebc7507a211100e98"
        )
        proj = angr.Project(binary_path, auto_load_libs=False)

        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions(mode=mode, recover_variables=True)

        func_main = cfg.kb.functions[0x4106F0]
        assert isinstance(func_main.calling_convention, SimCCCdecl)
        assert func_main.prototype is not None
        assert len(func_main.prototype.args) == 4


if __name__ == "__main__":
    # logging.getLogger("angr.analyses.variable_recovery.variable_recovery_fast").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.calling_convention").setLevel(logging.INFO)
    unittest.main()
