import logging
import os
import unittest

from common import requires_binaries_private
import archinfo
import angr
from angr.calling_conventions import (
    SimStackArg,
    SimRegArg,
    SimCCCdecl,
    SimCCSystemVAMD64,
)
from angr.sim_type import SimTypeFunction

test_location = os.path.join(
    os.path.dirname(os.path.realpath(str(__file__))),
    "..",
    "..",
    "binaries",
)


# pylint: disable=missing-class-docstring
# pylint: disable=no-self-use
class TestCallingConventionAnalysis(unittest.TestCase):
    def _run_fauxware(self, arch, function_and_cc_list):
        binary_path = os.path.join(test_location, "tests", arch, "fauxware")
        fauxware = angr.Project(binary_path, auto_load_libs=False)

        cfg = fauxware.analyses.CFG()

        for func_name, expected_cc in function_and_cc_list:
            authenticate = cfg.functions[func_name]
            _ = fauxware.analyses.VariableRecoveryFast(authenticate)

            cc_analysis = fauxware.analyses.CallingConvention(authenticate, cfg=cfg, analyze_callsites=True)
            cc = cc_analysis.cc

            assert cc == expected_cc

    def _run_cgc(self, binary_name):
        pass
        # binary_path = os.path.join(test_location, '..', 'binaries-private', 'cgc_qualifier_event', 'cgc', binary_name)
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
            arg_str = "r_%s" % (arg.reg_name)
        else:
            raise TypeError("Unsupported argument type %s." % type(arg))
        return arg_str == expected_str

    def check_args(self, func_name, args, expected_arg_strs):
        assert len(args) == len(expected_arg_strs), "Wrong number of arguments for function %s. Got %d, expect %d." % (
            func_name,
            len(args),
            len(expected_arg_strs),
        )

        for idx, (arg, expected_arg_str) in enumerate(zip(args, expected_arg_strs)):
            r = self.check_arg(arg, expected_arg_str)
            assert r, "Incorrect argument %d for function %s. Got %s, expect %s." % (
                idx,
                func_name,
                arg,
                expected_arg_str,
            )

    def _a(self, funcs, func_name):
        func = funcs[func_name]
        return func.calling_convention.arg_locs(func.prototype)

    def test_x8664_dir_gcc_O0(self):
        binary_path = os.path.join(test_location, "tests", "x86_64", "dir_gcc_-O0")
        proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)

        cfg = proj.analyses.CFG()  # fill in the default kb

        proj.analyses.CompleteCallingConventions(recover_variables=True)

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

    def test_armel_fauxware(self):
        binary_path = os.path.join(test_location, "tests", "armel", "fauxware")
        proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)

        cfg = proj.analyses.CFG()  # fill in the default kb

        proj.analyses.CompleteCallingConventions(recover_variables=True)

        funcs = cfg.kb.functions

        # check args
        expected_args = {
            "main": ["r_r0", "r_r1"],
            "accepted": ["r_r0", "r_r1", "r_r2", "r_r3"],
            "rejected": [],
            "authenticate": ["r_r0", "r_r1", "r_r2"],  # TECHNICALLY WRONG but what are you gonna do about it
            # details: open(3) can take either 2 or 3 args. we use the 2 arg version but we have the 3 arg version
            # hardcoded in angr. the third arg is still "live" from the function start.
        }

        for func_name, args in expected_args.items():
            self.check_args(func_name, self._a(funcs, func_name), args)

    def test_x8664_void(self):
        binary_path = os.path.join(test_location, "tests", "x86_64", "types", "void")
        proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)

        cfg = proj.analyses.CFG()

        proj.analyses.CompleteCallingConventions(recover_variables=True, cfg=cfg.model, analyze_callsites=True)

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
            if func.is_simprocedure or func.alignment:
                continue
            if func.calling_convention is None:
                continue
            if func.name in groundtruth:
                r = groundtruth[func.name]
                if r is None:
                    assert func.prototype.returnty is None
                else:
                    ret_val = func.calling_convention.return_val(func.prototype.returnty)
                    assert isinstance(ret_val, SimRegArg)
                    assert ret_val.reg_name == r

    def test_x86_saved_regs(self):
        # Calling convention analysis should be able to determine calling convention of functions with registers
        # saved on the stack.
        binary_path = os.path.join(test_location, "tests", "cgc", "NRFIN_00036")
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
        assert len(prototype.args) == 1
        assert cc.arg_locs(prototype)[0] == SimStackArg(4, 4)

    def test_callsite_inference_amd64(self):
        # Calling convention analysis should be able to determine calling convention of a library function by
        # analyzing its callsites.
        binary_path = os.path.join(test_location, "tests", "x86_64", "decompiler", "morton")
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFG(data_references=True, normalize=True)

        func = cfg.functions.function(name="mosquitto_publish", plt=True)
        cca = proj.analyses.CallingConvention(func, analyze_callsites=True)
        assert len(cca.prototype.args) == 6

    def test_x64_return_value_used(self):
        binary_path = os.path.join(test_location, "tests", "x86_64", "cwebp-0.3.1-feh-original")
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True, force_complete_scan=False)
        func = proj.kb.functions.get_by_addr(0x4046E0)
        cca = proj.analyses.CallingConvention(func=func, cfg=cfg, analyze_callsites=True)

        assert cca.prototype is not None
        assert cca.prototype.returnty is not None

    def test_armhf_thumb_movcc(self):
        binary_path = os.path.join(test_location, "tests", "armhf", "amp_challenge_07.gcc")
        proj = angr.Project(binary_path, auto_load_libs=False)
        _ = proj.analyses.CFGFast(normalize=True, data_references=True, regions=[(0xFEC94, 0xFEF60)])
        f = proj.kb.functions[0xFEC95]
        proj.analyses.VariableRecoveryFast(f)
        cca = proj.analyses.CallingConvention(f)

        assert cca.prototype is not None
        assert cca.cc is not None
        assert isinstance(cca.prototype, SimTypeFunction)
        assert len(cca.prototype.args) == 2

    def manual_test_workers(self):
        binary_path = os.path.join(test_location, "tests", "x86_64", "1after909")
        proj = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)

        cfg = proj.analyses.CFG(normalize=True)  # fill in the default kb

        _ = proj.analyses.CompleteCallingConventions(
            cfg=cfg.model, recover_variables=True, workers=4, show_progressbar=True
        )

        for func in cfg.functions.values():
            assert func.is_prototype_guessed is True

    def test_tail_calls(self):
        for opt_level in (1, 2):
            binary_path = os.path.join(test_location, "tests", "x86_64", "tailcall-O%d" % opt_level)
            proj = angr.Project(binary_path, auto_load_libs=False)

            proj.analyses.CFG(normalize=True)
            proj.analyses.CompleteCallingConventions(recover_variables=True)

            for func in ["target", "direct", "plt"]:
                self.assertEqual(str(proj.kb.functions[func].prototype), "(long long (64 bits)) -> long long (64 bits)")
                # technically should be (int) -> int, but the compiler loads all 64 bits and then truncates


if __name__ == "__main__":
    # logging.getLogger("angr.analyses.variable_recovery.variable_recovery_fast").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.calling_convention").setLevel(logging.INFO)
    unittest.main()
