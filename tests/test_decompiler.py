# pylint: disable=missing-class-docstring,no-self-use,line-too-long
import logging
import os
import re
import unittest
from functools import wraps

import angr
from angr.knowledge_plugins.variables.variable_manager import VariableManagerInternal
from angr.sim_type import SimTypeInt, SimTypePointer
from angr.analyses import (
    VariableRecoveryFast,
    CallingConventionAnalysis,
    CompleteCallingConventionsAnalysis,
    CFGFast,
    Decompiler,
)
from angr.analyses.decompiler.optimization_passes.expr_op_swapper import OpDescriptor
from angr.analyses.decompiler.decompilation_options import get_structurer_option
from angr.analyses.decompiler.structuring import STRUCTURER_CLASSES

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")
l = logging.Logger(__name__)

WORKER = bool(os.environ.get("WORKER", False))  # this variable controls whether we print the decompilation code or not


def for_all_structuring_algos(func):
    """
    A helper wrapper that wraps a unittest function that has an option for 'decompiler_options'.
    This option MUST be used when calling the Decompiler interface for the effects of using all
    structuring algorithms.

    In the function its best to call your decompiler like so:
    angr.analyses.Decompiler(f, cfg=..., options=decompiler_options)
    """

    @wraps(func)
    def _for_all_structuring_algos(*args, **kwargs):
        orig_opts = kwargs.pop("decompiler_options", None) or []
        ret_vals = []
        structurer_option = get_structurer_option()
        for structurer in STRUCTURER_CLASSES:
            new_opts = orig_opts + [(structurer_option, structurer)]
            ret_vals.append(func(*args, decompiler_options=new_opts, **kwargs))

        return ret_vals

    return _for_all_structuring_algos


def structuring_algo(algo: str):
    def _structuring_algo(func):
        @wraps(func)
        def inner(*args, **kwargs):
            orig_opts = kwargs.pop("decompiler_options", None) or []
            ret_vals = []
            structurer_option = get_structurer_option()
            new_opts = orig_opts + [(structurer_option, algo)]
            ret_vals.append(func(*args, decompiler_options=new_opts, **kwargs))
            return ret_vals

        return inner

    return _structuring_algo


class TestDecompiler(unittest.TestCase):
    def _print_decompilation_result(self, dec):
        if not WORKER:
            print("Decompilation result:")
            print(dec.codegen.text)

    @for_all_structuring_algos
    def test_decompiling_all_x86_64(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "all")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        for f in cfg.functions.values():
            if f.is_simprocedure:
                l.debug("Skipping SimProcedure %s.", repr(f))
                continue
            p.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
            # FIXME: This test does not pass
            # assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
            # self._print_decompilation_result(dec)

    @for_all_structuring_algos
    def test_decompiling_babypwn_i386(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "i386", "decompiler", "codegate2017_babypwn")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)
        p.analyses[CompleteCallingConventionsAnalysis].prep()(recover_variables=True)
        for f in cfg.functions.values():
            if f.is_simprocedure:
                l.debug("Skipping SimProcedure %s.", repr(f))
                continue
            if f.addr not in (0x8048A71, 0x8048C6B):
                continue
            dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
            assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
            self._print_decompilation_result(dec)

    @for_all_structuring_algos
    def test_decompiling_loop_x86_64(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "loop")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)
        f = cfg.functions["loop"]
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)
        # it should be properly structured to a while loop without conditional breaks.
        assert "break" not in dec.codegen.text

    @for_all_structuring_algos
    def test_decompiling_all_i386(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "i386", "all")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        f = cfg.functions["main"]
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)

    @for_all_structuring_algos
    def test_decompiling_aes_armel(self, decompiler_options=None):
        # EDG Says: This binary is invalid.
        # Consider replacing with some real firmware
        bin_path = os.path.join(test_location, "armel", "aes")
        # TODO: FIXME: EDG says: This binary is actually CortexM
        # It is incorrectly linked. We override this here
        p = angr.Project(bin_path, arch="ARMEL", auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        f = cfg.functions["main"]
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)

    @for_all_structuring_algos
    def test_decompiling_mips_allcmps(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "mips", "allcmps")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(collect_data_references=True, normalize=True)

        f = cfg.functions["main"]
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)

    @for_all_structuring_algos
    def test_decompiling_linked_list(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "linked_list")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        f = cfg.functions["sum"]
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)

    @for_all_structuring_algos
    def test_decompiling_dir_gcc_O0_free_ent(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "dir_gcc_-O0")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(normalize=True)

        f = cfg.functions["free_ent"]
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)

    @for_all_structuring_algos
    def test_decompiling_dir_gcc_O0_main(self, decompiler_options=None):
        # tests loop structuring
        bin_path = os.path.join(test_location, "x86_64", "dir_gcc_-O0")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(normalize=True)

        f = cfg.functions["main"]
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)

    @for_all_structuring_algos
    def test_decompiling_dir_gcc_O0_emit_ancillary_info(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "dir_gcc_-O0")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(normalize=True)

        f = cfg.functions["emit_ancillary_info"]
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)

    @for_all_structuring_algos
    def test_decompiling_switch0_x86_64(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "switch_0")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        f = cfg.functions["main"]
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)

        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)
        code = dec.codegen.text
        assert "switch" in code
        assert "case 1:" in code
        assert "case 2:" in code
        assert "case 3:" in code
        assert "case 4:" in code
        assert "case 5:" in code
        assert "case 6:" in code
        assert "case 7:" in code
        assert "default:" in code

    @for_all_structuring_algos
    def test_decompiling_switch1_x86_64(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "switch_1")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes = [
            p
            for p in all_optimization_passes
            if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier
        ]

        f = cfg.functions["main"]
        dec = p.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)
        code = dec.codegen.text
        assert "switch" in code
        assert "case 1:" in code
        assert "case 2:" in code
        assert "case 3:" in code
        assert "case 4:" in code
        assert "case 5:" in code
        assert "case 6:" in code
        assert "case 7:" in code
        assert "case 8:" in code
        assert "default:" not in code

    @for_all_structuring_algos
    def test_decompiling_switch2_x86_64(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "switch_2")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes = [
            p
            for p in all_optimization_passes
            if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier
        ]

        f = cfg.functions["main"]
        dec = p.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)
        code = dec.codegen.text
        assert "switch" in code
        assert "case 1:" in code
        assert "case 2:" in code
        assert "case 3:" in code
        assert "case 4:" in code
        assert "case 5:" in code
        assert "case 6:" in code
        assert "case 7:" in code
        assert "case 8:" not in code
        assert "default:" in code

        assert code.count("break;") == 4

    @for_all_structuring_algos
    def test_decompiling_true_x86_64_0(self, decompiler_options=None):
        # in fact this test case tests if CFGBase._process_jump_table_targeted_functions successfully removes "function"
        # 0x402543, which is an artificial function that the compiler (GCC) created for identified "cold" functions.

        bin_path = os.path.join(test_location, "x86_64", "true_ubuntu_2004")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes = [
            p
            for p in all_optimization_passes
            if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier
        ]

        f = cfg.functions[0x4048C0]
        dec = p.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)
        code = dec.codegen.text
        assert "switch" in code
        assert "case" in code

    @for_all_structuring_algos
    def test_decompiling_true_x86_64_1(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "true_ubuntu_2004")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes = [
            p
            for p in all_optimization_passes
            if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier
        ]

        f = cfg.functions[0x404DC0]
        dec = p.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)
        code: str = dec.codegen.text

        # constant propagation was failing. see https://github.com/angr/angr/issues/2659
        assert (
            code.count("32 <=") == 0
            and code.count("32 >") == 0
            and code.count("((int)32) <=") == 0
            and code.count("((int)32) >") == 0
        )
        if "*(&stack_base-56:32)" in code:
            assert code.count("32") == 3
        else:
            assert code.count("32") == 2

    @for_all_structuring_algos
    def test_decompiling_true_a_x86_64_0(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "true_a")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep(show_progressbar=not WORKER)(normalize=True, data_references=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes = [
            p
            for p in all_optimization_passes
            if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier
        ]

        f = cfg.functions[0x401E60]
        dec = p.analyses[Decompiler].prep(show_progressbar=not WORKER)(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)

        assert dec.codegen.text.count("switch (") == 3  # there are three switch-cases in total

    @for_all_structuring_algos
    def test_decompiling_true_a_x86_64_1(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "true_a")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes = [
            p
            for p in all_optimization_passes
            if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier
        ]

        f = cfg.functions[0x404410]
        dec = p.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)

        # the decompilation output should somewhat make sense
        assert 'getenv("CHARSETALIASDIR");' in dec.codegen.text
        assert "fscanf(" in dec.codegen.text
        assert '"%50s %50s"' in dec.codegen.text

        # make sure all "break;" is followed by a curly brace
        dec_no_spaces = dec.codegen.text.replace("\n", "").replace(" ", "")
        replaced = dec_no_spaces.replace("break;}", "")
        assert "break" not in replaced

    @for_all_structuring_algos
    def test_decompiling_true_1804_x86_64(self, decompiler_options=None):
        # true in Ubuntu 18.04, with -O2, has special optimizations that
        # may mess up the way we structure loops and conditionals

        bin_path = os.path.join(test_location, "x86_64", "true_ubuntu1804")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses.CFG(normalize=True, data_references=True)

        f = cfg.functions["usage"]
        dec = p.analyses.Decompiler(f, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)

    @for_all_structuring_algos
    def test_decompiling_true_mips64(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "mips64", "true")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=False)
        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "MIPS64", "linux"
        )

        f = cfg.functions["main"]
        dec = p.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)
        # make sure strings exist
        assert '"coreutils"' in dec.codegen.text
        assert '"/usr/local/share/locale"' in dec.codegen.text
        assert '"--help"' in dec.codegen.text
        assert '"Jim Meyering"' in dec.codegen.text
        # make sure function calls exist
        assert "set_program_name(" in dec.codegen.text
        assert "setlocale(" in dec.codegen.text
        assert "usage(0);" in dec.codegen.text

    @for_all_structuring_algos
    def test_decompiling_1after909_verify_password(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "1after909")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        # verify_password
        f = cfg.functions["verify_password"]
        # recover calling convention
        p.analyses[VariableRecoveryFast].prep()(f)
        cca = p.analyses[CallingConventionAnalysis].prep()(f)
        f.calling_convention = cca.cc
        f.prototype = cca.prototype
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)

        code = dec.codegen.text
        assert "stack_base" not in code, "Some stack variables are not recognized"

        m = re.search(r"strncmp\(a1, \S+, 0x40\)", code)
        assert m is not None
        strncmp_expr = m.group(0)
        strncmp_stmt = strncmp_expr + ";"
        assert strncmp_stmt not in code, "Call expressions folding failed for strncmp()"

        lines = code.split("\n")
        for line in lines:
            if '"%02x"' in line:
                assert "sprintf(" in line
                assert (
                    "v0" in line and "v1" in line and "v2" in line or "v2" in line and "v3" in line and "v4" in line
                ), "Failed to find v0, v1, and v2 in the same line. Is propagator over-propagating?"

        assert "= sprintf" not in code, "Failed to remove the unused return value of sprintf()"

    @for_all_structuring_algos
    def test_decompiling_1after909_doit(self, decompiler_options=None):
        # the doit() function has an abnormal loop at 0x1d47 - 0x1da1 - 0x1d73

        bin_path = os.path.join(test_location, "x86_64", "1after909")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        # doit
        f = cfg.functions["doit"]
        optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            p.arch, p.simos.name
        )
        if angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier not in optimization_passes:
            optimization_passes += [
                angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier,
            ]
        dec = p.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=optimization_passes
        )
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)

        code = dec.codegen.text
        # with EagerReturnSimplifier applied, there should be no goto!
        assert "goto" not in code.lower(), "Found goto statements. EagerReturnSimplifier might have failed."
        # with global variables discovered, there should not be any loads of constant addresses.
        assert "fflush(stdout);" in code.lower()

        assert (
            code.count("access(") == 2
        ), "The decompilation should contain 2 calls to access(), but instead %d calls are present." % code.count(
            "access("
        )

        m = re.search(r"if \([\S]*access\(&[\S]+, [\S]+\) == -1\)", code)
        assert m is not None, "The if branch at 0x401c91 is not found. Structurer is incorrectly removing conditionals."

        # Arguments to the convert call should be fully folded into the call statement itself
        code_lines = [line.strip(" ") for line in code.split("\n")]
        for i, line in enumerate(code_lines):
            if "convert(" in line:
                # the previous line must be a curly brace
                assert i > 0
                assert code_lines[i - 1] == "{", (
                    "Some arguments to convert() are probably not folded into this call " "statement."
                )
                break
        else:
            assert False, "Call to convert() is not found in decompilation output."

        # propagator should not replace stack variables
        assert "free(v" in code
        assert "free(NULL" not in code and "free(0" not in code

        # return values are either 0xffffffff or -1
        assert " = 4294967295;" in code or " = -1;" in code

        # the while loop containing puts("Empty title"); must have both continue and break
        for i, line in enumerate(code_lines):
            if line == 'puts("Empty title");':
                assert "break;" in code_lines[i - 9 : i + 9]
                break
        else:
            assert False, "Did not find statement 'puts(\"Empty title\");'"

    @for_all_structuring_algos
    def test_decompiling_libsoap(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "armel", "libsoap.so")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions[0x41D000]
        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(func)
        self._print_decompilation_result(dec)

    @for_all_structuring_algos
    def test_decompiling_no_arguments_in_variable_list(self, decompiler_options=None):
        # function arguments should never appear in the variable list
        bin_path = os.path.join(test_location, "x86_64", "test_arrays")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions["main"]

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(func)
        self._print_decompilation_result(dec)
        self._print_decompilation_result(dec)
        code = dec.codegen.text
        decls = code.split("\n\n")[0]

        argc_name = " a0"  # update this variable once the decompiler picks up
        # argument names from the common definition of main()
        assert argc_name in decls
        assert code.count(decls) == 1  # it should only appear once

    def test_decompiling_strings_c_representation(self):
        input_expected = [("""Foo"bar""", '"Foo\\"bar"'), ("""Foo'bar""", '"Foo\'bar"')]

        for _input, expected in input_expected:
            result = angr.analyses.decompiler.structured_codegen.c.CConstant.str_to_c_str(_input)
            assert result == expected

    @for_all_structuring_algos
    def test_decompiling_strings_local_strlen(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "types", "strings")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        func = cfg.functions["local_strlen"]

        _ = p.analyses[VariableRecoveryFast].prep()(func)
        cca = p.analyses[CallingConventionAnalysis].prep()(func, cfg=cfg.model)
        func.calling_convention = cca.cc
        func.prototype = cca.prototype

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)

        code = dec.codegen.text
        # Make sure argument a0 is correctly typed to char*
        lines = code.split("\n")
        assert "local_strlen(char *a0)" in lines[0], "Argument a0 seems to be incorrectly typed: %s" % lines[0]

    @for_all_structuring_algos
    def test_decompiling_strings_local_strcat(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "types", "strings")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        func = cfg.functions["local_strcat"]

        _ = p.analyses[VariableRecoveryFast].prep()(func)
        cca = p.analyses[CallingConventionAnalysis].prep()(func, cfg=cfg.model)
        func.calling_convention = cca.cc
        func.prototype = cca.prototype

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)

        code = dec.codegen.text
        # Make sure argument a0 is correctly typed to char*
        lines = code.split("\n")
        assert "local_strcat(char *a0, char *a1)" in lines[0], (
            "Argument a0 and a1 seem to be incorrectly typed: %s" % lines[0]
        )

    @for_all_structuring_algos
    def test_decompiling_strings_local_strcat_with_local_strlen(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "types", "strings")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        func_strlen = cfg.functions["local_strlen"]
        _ = p.analyses[VariableRecoveryFast].prep()(func_strlen)
        cca = p.analyses[CallingConventionAnalysis].prep()(func_strlen, cfg=cfg.model)
        func_strlen.calling_convention = cca.cc
        func_strlen.prototype = cca.prototype
        p.analyses[Decompiler].prep()(func_strlen, cfg=cfg.model, options=decompiler_options)

        func = cfg.functions["local_strcat"]

        _ = p.analyses[VariableRecoveryFast].prep()(func)
        cca = p.analyses[CallingConventionAnalysis].prep()(func, cfg=cfg.model)
        func.calling_convention = cca.cc
        func.prototype = cca.prototype

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)

        code = dec.codegen.text
        # Make sure argument a0 is correctly typed to char*
        lines = code.split("\n")
        assert "local_strcat(char *a0, char *a1)" in lines[0], (
            "Argument a0 and a1 seem to be incorrectly typed: %s" % lines[0]
        )

    @for_all_structuring_algos
    def test_decompilation_call_expr_folding(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "call_expr_folding")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func_0 = cfg.functions["strlen_should_fold"]
        opt = [o for o in angr.analyses.decompiler.decompilation_options.options if o.param == "remove_dead_memdefs"][0]
        opt_selection = [(opt, True)]
        options = opt_selection if not decompiler_options else opt_selection + decompiler_options
        dec = p.analyses[Decompiler].prep()(func_0, cfg=cfg.model, options=options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func_0
        self._print_decompilation_result(dec)

        code = dec.codegen.text
        m = re.search(r"v(\d+) = (\(.*\))?strlen\(&v(\d+)\);", code)  # e.g., s_428 = (int)strlen(&s_418);
        assert m is not None, (
            "The result of strlen() should be directly assigned to a stack "
            "variable because of call-expression folding."
        )
        assert m.group(1) != m.group(2)

        func_1 = cfg.functions["strlen_should_not_fold"]
        dec = p.analyses[Decompiler].prep()(func_1, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(dec)
        code = dec.codegen.text
        assert code.count("strlen(") == 1

        func_2 = cfg.functions["strlen_should_not_fold_into_loop"]
        dec = p.analyses[Decompiler].prep()(func_2, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(dec)
        code = dec.codegen.text
        assert code.count("strlen(") == 1

    @for_all_structuring_algos
    def test_decompilation_call_expr_folding_mips64_true(self, decompiler_options=None):
        # This test is to ensure call expression folding correctly replaces call expressions in return statements
        bin_path = os.path.join(test_location, "mips64", "true")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func_0 = cfg.functions["version_etc"]
        dec = p.analyses[Decompiler].prep()(func_0, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func_0
        l.debug("Decompiled function %s\n%s", repr(func_0), dec.codegen.text)

        code = dec.codegen.text
        assert "version_etc_va(" in code

    @for_all_structuring_algos
    def test_decompilation_call_expr_folding_x8664_calc(self, decompiler_options=None):
        # This test is to ensure call expression folding do not re-use out-dated definitions when folding expressions
        bin_path = os.path.join(test_location, "x86_64", "calc")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        # unfortunately we cannot correctly figure out the calling convention of "root" by just analyzing the call
        # site... yet
        p.analyses[CompleteCallingConventionsAnalysis].prep()(cfg=cfg.model, recover_variables=True)

        func_0 = cfg.functions["main"]
        dec = p.analyses[Decompiler].prep()(func_0, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func_0
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        assert "root(" in code
        assert "strlen(" in code  # incorrect call expression folding would
        # fold root() into printf() and remove strlen()
        assert "printf(" in code

        lines = code.split("\n")
        # make sure root() and strlen() appear within the same line
        for line in lines:
            if "root(" in line:
                assert "strlen(" in line
                assert line.count("strlen") == 1

    @structuring_algo("phoenix")
    def test_decompilation_call_expr_folding_into_if_conditions(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "stat.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["find_bind_mount"]

        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        m = re.search(
            r"if \([^\n]+ == 47 "
            r"&& strcmp\([^\n]+\) == 0 "
            r"&& stat\([^\n]+\) == 0 "
            r"&& [^\n]+ == [^\n]+ "
            r"&& [^\n]+ == [^\n]+\)",
            d.codegen.text,
        )
        assert m is not None

    @for_all_structuring_algos
    def test_decompilation_excessive_condition_removal(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "bf")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions[0x100003890]

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        code = code.replace(" ", "").replace("\n", "")
        # s_1a += 1 should not be wrapped inside any if-statements. it is always reachable.
        assert "}v4+=1;}" in code or "}v4+=0x1;}" in code

    @for_all_structuring_algos
    def test_decompilation_excessive_goto_removal(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "bf")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions[0x100003890]

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)

        code = dec.codegen.text

        assert "goto" not in code

    @for_all_structuring_algos
    def test_decompilation_switch_case_structuring_with_removed_nodes(self, decompiler_options=None):
        # Some jump table entries are fully folded into their successors. Structurer should be able to handle this case.
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "union")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions["build_date"]
        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        n = code.count("switch")
        assert n == 2, f"Expect two switch-case constructs, only found {n} instead."

    @for_all_structuring_algos
    def test_decompilation_x86_64_stack_arguments(self, decompiler_options=None):
        # Arguments passed on the stack should not go missing
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "union")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions["build_date"]

        # no dead memdef removal
        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        lines = code.split("\n")
        for line in lines:
            if "snprintf" in line:
                # The line should look like this:
                #   v0 = (int)snprintf(v32[8], (v43 + 0x1) * 0x2 + 0x1a, "%s, %.2d %s %d %.2d:%.2d:%.2d GMT\r\n", &v34,
                #   ((long long)v35), &v33, ((long long)v36 + 1900), ((long long)v35), ((long long)v35),
                #   ((long long)v35));
                assert line.count(",") == 10, "There is a missing stack argument."
                break
        else:
            assert False, "The line with snprintf() is not found."

        # with dead memdef removal
        opt = [o for o in angr.analyses.decompiler.decompilation_options.options if o.param == "remove_dead_memdefs"][0]
        # kill the cache since variables to statements won't match any more - variables are re-discovered with the new
        # option.
        p.kb.structured_code.cached.clear()
        options = [(opt, True)] if not decompiler_options else [(opt, True)] + decompiler_options
        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        lines = code.split("\n")
        for line in lines:
            if "snprintf" in line:
                # The line should look like this:
                #   v0 = (int)snprintf(v32[8], (v43 + 0x1) * 0x2 + 0x1a, "%s, %.2d %s %d %.2d:%.2d:%.2d GMT\r\n", &v34,
                #   ((long long)v35), &v33, ((long long)v36 + 1900), ((long long)v35), ((long long)v35),
                #   ((long long)v35));
                assert line.count(",") == 10, "There is a missing stack argument."
                break
        else:
            assert False, "The line with snprintf() is not found."

    @for_all_structuring_algos
    def test_decompiling_amp_challenge03_arm(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "armhf", "decompiler", "challenge_03")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        func = cfg.functions["main"]

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        # make sure there are no empty code blocks
        code = code.replace(" ", "").replace("\n", "")
        assert "{}" not in code, (
            "Found empty code blocks in decompilation output. This may indicate some "
            "assignments are incorrectly removed."
        )
        assert '"o"' in code and '"x"' in code, "CFG failed to recognize single-byte strings."

    @for_all_structuring_algos
    def test_decompiling_amp_challenge03_arm_expr_swapping(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "armhf", "decompiler", "challenge_03")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        func = cfg.functions["main"]

        binop_operators = {OpDescriptor(0x400A1D, 0, 0x400A27, "CmpGT"): "CmpLE"}
        dec = p.analyses[Decompiler].prep()(
            func, cfg=cfg.model, options=decompiler_options, binop_operators=binop_operators
        )
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        # make sure there are no empty code blocks
        lines = [line.strip(" ") for line in code.split("\n")]
        #   v25 = select(v27, &stack_base-200, NULL, NULL, &v19);
        select_var = None
        select_line = None
        for idx, line in enumerate(lines):
            m = re.search(r"(v\d+) = select\(v", line)
            if m is not None:
                select_line = idx
                select_var = m.group(1)
                break

        assert select_var, "Failed to find the variable that stores the result from select()"
        #   if (0 <= v25)
        next_line = lines[select_line + 1]
        assert next_line.startswith(f"if (0 <= {select_var})")

    @for_all_structuring_algos
    def test_decompiling_fauxware_mipsel(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "mipsel", "fauxware")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        func = cfg.functions["main"]

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        # The function calls must be correctly decompiled
        assert "puts(" in code
        assert "read(" in code
        assert "authenticate(" in code
        # The string references must be correctly recovered
        assert '"Username: "' in code
        assert '"Password: "' in code

    @for_all_structuring_algos
    def test_stack_canary_removal_x8664_extra_exits(self, decompiler_options=None):
        # Test stack canary removal on functions with extra exit
        # nodes (e.g., assert(false);) without stack canary checks
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "babyheap_level1_teaching1")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        func = cfg.functions["main"]

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        # We should not find "__stack_chk_fail" in the code
        assert "__stack_chk_fail" not in code

    @for_all_structuring_algos
    def test_ifelseif_x8664(self, decompiler_options=None):
        # nested if-else should be transformed to cascading if-elseif constructs
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "babyheap_level1_teaching1")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        func = cfg.functions["main"]

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        # it should make somewhat sense
        assert 'printf("[*] flag_buffer = malloc(%d)\\n",' in code

        if decompiler_options and decompiler_options[-1][-1] == "dream":
            assert code.count("else if") == 3

    @for_all_structuring_algos
    def test_decompiling_missing_function_call(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "adams")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        func = cfg.functions["main"]

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        # the call to fileno() should not go missing
        assert code.count("fileno") == 1

        code_without_spaces = code.replace(" ", "").replace("\n", "")
        # make sure all break statements are followed by either "case " or "}"
        replaced = code_without_spaces.replace("break;case", "")
        replaced = replaced.replace("break;default:", "")
        replaced = replaced.replace("break;}", "")
        assert "break" not in replaced

        # ensure if-else removal does not incorrectly remove else nodes
        assert "emaillist=strdup(" in code_without_spaces

    @for_all_structuring_algos
    def test_decompiling_morton_my_message_callback(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "morton")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions["my_message_callback"]

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        # we should not propagate generate_random() calls into function arguments without removing the original call
        # statement.
        assert code.count("generate_random(") == 3
        # we should be able to correctly figure out all arguments for mosquitto_publish() by analyzing call sites
        assert code.count("mosquitto_publish()") == 0
        assert code.count("mosquitto_publish(") == 6

    @for_all_structuring_algos
    def test_decompiling_morton_lib_handle__suback(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "morton.libmosquitto.so.1")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions.function(name="handle__suback", plt=False)

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        assert "__stack_chk_fail" not in code  # stack canary checks should be removed by default

    @for_all_structuring_algos
    def test_decompiling_newburry_main(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "newbury")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep(show_progressbar=not WORKER)(data_references=True, normalize=True)

        func = cfg.functions["main"]

        dec = p.analyses[Decompiler].prep(show_progressbar=not WORKER)(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        # return statements should not be wrapped into a for statement
        assert re.search(r"for[^\n]*return[^\n]*;", code) is None

    @for_all_structuring_algos
    def test_single_instruction_loop(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "level_12_teaching")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions["main"]

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=decompiler_options)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        code_without_spaces = code.replace(" ", "").replace("\n", "")
        assert "while(true" not in code_without_spaces
        assert "for(" in code_without_spaces
        m = re.search(r"if\([^=]+==0\)", code_without_spaces)
        assert m is None

    @for_all_structuring_algos
    def test_simple_strcpy(self, decompiler_options=None):
        """
        Original C: while (( *dst++ = *src++ ));
        Ensures incremented src and dst are not accidentally used in copy statement.
        """
        bin_path = os.path.join(test_location, "x86_64", "test_simple_strcpy")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses.CFGFast(normalize=True)

        f = p.kb.functions["simple_strcpy"]
        d = p.analyses.Decompiler(f, cfg=cfg.model, options=decompiler_options)
        assert d.codegen is not None, "Failed to decompile function %r." % f
        self._print_decompilation_result(d)
        dw = d.codegen.cfunc.statements.statements[1]
        assert isinstance(dw, angr.analyses.decompiler.structured_codegen.c.CDoWhileLoop)
        stmts = dw.body.statements
        assert len(stmts) == 5
        assert stmts[1].lhs.unified_variable == stmts[0].rhs.unified_variable
        assert stmts[3].lhs.unified_variable == stmts[2].rhs.unified_variable
        assert stmts[4].lhs.operand.variable == stmts[2].lhs.variable
        assert stmts[4].rhs.operand.variable == stmts[0].lhs.variable
        assert dw.condition.lhs.operand.variable == stmts[2].lhs.variable

    @for_all_structuring_algos
    def test_decompiling_nl_i386_pie(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "i386", "nl")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses.CFGFast(normalize=True)

        f = p.kb.functions["usage"]
        d = p.analyses.Decompiler(f, cfg=cfg.model, options=decompiler_options)
        assert d.codegen is not None, "Failed to decompile function %r." % f
        self._print_decompilation_result(d)

        assert '"Usage: %s [OPTION]... [FILE]...\\n"' in d.codegen.text
        assert (
            '"Write each FILE to standard output, with line numbers added.\\nWith no FILE, or when FILE is -,'
            ' read standard input.\\n\\n"' in d.codegen.text
        )
        assert "\"For complete documentation, run: info coreutils '%s invocation'\\n\"" in d.codegen.text

    @for_all_structuring_algos
    def test_decompiling_x8664_cvs(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "cvs")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses.CFGFast(normalize=True, show_progressbar=not WORKER)

        f = p.kb.functions["main"]
        d = p.analyses.Decompiler(f, cfg=cfg.model, options=decompiler_options, show_progressbar=not WORKER)
        assert d.codegen is not None, "Failed to decompile function %r." % f
        self._print_decompilation_result(d)

        # at the very least, it should decompile within a reasonable amount of time...
        # the switch-case must be recovered
        assert "switch (" in d.codegen.text

    @for_all_structuring_algos
    def test_decompiling_short_circuit_O0_func_1(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "short_circuit_O0")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses.CFGFast(normalize=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes = [
            p
            for p in all_optimization_passes
            if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier
        ]

        f = p.kb.functions["func_1"]
        d = p.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        assert d.codegen is not None, "Failed to decompile function %r." % f
        self._print_decompilation_result(d)

        assert "goto" not in d.codegen.text

    @for_all_structuring_algos
    def test_decompiling_short_circuit_O0_func_2(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "short_circuit_O0")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses.CFGFast(normalize=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes = [
            p
            for p in all_optimization_passes
            if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier
        ]

        f = p.kb.functions["func_2"]
        d = p.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        assert d.codegen is not None, "Failed to decompile function %r." % f
        self._print_decompilation_result(d)

        assert "goto" not in d.codegen.text

    @for_all_structuring_algos
    def test_decompiling_x8664_mv_O2(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "mv_-O2")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses.CFGFast(normalize=True, show_progressbar=not WORKER)

        f = p.kb.functions["main"]
        d = p.analyses.Decompiler(f, cfg=cfg.model, options=decompiler_options, show_progressbar=not WORKER)
        self._print_decompilation_result(d)

        assert "(False)" not in d.codegen.text
        assert "None" not in d.codegen.text

    @for_all_structuring_algos
    def test_extern_decl(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "test_gdb_plugin")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses.CFGFast(normalize=True)

        f = p.kb.functions["set_globals"]
        d = p.analyses.Decompiler(f, cfg=cfg.model, options=decompiler_options)
        l.debug("Decompiled function %s\n%s", repr(f), d.codegen.text)

        assert "extern unsigned int a;" in d.codegen.text
        assert "extern unsigned int b;" in d.codegen.text
        assert "extern unsigned int c;" in d.codegen.text

    @for_all_structuring_algos
    def test_decompiling_amp_challenge_07(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "armhf", "amp_challenge_07.gcc.dyn.unstripped")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions[0x401865]
        proj.analyses.VariableRecoveryFast(f)
        cca = proj.analyses.CallingConvention(f)
        f.prototype = cca.prototype
        f.calling_convention = cca.cc

        d = proj.analyses.Decompiler(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        # make sure the types of extern variables are correct
        assert "extern char num_connections;" in d.codegen.text
        assert "extern char num_packets;" in d.codegen.text
        assert "extern char src;" in d.codegen.text

        lines = [line.strip(" ") for line in d.codegen.text.split("\n")]

        # make sure the line with printf("Recieved packet %d for connection with %d\n"...) does not have
        # "v23->field_5 + 1". otherwise it's an incorrect variable folding result
        line_0s = [line for line in lines if "printf(" in line and "Recieved packet %d for connection with %d" in line]
        assert len(line_0s) == 1
        line_0 = line_0s[0].replace(" ", "")
        assert "+1" not in line_0

        # make sure v % 7 is present
        line_assignment_mod_7 = [line for line in lines if re.search(r"v\d+ = v\d+ % 7", line)]
        assert len(line_assignment_mod_7) == 1
        line_mod_7 = [line for line in lines if re.search(r"v\d+ % 7", line)]
        assert len(line_mod_7) == 2

    @for_all_structuring_algos
    def test_decompiling_fmt_get_space(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "fmt")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions[0x4020F0]
        proj.analyses.VariableRecoveryFast(f)
        cca = proj.analyses.CallingConvention(f)
        f.prototype = cca.prototype
        f.calling_convention = cca.cc

        d = proj.analyses.Decompiler(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        assert "break" in d.codegen.text

    @for_all_structuring_algos
    def test_decompiling_fmt_main(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "fmt")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        xdectoumax = proj.kb.functions[0x406010]
        proj.analyses.VariableRecoveryFast(xdectoumax)
        cca = proj.analyses.CallingConvention(xdectoumax)
        xdectoumax.prototype = cca.prototype
        xdectoumax.calling_convention = cca.cc
        assert isinstance(xdectoumax.prototype.returnty, SimTypeInt)

        f = proj.kb.functions[0x401900]
        proj.analyses.VariableRecoveryFast(f)
        cca = proj.analyses.CallingConvention(f)
        f.prototype = cca.prototype
        f.calling_convention = cca.cc

        d = proj.analyses.Decompiler(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        # function arguments must be a0 and a1. they cannot be renamed
        assert re.search(r"int main\([\s\S]+ a0, [\s\S]+a1\)", d.codegen.text) is not None

        assert "max_width = (int)xdectoumax(" in d.codegen.text or "max_width = xdectoumax(" in d.codegen.text
        assert "goal_width = xdectoumax(" in d.codegen.text
        assert (
            "max_width = goal_width + 10;" in d.codegen.text
            or "max_width = ((int)(goal_width + 10));" in d.codegen.text
        )

        # by default, largest_successor_tree_outside_loop in RegionIdentifier is set to True, which means the
        # getopt_long() == -1 case should be entirely left outside the loop. by ensuring the call to error(0x1) is
        # within the last few lines of decompilation output, we ensure the -1 case is indeed outside the loop.
        last_three_lines = "\n".join(line.strip(" ") for line in d.codegen.text.split("\n")[-4:])
        assert 'error(0x1, *(__errno_location()), "%s");' in last_three_lines

    @for_all_structuring_algos
    def test_decompiling_fmt0_main(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "fmt_0")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["main"]
        proj.analyses.VariableRecoveryFast(f)
        cca = proj.analyses.CallingConvention(f)
        f.prototype = cca.prototype
        f.calling_convention = cca.cc

        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        # ensure the default case node is not duplicated
        cases = set(re.findall(r"case \d+:", d.codegen.text))
        assert cases.issuperset(
            {"case 99:", "case 103:", "case 112:", "case 115:", "case 116:", "case 117:", "case 119:"}
        )

    @for_all_structuring_algos
    def test_expr_collapsing(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "deep_expr")
        proj = angr.Project(bin_path, auto_load_libs=False)

        proj.analyses.CFGFast(normalize=True)
        d = proj.analyses.Decompiler(proj.kb.functions["main"], options=decompiler_options)
        assert "..." in d.codegen.text, "codegen should have a too-deep expression replaced with '...'"
        collapsed = d.codegen.map_pos_to_node.get_node(d.codegen.text.find("..."))
        assert collapsed is not None, "collapsed node should appear in map"
        assert collapsed.collapsed, "collapsed node should be marked as collapsed"
        collapsed.collapsed = False
        old_len = len(d.codegen.text)
        d.codegen.regenerate_text()
        new_len = len(d.codegen.text)
        assert new_len > old_len, "un-collapsing node should expand decompilation output"

    @for_all_structuring_algos
    def test_decompiling_dirname_x2nrealloc(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "dirname")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["x2nrealloc"]

        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        assert "__CFADD__" in d.codegen.text

    @for_all_structuring_algos
    def test_decompiling_division3(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "i386", "decompiler", "division3")
        proj = angr.Project(bin_path, auto_load_libs=False)

        proj.analyses.CFGFast(normalize=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes = [
            p
            for p in all_optimization_passes
            if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier
        ]
        d = proj.analyses.Decompiler(
            proj.kb.functions["division3"], optimization_passes=all_optimization_passes, options=decompiler_options
        )
        self._print_decompilation_result(d)

        # get the returned expression from the return statement
        # e.g., retexpr will be "v2" if the return statement is "  return v2;"
        lines = d.codegen.text.split("\n")
        retexpr = [line for line in lines if "return " in line][0].strip(" ;")[7:]

        # find the statement "v2 = v0 / 3"
        div3 = [line for line in lines if re.match(retexpr + r" = v\d+ / 3;", line.strip(" ")) is not None]
        assert len(div3) == 1, f"Cannot find statement {retexpr} = v0 / 3."
        # find the statement "v2 = v0 * 7"
        mul7 = [line for line in lines if re.match(retexpr + r" = v\d+ \* 7;", line.strip(" ")) is not None]
        assert len(mul7) == 1, f"Cannot find statement {retexpr} = v0 * 7."

    # @for_all_structuring_algos
    @structuring_algo("dream")
    def test_decompiling_dirname_quotearg_n_options(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "dirname")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["quotearg_n_options"]

        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

    @for_all_structuring_algos
    def test_decompiling_simple_ctfbin_modulo(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "simple_ctfbin_modulo")
        proj = angr.Project(bin_path, auto_load_libs=False)

        proj.analyses.CFGFast(normalize=True)

        d = proj.analyses.Decompiler(proj.kb.functions["encrypt"], options=decompiler_options)
        self._print_decompilation_result(d)

        assert "% 61" in d.codegen.text, "Modulo simplification failed."

    @for_all_structuring_algos
    def test_struct_access(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "struct_access")
        proj = angr.Project(bin_path, auto_load_libs=False)

        proj.analyses.CFGFast(normalize=True)

        typedefs = angr.sim_type.parse_file(
            """
        struct A {
            int a1;
            int a2;
            int a3;
        };

        struct B {
            struct A b1;
            struct A b2;
        };

        struct C {
            int c1;
            struct B c2[10];
            int c3[10];
            struct C *c4;
        };
        """
        )

        d = proj.analyses.Decompiler(proj.kb.functions["main"], options=decompiler_options)
        vmi: VariableManagerInternal = d.cache.clinic.variable_kb.variables["main"]
        vmi.set_variable_type(
            next(iter(vmi.find_variables_by_stack_offset(-0x148))),
            SimTypePointer(typedefs[1]["struct C"]),
            all_unified=True,
            mark_manual=True,
        )
        unified = vmi.unified_variable(next(iter(vmi.find_variables_by_stack_offset(-0x148))))
        unified.name = "c_ptr"
        unified.renamed = True

        vmi.set_variable_type(
            next(iter(vmi.find_variables_by_stack_offset(-0x140))),
            SimTypePointer(typedefs[1]["struct B"]),
            all_unified=True,
            mark_manual=True,
        )
        unified = vmi.unified_variable(next(iter(vmi.find_variables_by_stack_offset(-0x140))))
        unified.name = "b_ptr"
        unified.renamed = True

        # NOTE TO WHOEVER SEES THIS
        # this is an INCOMPLETE way to set the type of an argument
        # you also need to change the function prototype
        vmi.set_variable_type(
            next(iter(vmi.find_variables_by_register("rdi"))), SimTypeInt(), all_unified=True, mark_manual=True
        )
        unified = vmi.unified_variable(next(iter(vmi.find_variables_by_register("rdi"))))
        unified.name = "argc"
        unified.renamed = True

        d = proj.analyses.Decompiler(
            proj.kb.functions["main"], variable_kb=d.cache.clinic.variable_kb, options=decompiler_options
        )
        self._print_decompilation_result(d)

        # TODO c_val
        assert "b_ptr = &c_ptr->c2[argc];" in d.codegen.text
        assert "c_ptr->c3[argc] = argc;" in d.codegen.text
        assert "c_ptr->c2[argc].b2.a2 = argc;" in d.codegen.text
        assert "b_ptr = &b_ptr[1];" in d.codegen.text
        assert "return c_ptr->c4->c2[argc].b2.a2;" in d.codegen.text

    @for_all_structuring_algos
    def test_call_return_variable_folding(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "ls_gcc_O0")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg, recover_variables=True)

        dec = proj.analyses.Decompiler(proj.kb.functions["print_long_format"], options=decompiler_options)
        self._print_decompilation_result(dec)

        assert "if (timespec_cmp(" in dec.codegen.text or "if ((int)timespec_cmp(" in dec.codegen.text
        assert "&& localtime_rz(localtz, " in dec.codegen.text

    @structuring_algo("phoenix")
    def test_cascading_boolean_and(self, decompiler_options=None):
        # test binary contributed by zion
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "test_cascading_boolean_and")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes = [
            p
            for p in all_optimization_passes
            if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier
        ]

        dec = proj.analyses.Decompiler(
            proj.kb.functions["foo"], cfg=cfg, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        self._print_decompilation_result(dec)
        assert dec.codegen.text.count("goto") == 1  # should have only one goto

    @for_all_structuring_algos
    def test_decompiling_tee_O2_x2nrealloc(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "tee_O2")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["x2nrealloc"]

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes = [
            p
            for p in all_optimization_passes
            if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier
        ]

        d = proj.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        self._print_decompilation_result(d)

        # ensure xalloc_die() is within its own block
        lines = [line.strip("\n ") for line in d.codegen.text.split("\n")]
        for i, line in enumerate(lines):
            if line.startswith("xalloc_die();"):
                assert lines[i - 1] == "{"
                assert lines[i + 1] == "}"
                break
        else:
            assert False, "xalloc_die() is not found"

    @for_all_structuring_algos
    def test_decompiling_mv0_main(self, decompiler_options=None):
        # one of the jump tables has an entry that goes back to the loop head
        bin_path = os.path.join(test_location, "x86_64", "mv_0")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["main"]

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes = [
            p
            for p in all_optimization_passes
            if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier
        ]

        d = proj.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        self._print_decompilation_result(d)

    @for_all_structuring_algos
    def test_decompiling_dirname_last_component_missing_loop(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "dirname")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["last_component"]

        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        assert d.codegen.text.count("for (") == 2  # two loops

    @for_all_structuring_algos
    def test_decompiling_tee_O2_tail_jumps(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "tee_O2")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        # argmatch_die
        f = proj.kb.functions["__argmatch_die"]
        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)
        assert "usage(" in d.codegen.text

        # setlocale_null_androidfix
        f = proj.kb.functions["setlocale_null_androidfix"]
        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)
        assert "setlocale(" in d.codegen.text
        assert "NULL);" in d.codegen.text, "The arguments for setlocale() are missing"

    @for_all_structuring_algos
    def test_decompiling_du_di_set_alloc(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "du")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["di_set_alloc"]

        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        # addresses in function pointers should be correctly resolved into function pointers
        assert "&di_ent_hash" in d.codegen.text
        assert "&di_ent_compare" in d.codegen.text
        assert "&di_ent_free" in d.codegen.text

    @for_all_structuring_algos
    def test_decompiling_du_humblock_missing_conditions(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "du")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["humblock"]

        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        assert d.codegen.text.count("if (v0 == 0)") == 3 or d.codegen.text.count("if (v0 != 0)") == 3
        assert d.codegen.text.count("break;") > 0

    @structuring_algo("phoenix")
    def test_decompiling_setb(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "basenc")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["c_isupper"]
        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        assert f.prototype.returnty is not None and f.prototype.returnty.size == 8
        assert "a0 - 65 < 26;" in d.codegen.text

    @for_all_structuring_algos
    def test_decompiling_tac_base_len(self, decompiler_options=None):
        # source: https://github.com/coreutils/gnulib/blob/08ba9aaebff69a02cbb794c6213314fd09dd5ec5/lib/basename-lgpl.c#L52
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "tac")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["base_len"]
        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        spaceless_text = d.codegen.text.replace(" ", "").replace("\n", "")
        assert "==47" in spaceless_text or "!=47" in spaceless_text

    @for_all_structuring_algos
    def test_decompiling_dd_argmatch_to_argument_noeagerreturns(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "dd")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64",
            "linux",
        )
        all_optimization_passes = [
            p
            for p in all_optimization_passes
            if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier
        ]

        f = proj.kb.functions["argmatch_to_argument"]
        d = proj.analyses[Decompiler].prep()(
            f,
            cfg=cfg.model,
            options=decompiler_options,
            optimization_passes=all_optimization_passes,
        )
        self._print_decompilation_result(d)

        # break should always be followed by a curly brace, not another statement
        t = d.codegen.text.replace(" ", "").replace("\n", "")
        if "break;" in t:
            assert "break;}" in t
            t = t.replace("break;}", "")
            assert "break;" not in t

        # continue should always be followed by a curly brace, not another statement
        if "continue;" in t:
            assert "continue;}" in t
            t = t.replace("continue;}", "")
            assert "continue;" not in t

    @for_all_structuring_algos
    def test_decompiling_dd_argmatch_to_argument_eagerreturns(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "dd")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["argmatch_to_argument"]
        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        # return should always be followed by a curly brace, not another statement
        t = d.codegen.text.replace(" ", "").replace("\n", "")
        return_stmt_ctr = 0
        for m in re.finditer(r"return[^;]+;", t):
            return_stmt_ctr += 1
            assert t[m.start() + len(m.group(0))] == "}"

        if return_stmt_ctr == 0:
            assert False, "Cannot find any return statements."

        # continue should always be followed by a curly brace, not another statement
        if "continue;}" in t:
            t = t.replace("continue;}", "")
            assert "continue;" not in t

    @for_all_structuring_algos
    def test_decompiling_remove_write_protected_non_symlink(self, decompiler_options=None):
        # labels test
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "remove.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["write_protected_non_symlink"]
        proj.analyses.CompleteCallingConventions(cfg=cfg, recover_variables=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes = [
            p
            for p in all_optimization_passes
            if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier
        ]

        d = proj.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        self._print_decompilation_result(d)

        assert "faccessat(" in d.codegen.text
        if decompiler_options:
            if decompiler_options[-1][-1] == "phoenix":
                # make sure there is one label
                all_labels = set()
                all_gotos = set()
                for m in re.finditer(r"LABEL_[^:;]+:", d.codegen.text):
                    all_labels.add(m.group(0)[:-1])
                for m in re.finditer(r"goto ([^;]+);", d.codegen.text):
                    all_gotos.add(m.group(1))
                assert len(all_labels) == 1
                assert len(all_gotos) == 1
                assert all_labels == all_gotos
            else:
                # dream
                assert "LABEL_" not in d.codegen.text
                assert "goto" not in d.codegen.text

    @structuring_algo("phoenix")
    def test_decompiling_split_lines_split(self, decompiler_options=None):
        # Region identifier's fine-tuned loop refinement logic ensures there is only one goto statement in the
        # decompilation output.
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "split.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["lines_split"]

        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        assert d.codegen.text.count("goto ") == 1

    @structuring_algo("phoenix")
    def test_decompiling_ptx_fix_output_parameters(self, decompiler_options=None):
        # the carefully tuned edge sorting logic in Phoenix's last_resort_refinement ensures that there are one or two
        # goto statements in this function.
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "ptx.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["fix_output_parameters"]

        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        assert len(list(re.findall(r"LABEL_[^;:]+:", d.codegen.text))) in {1, 2}

    @structuring_algo("phoenix")
    def test_decompiling_dd_advance_input_after_read_error(self, decompiler_options=None):
        # incorrect _unify_local_variables logic was creating incorrectly simplified logic:
        #
        #   *(v2) = input_seek_errno;
        #   v2 = __errno_location();
        #
        # it should be
        #
        #   v2 = __errno_location();
        #   *(v2) = input_seek_errno;
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "dd.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["advance_input_after_read_error"]

        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        condensed = d.codegen.text.replace(" ", "").replace("\n", "")
        assert re.search(r"v\d=__errno_location\(\);\*\(v\d\)=input_seek_errno;", condensed)

    @for_all_structuring_algos
    def test_decompiling_prototype_recovery_two_blocks(self, decompiler_options=None):
        # we must analyze both 0x40021d and 0x400225 to determine the prototype of xstrtol
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "stty.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["screen_columns"]

        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)

        assert proj.kb.functions["xstrtol"].prototype is not None
        assert proj.kb.functions["xstrtol"].prototype.args is not None
        assert len(proj.kb.functions["xstrtol"].prototype.args) == 5
        assert re.search(r"xstrtol\([^\n,]+, [^\n,]+, [^\n,]+, [^\n,]+, [^\n,]+\)", d.codegen.text) is not None

    @for_all_structuring_algos
    def test_decompiling_base32_basenc_do_decode(self, decompiler_options=None):
        # if region identifier works correctly, there should be no gotos
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "base32-basenc.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["do_decode"]
        proj.analyses.CompleteCallingConventions(cfg=cfg, recover_variables=True)

        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        assert "finish_and_exit(" in d.codegen.text
        assert "goto" not in d.codegen.text

    @structuring_algo("phoenix")
    def test_decompiling_sort_specify_nmerge(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "sort.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        f = proj.kb.functions["specify_nmerge"]
        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        assert "goto" not in d.codegen.text

    @structuring_algo("phoenix")
    def test_decompiling_ls_print_many_per_line(self, decompiler_options=None):
        # complex variable types involved. a struct with only one field was causing _access() in
        # CStructuredCodeGenerator to end up in an infinite loop.
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "ls.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        f = proj.kb.functions["print_many_per_line"]
        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        # it should make somewhat sense
        assert "calculate_columns(" in d.codegen.text
        assert "putchar_unlocked(eolbyte)" in d.codegen.text

    @structuring_algo("phoenix")
    def test_decompiling_who_scan_entries(self, decompiler_options=None):
        # order of edge virtualization matters. suboptimal order will lead to more gotos.
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "who.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        f = proj.kb.functions["scan_entries"]
        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        # it should make somewhat sense
        assert d.codegen.text.count("goto ") == 1

    @structuring_algo("phoenix")
    def test_decompiling_tr_build_spec_list(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "tr.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["build_spec_list"]
        proj.analyses.CompleteCallingConventions(cfg=cfg, recover_variables=True)

        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        # lowered-switch simplifier cannot be enabled. otherwise we will have an extra goto that goes into the fake
        # switch-case.

        # also, setting max_level to 3 in EagerReturnsSimplifier will eliminate the other unexpected goto

        d = proj.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        self._print_decompilation_result(d)

        assert d.codegen.text.count("goto ") == 3
        assert d.codegen.text.count("goto LABEL_400d08;") == 2
        # goto 400e40 this is the fake goto that can be eliminated if cross-jumping reverter is present
        assert d.codegen.text.count("goto LABEL_400e40;") == 1

    @structuring_algo("phoenix")
    def test_decompiling_sha384sum_digest_bsd_split_3(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "sha384sum-digest.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["bsd_split_3"]
        proj.analyses.CompleteCallingConventions(cfg=cfg, recover_variables=True)

        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes = [
            p
            for p in all_optimization_passes
            if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier
        ]
        d = proj.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        self._print_decompilation_result(d)

        # there should only be two or even fewer gotos
        assert d.codegen.text.count("goto ") == 2

    @for_all_structuring_algos
    def test_eliminating_stack_canary_reused_stack_chk_fail_call(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "cksum-digest.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        f = proj.kb.functions["split_3"]
        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        assert "return " in d.codegen.text
        assert "stack_chk_fail" not in d.codegen.text

    @structuring_algo("phoenix")
    def test_decompiling_tr_card_of_complement(self, decompiler_options=None):
        # this function has a single-block loop (rep stosq). make sure we handle properly without introducing gotos.
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "tr.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        f = proj.kb.functions["card_of_complement"]
        d = proj.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        self._print_decompilation_result(d)
        assert "goto " not in d.codegen.text

    @structuring_algo("phoenix")
    def test_decompiling_printenv_main(self, decompiler_options=None):
        # when a subgraph inside a loop cannot be structured, instead of entering last-resort refinement, we should
        # return the subgraph and let structuring resume with the knowledge of the loop.
        # otherwise, in this function, we will see a goto while in reality we do not need any gotos.
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "printenv.o")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        f = proj.kb.functions["main"]
        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)
        assert "goto " not in d.codegen.text

    @structuring_algo("phoenix")
    def test_reverting_switch_lowering_cksum_digest_print_filename(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "cksum-digest.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes += [angr.analyses.decompiler.optimization_passes.LoweredSwitchSimplifier]

        f = proj.kb.functions["print_filename"]
        d = proj.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        self._print_decompilation_result(d)

        assert "switch" in d.codegen.text
        assert "case 10:" in d.codegen.text
        assert "case 13:" in d.codegen.text
        assert "case 92:" in d.codegen.text
        assert "default:" in d.codegen.text
        assert "goto" not in d.codegen.text

    @structuring_algo("phoenix")
    def test_reverting_switch_lowering_cksum_digest_main(self, decompiler_options=None):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "cksum-digest.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes += [angr.analyses.decompiler.optimization_passes.LoweredSwitchSimplifier]

        f = proj.kb.functions["main"]
        d = proj.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        self._print_decompilation_result(d)

        assert "case 4294967165:" in d.codegen.text
        assert "case 4294967166:" in d.codegen.text

    @structuring_algo("phoenix")
    def test_reverting_switch_lowering_filename_unescape(self, decompiler_options=None):
        # nested switch-cases
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "b2sum-digest.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes += [angr.analyses.decompiler.optimization_passes.LoweredSwitchSimplifier]

        f = proj.kb.functions["filename_unescape"]
        d = proj.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        self._print_decompilation_result(d)

        # the following ideal case requires a reimplementation of copy propagation
        # assert d.codegen.text.count("switch ") == 2
        # assert d.codegen.text.count("case 92:") == 2
        # assert d.codegen.text.count("case 0:") == 1
        # assert "goto" not in d.codegen.text
        assert d.codegen.text.count("switch ") == 1
        assert d.codegen.text.count("case 92:") == 1

    @structuring_algo("phoenix")
    def test_reverting_switch_clustering_and_lowering_cat_main(self, decompiler_options=None):
        # nested switch-cases
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "cat.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes += [angr.analyses.decompiler.optimization_passes.LoweredSwitchSimplifier]

        f = proj.kb.functions["main"]
        d = proj.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        self._print_decompilation_result(d)

        assert d.codegen.text.count("switch (") == 1
        assert (
            "> 118" not in d.codegen.text and ">= 119" not in d.codegen.text
        )  # > 118 (>= 119) goes to the default case

    @structuring_algo("phoenix")
    def test_reverting_switch_clustering_and_lowering_cat_main_no_endpoint_dup(self, decompiler_options=None):
        # nested switch-cases
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "cat.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        # turn off eager returns simplifier
        all_optimization_passes = [
            p
            for p in all_optimization_passes
            if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier
        ]
        all_optimization_passes += [angr.analyses.decompiler.optimization_passes.LoweredSwitchSimplifier]

        f = proj.kb.functions["main"]
        d = proj.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        self._print_decompilation_result(d)

        assert d.codegen.text.count("switch (") == 1
        assert (
            "> 118" not in d.codegen.text and ">= 119" not in d.codegen.text
        )  # > 118 (>= 119) goes to the default case

    @structuring_algo("phoenix")
    def test_comma_separated_statement_expression_whoami(self, decompiler_options=None):
        # nested switch-cases
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "whoami.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        f = proj.kb.functions["main"]
        d = proj.analyses[Decompiler].prep()(f, cfg=cfg.model, options=decompiler_options)
        self._print_decompilation_result(d)

        assert "goto" not in d.codegen.text
        assert re.search(r"if \(v\d+ != -1 \|\| \(v\d+ = 0, \*\(v\d+\) == 0\)\)", d.codegen.text) is not None

    @for_all_structuring_algos
    def test_complex_stack_offset_calculation(self, decompiler_options=None):
        # nested switch-cases
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "babyheap_level1.1")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions["main"]
        d = proj.analyses[Decompiler].prep()(
            f,
            cfg=cfg.model,
            options=decompiler_options,
        )
        self._print_decompilation_result(d)

        # The highest level symptom here is that two variable used are
        # confused and this shows up in the addition types.
        assert "Other Possible Types" not in d.codegen.text

        # check that the variable used in free is different from the one used in atoi
        m = re.search(r"free\(([^)]+)", d.codegen.text)
        assert m

        var_name = m.group(1)
        assert not re.search(f"atoi.*{var_name}", d.codegen.text)

    @for_all_structuring_algos
    def test_switch_case_shared_case_nodes_b2sum_digest(self, decompiler_options=None):
        # node 0x4028c8 is shared by two switch-case constructs. we should not crash even when eager returns simplifier
        # is disabled.
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "b2sum-digest_shared_switch_nodes.o")
        proj = angr.Project(bin_path, auto_load_libs=False)

        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            "AMD64", "linux"
        )
        all_optimization_passes = [
            p
            for p in all_optimization_passes
            if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier
        ]

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
        f = proj.kb.functions["main"]
        d = proj.analyses[Decompiler].prep()(
            f, cfg=cfg.model, options=decompiler_options, optimization_passes=all_optimization_passes
        )
        self._print_decompilation_result(d)

        assert d.codegen.text.count("switch") == 1


if __name__ == "__main__":
    unittest.main()
