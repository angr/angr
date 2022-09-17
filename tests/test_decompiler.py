# pylint: disable=missing-class-docstring,no-self-use,
import logging
import os
import re
import unittest

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

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')
l = logging.Logger(__name__)

WORKER = bool(os.environ.get('WORKER', False))  # this variable controls whether we print the decompilation code or not


class TestDecompiler(unittest.TestCase):

    def _print_decompilation_result(self, dec):
        if not WORKER:
            print("Decompilation result:")
            print(dec.codegen.text)

    def test_decompiling_all_x86_64(self):
        bin_path = os.path.join(test_location, "x86_64", "all")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        for f in cfg.functions.values():
            if f.is_simprocedure:
                l.debug("Skipping SimProcedure %s.", repr(f))
                continue
            dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)  # pylint: disable=unused-variable
            # FIXME: This test does not pass
            # assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
            # l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)

    def test_decompiling_babypwn_i386(self):
        bin_path = os.path.join(test_location, "i386", "decompiler", "codegate2017_babypwn")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)
        for f in cfg.functions.values():
            if f.is_simprocedure:
                l.debug("Skipping SimProcedure %s.", repr(f))
                continue
            if f.addr not in (0x8048a71, 0x8048c6b):
                continue
            dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
            assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
            l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)

    def test_decompiling_loop_x86_64(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "loop")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)
        f = cfg.functions['loop']
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)
        # it should be properly structured to a while loop without conditional breaks
        assert "break" not in dec.codegen.text

    def test_decompiling_all_i386(self):
        bin_path = os.path.join(test_location, "i386", "all")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        f = cfg.functions['main']
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)

    def test_decompiling_aes_armel(self):
        # EDG Says: This binary is invalid.
        # Consider replacing with some real firmware
        bin_path = os.path.join(test_location, "armel", "aes")
        # TODO: FIXME: EDG says: This binary is actually CortexM
        # It is incorrectly linked. We override this here
        p = angr.Project(bin_path, arch='ARMEL', auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        f = cfg.functions['main']
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)

    def test_decompiling_mips_allcmps(self):
        bin_path = os.path.join(test_location, "mips", "allcmps")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(collect_data_references=True, normalize=True)

        f = cfg.functions['main']
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)

    def test_decompiling_linked_list(self):
        bin_path = os.path.join(test_location, "x86_64", "linked_list")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        f = cfg.functions['sum']
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)


    def test_decompiling_dir_gcc_O0_free_ent(self):
        bin_path = os.path.join(test_location, "x86_64", "dir_gcc_-O0")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(normalize=True)

        f = cfg.functions['free_ent']
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)

    def test_decompiling_dir_gcc_O0_main(self):

        # tests loop structuring
        bin_path = os.path.join(test_location, "x86_64", "dir_gcc_-O0")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(normalize=True)

        f = cfg.functions['main']
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)

    def test_decompiling_dir_gcc_O0_emit_ancillary_info(self):
        bin_path = os.path.join(test_location, "x86_64", "dir_gcc_-O0")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(normalize=True)

        f = cfg.functions['emit_ancillary_info']
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)

    def test_decompiling_switch0_x86_64(self):

        bin_path = os.path.join(test_location, "x86_64", "switch_0")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        f = cfg.functions['main']
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)

        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)
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

    def test_decompiling_switch1_x86_64(self):

        bin_path = os.path.join(test_location, "x86_64", "switch_1")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes("AMD64",
                                                                                                               "linux")
        all_optimization_passes = [ p for p in all_optimization_passes
                                    if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier ]

        f = cfg.functions['main']
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, optimization_passes=all_optimization_passes)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)
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

    def test_decompiling_switch2_x86_64(self):

        bin_path = os.path.join(test_location, "x86_64", "switch_2")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes("AMD64",
                                                                                                               "linux")
        all_optimization_passes = [ p for p in all_optimization_passes
                                    if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier ]

        f = cfg.functions['main']
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, optimization_passes=all_optimization_passes)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)
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

    def test_decompiling_true_x86_64_0(self):

        # in fact this test case tests if CFGBase._process_jump_table_targeted_functions successfully removes "function"
        # 0x402543, which is an artificial function that the compiler (GCC) created for identified "cold" functions.

        bin_path = os.path.join(test_location, "x86_64", "true_ubuntu_2004")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes("AMD64",
                                                                                                               "linux")
        all_optimization_passes = [p for p in all_optimization_passes
                                   if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier]

        f = cfg.functions[0x4048c0]
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, optimization_passes=all_optimization_passes)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)
        code = dec.codegen.text
        assert "switch" in code
        assert "case" in code

    def test_decompiling_true_x86_64_1(self):
        bin_path = os.path.join(test_location, "x86_64", "true_ubuntu_2004")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes("AMD64",
                                                                                                               "linux")
        all_optimization_passes = [p for p in all_optimization_passes
                                   if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier]

        f = cfg.functions[0x404dc0]
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, optimization_passes=all_optimization_passes)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)
        code: str = dec.codegen.text

        # constant propagation was failing. see https://github.com/angr/angr/issues/2659
        assert code.count("32 <=") == 0 and code.count("32 >") == 0 and \
               code.count("((int)32) <=") == 0 and code.count("((int)32) >") == 0
        if "*(&stack_base-56:32)" in code:
            assert code.count("32") == 3
        else:
            assert code.count("32") == 2

    def test_decompiling_true_a_x86_64_0(self):
        bin_path = os.path.join(test_location, "x86_64", "true_a")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes("AMD64",
                                                                                                               "linux")
        all_optimization_passes = [p for p in all_optimization_passes
                                   if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier]

        f = cfg.functions[0x401e60]
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, optimization_passes=all_optimization_passes)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)

        assert dec.codegen.text.count("switch (") == 3  # there are three switch-cases in total

    def test_decompiling_true_a_x86_64_1(self):

        bin_path = os.path.join(test_location, "x86_64", "true_a")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes("AMD64",
                                                                                                               "linux")
        all_optimization_passes = [p for p in all_optimization_passes
                                   if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier]

        f = cfg.functions[0x404410]
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, optimization_passes=all_optimization_passes)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)

    def test_decompiling_true_1804_x86_64(self):
        # true in Ubuntu 18.04, with -O2, has special optimizations that
        # may mess up the way we structure loops and conditionals

        bin_path = os.path.join(test_location, "x86_64", "true_ubuntu1804")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses.CFG(normalize=True, data_references=True)

        f = cfg.functions["usage"]
        dec = p.analyses.Decompiler(f, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)

    def test_decompiling_true_mips64(self):

        bin_path = os.path.join(test_location, "mips64", "true")
        p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=False)
        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes("MIPS64",
                                                                                                               "linux")

        f = cfg.functions['main']
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, optimization_passes=all_optimization_passes)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)
        # make sure strings exist
        assert '"coreutils"' in dec.codegen.text
        assert '"/usr/local/share/locale"' in dec.codegen.text
        assert '"--help"' in dec.codegen.text
        assert '"Jim Meyering"' in dec.codegen.text
        # make sure function calls exist
        assert "set_program_name(" in dec.codegen.text
        assert "setlocale(" in dec.codegen.text
        assert "usage();" in dec.codegen.text

    def test_decompiling_1after909_verify_password(self):

        bin_path = os.path.join(test_location, "x86_64", "1after909")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

        # verify_password
        f = cfg.functions['verify_password']
        # recover calling convention
        p.analyses[VariableRecoveryFast].prep()(f)
        cca = p.analyses[CallingConventionAnalysis].prep()(f)
        f.calling_convention = cca.cc
        f.prototype = cca.prototype
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        l.debug("Decompiled function %s\n%s", repr(f), dec.codegen.text)
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
                assert ("v0" in line and "v1" in line and "v2" in line or
                        "v2" in line and "v3" in line and "v4" in line), \
                    "Failed to find v0, v1, and v2 in the same line. Is propagator over-propagating?"

        assert "= sprintf" not in code, "Failed to remove the unused return value of sprintf()"

    def test_decompiling_1after909_doit(self):

        # the doit() function has an abnormal loop at 0x1d47 - 0x1da1 - 0x1d73

        bin_path = os.path.join(test_location, "x86_64", "1after909")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)
        p.analyses[CompleteCallingConventionsAnalysis].prep()(recover_variables=True)

        # doit
        f = cfg.functions['doit']
        optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
            p.arch, p.simos.name
        )
        if angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier not in optimization_passes:
            optimization_passes += [
                angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier,
        ]
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, optimization_passes=optimization_passes)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(f)
        self._print_decompilation_result(dec)

        code = dec.codegen.text
        # with EagerReturnSimplifier applied, there should be no goto!
        assert "goto" not in code.lower(), "Found goto statements. EagerReturnSimplifier might have failed."
        # with global variables discovered, there should not be any loads of constant addresses.
        assert "fflush(stdout);" in code.lower()

        assert code.count("access(") == 2, (
            "The decompilation should contain 2 calls to access(), but instead %d calls are present."
            % code.count("access(")
        )

        m = re.search(r"if \([\S]*access\(&[\S]+, [\S]+\) == -1\)", code)
        assert m is not None, "The if branch at 0x401c91 is not found. Structurer is incorrectly removing conditionals."

        # Arguments to the convert call should be fully folded into the call statement itself
        code_lines = [ line.strip(" ") for line in code.split("\n") ]
        for i, line in enumerate(code_lines):
            if "convert(" in line:
                # the previous line must be a curly brace
                assert i > 0
                assert code_lines[i - 1] == "{", "Some arguments to convert() are probably not folded into this call " \
                                                 "statement."
                break
        else:
            assert False, "Call to convert() is not found in decompilation output."

        # propagator should not replace stack variables
        assert "free(v" in code
        assert "free(NULL" not in code and "free(0" not in code

    def test_decompiling_libsoap(self):

        bin_path = os.path.join(test_location, "armel", "libsoap.so")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions[0x41d000]
        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(func)
        l.debug("Decompiled function %s\n%s", repr(func), dec.codegen.text)

    def test_decompiling_no_arguments_in_variable_list(self):

        # function arguments should never appear in the variable list
        bin_path = os.path.join(test_location, "x86_64", "test_arrays")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        _ = p.analyses[CompleteCallingConventionsAnalysis].prep()(recover_variables=True)

        func = cfg.functions['main']

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(func)
        l.debug("Decompiled function %s\n%s", repr(func), dec.codegen.text)
        code = dec.codegen.text

        argc_name = " a0"  # update this variable once the decompiler picks up
                           # argument names from the common definition of main()
        assert argc_name in code
        assert code.count(argc_name) == 1  # it should only appear once

    def test_decompiling_strings_c_representation(self):

        input_expected = [("""Foo"bar""", "\"Foo\\\"bar\""),
                          ("""Foo'bar""", "\"Foo'bar\"")]

        for (_input, expected) in input_expected:
            result = angr.analyses.decompiler.structured_codegen.c.CConstant.str_to_c_str(_input)
            assert result == expected

    def test_decompiling_strings_local_strlen(self):
        bin_path = os.path.join(test_location, "x86_64", "types", "strings")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        func = cfg.functions['local_strlen']

        _ = p.analyses[VariableRecoveryFast].prep()(func)
        cca = p.analyses[CallingConventionAnalysis].prep()(func, cfg=cfg.model)
        func.calling_convention = cca.cc
        func.prototype = cca.prototype

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        l.debug("Decompiled function %s\n%s", repr(func), dec.codegen.text)

        code = dec.codegen.text
        # Make sure argument a0 is correctly typed to char*
        lines = code.split("\n")
        assert "local_strlen(char *a0)" in lines[0], "Argument a0 seems to be incorrectly typed: %s" % lines[0]

    def test_decompiling_strings_local_strcat(self):
        bin_path = os.path.join(test_location, "x86_64", "types", "strings")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        func = cfg.functions['local_strcat']

        _ = p.analyses[VariableRecoveryFast].prep()(func)
        cca = p.analyses[CallingConventionAnalysis].prep()(func, cfg=cfg.model)
        func.calling_convention = cca.cc
        func.prototype = cca.prototype

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        l.debug("Decompiled function %s\n%s", repr(func), dec.codegen.text)

        code = dec.codegen.text
        # Make sure argument a0 is correctly typed to char*
        lines = code.split("\n")
        assert "local_strcat(char *a0, char *a1)" in lines[0], \
            "Argument a0 and a1 seem to be incorrectly typed: %s" % lines[0]

    def test_decompiling_strings_local_strcat_with_local_strlen(self):
        bin_path = os.path.join(test_location, "x86_64", "types", "strings")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        func_strlen = cfg.functions['local_strlen']
        _ = p.analyses[VariableRecoveryFast].prep()(func_strlen)
        cca = p.analyses[CallingConventionAnalysis].prep()(func_strlen, cfg=cfg.model)
        func_strlen.calling_convention = cca.cc
        func_strlen.prototype = cca.prototype
        p.analyses[Decompiler].prep()(func_strlen, cfg=cfg.model)

        func = cfg.functions['local_strcat']

        _ = p.analyses[VariableRecoveryFast].prep()(func)
        cca = p.analyses[CallingConventionAnalysis].prep()(func, cfg=cfg.model)
        func.calling_convention = cca.cc
        func.prototype = cca.prototype

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        l.debug("Decompiled function %s\n%s", repr(func), dec.codegen.text)

        code = dec.codegen.text
        # Make sure argument a0 is correctly typed to char*
        lines = code.split("\n")
        assert "local_strcat(char *a0, char *a1)" in lines[0], \
            "Argument a0 and a1 seem to be incorrectly typed: %s" % lines[0]

    def test_decompilation_call_expr_folding(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "call_expr_folding")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func_0 = cfg.functions['strlen_should_fold']
        opt = [ o for o in angr.analyses.decompiler.decompilation_options.options
                if o.param == "remove_dead_memdefs" ][0]
        dec = p.analyses[Decompiler].prep()(func_0, cfg=cfg.model, options=[(opt, True)])
        assert dec.codegen is not None, "Failed to decompile function %r." % func_0
        self._print_decompilation_result(dec)

        code = dec.codegen.text
        m = re.search(r"v(\d+) = (\(.*\))?strlen\(&v(\d+)\);", code)  # e.g., s_428 = (int)strlen(&s_418);
        assert m is not None, "The result of strlen() should be directly assigned to a stack " \
                              "variable because of call-expression folding."
        assert m.group(1) != m.group(2)

        func_1 = cfg.functions['strlen_should_not_fold']
        dec = p.analyses[Decompiler].prep()(func_1, cfg=cfg.model)
        self._print_decompilation_result(dec)
        code = dec.codegen.text
        assert code.count("strlen(") == 1

        func_2 = cfg.functions['strlen_should_not_fold_into_loop']
        dec = p.analyses[Decompiler].prep()(func_2, cfg=cfg.model)
        self._print_decompilation_result(dec)
        code = dec.codegen.text
        assert code.count("strlen(") == 1

    def test_decompilation_call_expr_folding_mips64_true(self):

        # This test is to ensure call expression folding correctly replaces call expressions in return statements
        bin_path = os.path.join(test_location, "mips64", "true")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func_0 = cfg.functions['version_etc']
        dec = p.analyses[Decompiler].prep()(func_0, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %r." % func_0
        l.debug("Decompiled function %s\n%s", repr(func_0), dec.codegen.text)

        code = dec.codegen.text
        assert "version_etc_va(" in code

    def test_decompilation_call_expr_folding_x8664_calc(self):

        # This test is to ensure call expression folding do not re-use out-dated definitions when folding expressions
        bin_path = os.path.join(test_location, "x86_64", "calc")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        _ = p.analyses.CompleteCallingConventions(recover_variables=True)

        func_0 = cfg.functions['main']
        dec = p.analyses[Decompiler].prep()(func_0, cfg=cfg.model)
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

    def test_decompilation_excessive_condition_removal(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "bf")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions[0x100003890]

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        code = code.replace(" ", "").replace("\n", "")
        # s_1a += 1 should not be wrapped inside any if-statements. it is always reachable.
        assert "}v4+=1;}" in code or "}v4+=0x1;}" in code

    def test_decompilation_excessive_goto_removal(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "bf")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions[0x100003890]

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        l.debug("Decompiled function %s\n%s", repr(func), dec.codegen.text)

        code = dec.codegen.text

        assert "goto" not in code

    def test_decompilation_switch_case_structuring_with_removed_nodes(self):

        # Some jump table entries are fully folded into their successors. Structurer should be able to handle this case.
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "union")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions["build_date"]
        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        l.debug("Decompiled function %s\n%s", repr(func), dec.codegen.text)
        code = dec.codegen.text

        n = code.count("switch")
        assert n == 2, f"Expect two switch-case constructs, only found {n} instead."

    def test_decompilation_x86_64_stack_arguments(self):

        # Arguments passed on the stack should not go missing
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "union")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions["build_date"]

        # no dead memdef removal
        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        l.debug("Decompiled function %s\n%s", repr(func), dec.codegen.text)
        code = dec.codegen.text

        lines = code.split("\n")
        for line in lines:
            if "snprintf" in line:
                # The line should look like this:
                #   v0 = (int)snprintf(v32[8], (v43 + 0x1) * 0x2 + 0x1a, "%s, %.2d %s %d %.2d:%.2d:%.2d GMT\r\n", &v34,
                #   ((long long)v35), &v33, ((long long)v36 + 1900), ((long long)v35), ((long long)v35),
                #   ((long long)v35));
                assert line.count(',') == 10, "There is a missing stack argument."
                break
        else:
            assert False, "The line with snprintf() is not found."

        # with dead memdef removal
        opt = [o for o in angr.analyses.decompiler.decompilation_options.options if o.param == "remove_dead_memdefs"][0]
        # kill the cache since variables to statements won't match any more - variables are re-discovered with the new
        # option.
        p.kb.structured_code.cached.clear()
        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, options=[(opt, True)])
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        l.debug("Decompiled function %s\n%s", repr(func), dec.codegen.text)
        code = dec.codegen.text

        lines = code.split("\n")
        for line in lines:
            if "snprintf" in line:
                # The line should look like this:
                #   v0 = (int)snprintf(v32[8], (v43 + 0x1) * 0x2 + 0x1a, "%s, %.2d %s %d %.2d:%.2d:%.2d GMT\r\n", &v34,
                #   ((long long)v35), &v33, ((long long)v36 + 1900), ((long long)v35), ((long long)v35),
                #   ((long long)v35));
                assert line.count(',') == 10, "There is a missing stack argument."
                break
        else:
            assert False, "The line with snprintf() is not found."

    def test_decompiling_amp_challenge03_arm(self):
        bin_path = os.path.join(test_location, "armhf", "decompiler", "challenge_03")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        p.analyses[CompleteCallingConventionsAnalysis].prep()(recover_variables=True)
        func = cfg.functions['main']

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        # make sure there are no empty code blocks
        code = code.replace(" ", "").replace("\n", "")
        assert "{}" not in code, "Found empty code blocks in decompilation output. This may indicate some " \
                                 "assignments are incorrectly removed."
        assert '"o"' in code and '"x"' in code, "CFG failed to recognize single-byte strings."

    def test_decompiling_amp_challenge03_arm_expr_swapping(self):
        bin_path = os.path.join(test_location, "armhf", "decompiler", "challenge_03")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        p.analyses[CompleteCallingConventionsAnalysis].prep()(recover_variables=True)
        func = cfg.functions['main']

        binop_operators = {
            OpDescriptor(0x400a1d, 0, 0x400a27, "CmpGT"): "CmpLE"
        }
        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model, binop_operators=binop_operators)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        # make sure there are no empty code blocks
        lines = [ line.strip(" ") for line in code.split("\n") ]
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

    def test_decompiling_fauxware_mipsel(self):
        bin_path = os.path.join(test_location, "mipsel", "fauxware")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        func = cfg.functions['main']

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        l.debug("Decompiled function %s\n%s", repr(func), dec.codegen.text)
        code = dec.codegen.text

        # The function calls must be correctly decompiled
        assert "puts(" in code
        assert "read(" in code
        assert "authenticate(" in code
        # The string references must be correctly recovered
        assert '"Username: "' in code
        assert '"Password: "' in code

    def test_stack_canary_removal_x8664_extra_exits(self):

        # Test stack canary removal on functions with extra exit
        # nodes (e.g., assert(false);) without stack canary checks
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "babyheap_level1_teaching1")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        func = cfg.functions['main']

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        l.debug("Decompiled function %s\n%s", repr(func), dec.codegen.text)
        code = dec.codegen.text

        # We should not find "__stack_chk_fail" in the code
        assert "__stack_chk_fail" not in code

    def test_ifelseif_x8664(self):

        # nested if-else should be transformed to cascading if-elseif constructs
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "babyheap_level1_teaching1")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        func = cfg.functions['main']

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        assert code.count("else if") == 3

    def test_decompiling_missing_function_call(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "adams")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        func = cfg.functions['main']

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        l.debug("Decompiled function %s\n%s", repr(func), dec.codegen.text)
        code = dec.codegen.text

        # the call to fileno() should not go missing
        assert code.count("fileno") == 1

        code_without_spaces = code.replace(" ", "").replace("\n", "")
        # make sure all break statements are followed by either "case " or "}"
        replaced = code_without_spaces.replace("break;case", "")
        replaced = replaced.replace("break;}", "")
        assert "break" not in replaced

    def test_decompiling_morton_my_message_callback(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "morton")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        p.analyses[CompleteCallingConventionsAnalysis].prep()(recover_variables=True)

        func = cfg.functions['my_message_callback']

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        l.debug("Decompiled function %s\n%s", repr(func), dec.codegen.text)
        code = dec.codegen.text

        # we should not propagate generate_random() calls into function arguments without removing the original call
        # statement.
        assert code.count("generate_random(") == 3
        # we should be able to correctly figure out all arguments for mosquitto_publish() by analyzing call sites
        assert code.count("mosquitto_publish()") == 0
        assert code.count("mosquitto_publish(") == 6

    def test_decompiling_morton_lib_handle__suback(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "morton.libmosquitto.so.1")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
        p.analyses[CompleteCallingConventionsAnalysis].prep()(recover_variables=True)

        func = cfg.functions.function(name='handle__suback', plt=False)

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        l.debug("Decompiled function %s\n%s", repr(func), dec.codegen.text)
        code = dec.codegen.text

        assert "__stack_chk_fail" not in code  # stack canary checks should be removed by default

    def test_decompiling_newburry_main(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "newbury")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions['main']

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        self._print_decompilation_result(dec)
        code = dec.codegen.text

        # return statements should not be wrapped into a for statement
        assert re.search(r"for[^\n]*return[^\n]*;", code) is None

    def test_single_instruction_loop(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "level_12_teaching")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

        func = cfg.functions['main']

        dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %r." % func
        l.debug("Decompiled function %s\n%s", repr(func), dec.codegen.text)
        code = dec.codegen.text

        code_without_spaces = code.replace(" ", "").replace("\n", "")
        assert "while(true" not in code_without_spaces
        assert "for(" in code_without_spaces

    def test_simple_strcpy(self):
        """
        Original C: while (( *dst++ = *src++ ));
        Ensures incremented src and dst are not accidentally used in copy statement.
        """
        bin_path = os.path.join(test_location, "x86_64", "test_simple_strcpy")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses.CFGFast(normalize=True)
        p.analyses.CompleteCallingConventions(cfg=cfg, recover_variables=True)

        f = p.kb.functions['simple_strcpy']
        d = p.analyses.Decompiler(f, cfg=cfg.model)
        assert d.codegen is not None, "Failed to decompile function %r." % f
        self._print_decompilation_result(d)
        dw = d.codegen.cfunc.statements.statements[1]
        assert isinstance(dw, angr.analyses.decompiler.structured_codegen.c.CDoWhileLoop)
        stmts = dw.body.statements
        assert len(stmts) == 5
        assert stmts[1].lhs.unified_variable == stmts[0].rhs.unified_variable
        assert stmts[3].lhs.unified_variable == stmts[2].rhs.unified_variable
        assert stmts[4].lhs.operand.expr.variable == stmts[2].lhs.variable
        assert stmts[4].rhs.operand.expr.variable == stmts[0].lhs.variable
        assert dw.condition.lhs.operand.expr.variable == stmts[2].lhs.variable

    def test_decompiling_nl_i386_pie(self):
        bin_path = os.path.join(test_location, "i386", "nl")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses.CFGFast(normalize=True)
        p.analyses.CompleteCallingConventions(cfg=cfg, recover_variables=True)

        f = p.kb.functions['usage']
        d = p.analyses.Decompiler(f, cfg=cfg.model)
        assert d.codegen is not None, "Failed to decompile function %r." % f
        self._print_decompilation_result(d)

        assert '"Usage: %s [OPTION]... [FILE]...\\n"' in d.codegen.text
        assert '"Write each FILE to standard output, with line numbers added.\\nWith no FILE, or when FILE is -,' \
               ' read standard input.\\n\\n"' in d.codegen.text
        assert '"For complete documentation, run: info coreutils \'%s invocation\'\\n"' in d.codegen.text

    def test_decompiling_x8664_cvs(self):
        bin_path = os.path.join(test_location, "x86_64", "cvs")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses.CFGFast(normalize=True)
        # p.analyses.CompleteCallingConventions(cfg=cfg, recover_variables=True)

        f = p.kb.functions['main']
        d = p.analyses.Decompiler(f, cfg=cfg.model)
        assert d.codegen is not None, "Failed to decompile function %r." % f
        self._print_decompilation_result(d)

        # at the very least, it should decompile within a reasonable amount of time...
        # the switch-case must be recovered
        assert "switch (" in d.codegen.text

    def test_decompiling_x8664_mv_O2(self):
        bin_path = os.path.join(test_location, "x86_64", "mv_-O2")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses.CFGFast(normalize=True, show_progressbar=not WORKER)
        p.analyses.CompleteCallingConventions(cfg=cfg, recover_variables=True)

        f = p.kb.functions['main']
        d = p.analyses.Decompiler(f, cfg=cfg.model, show_progressbar=not WORKER)
        self._print_decompilation_result(d)

        assert "(False)" not in d.codegen.text
        assert "None" not in d.codegen.text

    def test_extern_decl(self):
        bin_path = os.path.join(test_location, "x86_64", "test_gdb_plugin")
        p = angr.Project(bin_path, auto_load_libs=False)

        cfg = p.analyses.CFGFast(normalize=True)

        f = p.kb.functions['set_globals']
        d = p.analyses.Decompiler(f, cfg=cfg.model)
        l.debug("Decompiled function %s\n%s", repr(f), d.codegen.text)

        assert "extern unsigned int a;" in d.codegen.text
        assert "extern unsigned int b;" in d.codegen.text
        assert "extern unsigned int c;" in d.codegen.text

    def test_decompiling_amp_challenge_07(self):
        bin_path = os.path.join(test_location, "armhf", "amp_challenge_07.gcc.dyn.unstripped")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions[0x401865]
        proj.analyses.VariableRecoveryFast(f)
        cca = proj.analyses.CallingConvention(f)
        f.prototype = cca.prototype
        f.calling_convention = cca.cc

        d = proj.analyses.Decompiler(f, cfg=cfg.model)
        self._print_decompilation_result(d)

        # make sure the types of extern variables are correct
        assert "extern char num_connections;" in d.codegen.text
        assert "extern char num_packets;" in d.codegen.text
        assert "extern char src;" in d.codegen.text

        lines = [ line.strip(" ") for line in d.codegen.text.split("\n") ]

        # make sure the line with printf("Recieved packet %d for connection with %d\n"...) does not have
        # "v23->field_5 + 1". otherwise it's an incorrect variable folding result
        line_0s = [ line for line in lines
                    if 'printf(' in line and 'Recieved packet %d for connection with %d' in line ]
        assert len(line_0s) == 1
        line_0 = line_0s[0].replace(" ", "")
        assert "+1" not in line_0

        # make sure v % 7 is present
        line_assignment_mod_7 = [ line for line in lines if re.search(r"v\d+ = v\d+ % 7", line)]
        assert len(line_assignment_mod_7) == 1
        line_mod_7 = [line for line in lines if re.search(r"v\d+ % 7", line)]
        assert len(line_mod_7) == 2

    def test_decompiling_fmt_get_space(self):

        bin_path = os.path.join(test_location, "x86_64", "decompiler", "fmt")
        proj = angr.Project(bin_path, auto_load_libs=False)

        cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

        f = proj.kb.functions[0x4020f0]
        proj.analyses.VariableRecoveryFast(f)
        cca = proj.analyses.CallingConvention(f)
        f.prototype = cca.prototype
        f.calling_convention = cca.cc

        d = proj.analyses.Decompiler(f, cfg=cfg.model)
        self._print_decompilation_result(d)

        assert "break" in d.codegen.text

    def test_decompiling_fmt_main(self):
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

        d = proj.analyses.Decompiler(f, cfg=cfg.model)
        self._print_decompilation_result(d)

        # function arguments must be a0 and a1. they cannot be renamed
        assert re.search(r"int main\([\s\S]+ a0, [\s\S]+a1\)", d.codegen.text) is not None

        assert "max_width = (int)xdectoumax(" in d.codegen.text or "max_width = xdectoumax(" in d.codegen.text
        assert "goal_width = xdectoumax(" in d.codegen.text
        assert "max_width = goal_width + 10;" in d.codegen.text \
               or "max_width = ((int)(goal_width + 10));" in d.codegen.text

        # by default, largest_successor_tree_outside_loop in RegionIdentifier is set to True, which means the
        # getopt_long() == -1 case should be entirely left outside the loop. by ensuring the call to error(0x1) is
        # within the last few lines of decompilation output, we ensure the -1 case is indeed outside the loop.
        last_three_lines = "\n".join(line.strip(" ") for line in d.codegen.text.split("\n")[-4:])
        assert "error(0x1, *(__errno_location()), \"%s\");" in last_three_lines

    def test_expr_collapsing(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "deep_expr")
        proj = angr.Project(bin_path, auto_load_libs=False)

        proj.analyses.CFGFast(normalize=True)
        d = proj.analyses.Decompiler(proj.kb.functions['main'])
        assert '...' in d.codegen.text, "codegen should have a too-deep expression replaced with '...'"
        collapsed = d.codegen.map_pos_to_node.get_node(d.codegen.text.find('...'))
        assert collapsed is not None, "collapsed node should appear in map"
        assert collapsed.collapsed, "collapsed node should be marked as collapsed"
        collapsed.collapsed = False
        old_len = len(d.codegen.text)
        d.codegen.regenerate_text()
        new_len = len(d.codegen.text)
        assert new_len > old_len, "un-collapsing node should expand decompilation output"

    def test_decompiling_division3(self):
        bin_path = os.path.join(test_location, "i386", "decompiler", "division3")
        proj = angr.Project(bin_path, auto_load_libs=False)

        proj.analyses.CFGFast(normalize=True)

        # disable eager returns simplifier
        all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes("AMD64",
                                                                                                               "linux")
        all_optimization_passes = [ p for p in all_optimization_passes
                                    if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier ]
        d = proj.analyses.Decompiler(proj.kb.functions["division3"], optimization_passes=all_optimization_passes)
        self._print_decompilation_result(d)

        # get the returned expression from the return statement
        # e.g., retexpr will be "v2" if the return statement is "  return v2;"
        lines = d.codegen.text.split("\n")
        retexpr = [ line for line in lines if "return " in line ][0].strip(" ;")[7:]

        # find the statement "v2 = v0 / 3"
        div3 = [ line for line in lines if re.match(retexpr + r" = v\d+ / 3;", line.strip(" ")) is not None]
        assert len(div3) == 1, f"Cannot find statement {retexpr} = v0 / 3."
        # find the statement "v2 = v0 * 7"
        mul7 = [line for line in lines if re.match(retexpr + r" = v\d+ \* 7;", line.strip(" ")) is not None]
        assert len(mul7) == 1, f"Cannot find statement {retexpr} = v0 * 7."

    def test_decompiling_simple_ctfbin_modulo(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "simple_ctfbin_modulo")
        proj = angr.Project(bin_path, auto_load_libs=False)

        proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(recover_variables=True)

        d = proj.analyses.Decompiler(proj.kb.functions["encrypt"])
        self._print_decompilation_result(d)

        assert "% 61" in d.codegen.text, "Modulo simplification failed."

    def test_struct_access(self):
        bin_path = os.path.join(test_location, "x86_64", "decompiler", "struct_access")
        proj = angr.Project(bin_path, auto_load_libs=False)

        proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(recover_variables=True)

        typedefs = angr.sim_type.parse_file("""
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
        """)

        d = proj.analyses.Decompiler(proj.kb.functions["main"])
        vmi: VariableManagerInternal = d.cache.clinic.variable_kb.variables['main']
        vmi.set_variable_type(
            next(iter(vmi.find_variables_by_stack_offset(-0x148))),
            SimTypePointer(typedefs[1]['struct C']),
            all_unified=True,
            mark_manual=True
        )
        unified = vmi.unified_variable(next(iter(vmi.find_variables_by_stack_offset(-0x148))))
        unified.name = "c_ptr"
        unified.renamed = True

        vmi.set_variable_type(
            next(iter(vmi.find_variables_by_stack_offset(-0x140))),
            SimTypePointer(typedefs[1]['struct B']),
            all_unified=True,
            mark_manual=True
        )
        unified = vmi.unified_variable(next(iter(vmi.find_variables_by_stack_offset(-0x140))))
        unified.name = "b_ptr"
        unified.renamed = True

        vmi.set_variable_type(
            next(iter(vmi.find_variables_by_register('rdi'))),
            SimTypeInt(),
            all_unified=True,
            mark_manual=True
        )
        unified = vmi.unified_variable(next(iter(vmi.find_variables_by_register('rdi'))))
        unified.name = "argc"
        unified.renamed = True

        d = proj.analyses.Decompiler(proj.kb.functions["main"], variable_kb=d.cache.clinic.variable_kb)
        self._print_decompilation_result(d)

        # TODO c_val
        assert 'b_ptr = &c_ptr->c2[argc];' in d.codegen.text
        assert 'c_ptr->c3[argc] = argc;' in d.codegen.text
        assert 'c_ptr->c2[argc].b2.a2 = argc;' in d.codegen.text
        assert 'b_ptr = &b_ptr[1];' in d.codegen.text
        assert 'return c_ptr->c4->c2[argc].b2.a2;' in d.codegen.text

if __name__ == "__main__":
    unittest.main()
