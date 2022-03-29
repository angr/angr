import re
import os
import angr
from angr.analyses import VariableRecoveryFast, CallingConventionAnalysis,\
    CompleteCallingConventionsAnalysis, CFGFast, Decompiler
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_decompiling_all_x86_64():
    bin_path = os.path.join(test_location, "x86_64", "all")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
    for f in cfg.functions.values():
        if f.is_simprocedure:
            print("Skipping SimProcedure %s." % repr(f))
            continue
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
        if dec.codegen is not None:
            print(dec.codegen.text)
        else:
            print("Failed to decompile function %s." % repr(f))


def test_decompiling_babypwn_i386():
    bin_path = os.path.join(test_location, "i386", "decompiler", "codegate2017_babypwn")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)
    for f in cfg.functions.values():
        if f.is_simprocedure:
            print("Skipping SimProcedure %s." % repr(f))
            continue
        if f.addr not in (0x8048a71, 0x8048c6b):
            continue
        dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
        if dec.codegen is not None:
            print(dec.codegen.text)
        else:
            print("Failed to decompile function %s." % repr(f))


def test_decompiling_loop_x86_64():
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "loop")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)
    f = cfg.functions['loop']
    dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
    if dec.codegen is not None:

        # it should be properly structured to a while loop without conditional breaks
        assert "break" not in dec.codegen.text

        print(dec.codegen.text)
    else:
        print("Failed to decompile function %s." % repr(f))


def test_decompiling_all_i386():
    bin_path = os.path.join(test_location, "i386", "all")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

    f = cfg.functions['main']
    dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %s." % repr(f))


def test_decompiling_aes_armel():
    # EDG Says: This binary is invalid.
    # Consider replacing with some real firmware
    bin_path = os.path.join(test_location, "armel", "aes")
    # TODO: FIXME: EDG says: This binary is actually CortexM
    # It is incorrectly linked. We override this here
    p = angr.Project(bin_path, arch='ARMEL', auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

    f = cfg.functions['main']
    dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %s." % repr(f))


def test_decompiling_mips_allcmps():
    bin_path = os.path.join(test_location, "mips", "allcmps")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses[CFGFast].prep()(collect_data_references=True, normalize=True)

    f = cfg.functions['main']
    dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %s." % repr(f))


def test_decompiling_linked_list():
    bin_path = os.path.join(test_location, "x86_64", "linked_list")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

    f = cfg.functions['sum']
    dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %r." % f)
        assert False


def test_decompiling_dir_gcc_O0_free_ent():
    bin_path = os.path.join(test_location, "x86_64", "dir_gcc_-O0")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses[CFGFast].prep()(normalize=True)

    f = cfg.functions['free_ent']
    dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %r." % f)
        assert False


def test_decompiling_dir_gcc_O0_main():

    # tests loop structuring
    bin_path = os.path.join(test_location, "x86_64", "dir_gcc_-O0")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses[CFGFast].prep()(normalize=True)

    f = cfg.functions['main']
    dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %r." % f)
        assert False


def test_decompiling_dir_gcc_O0_emit_ancillary_info():
    bin_path = os.path.join(test_location, "x86_64", "dir_gcc_-O0")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses[CFGFast].prep()(normalize=True)

    f = cfg.functions['emit_ancillary_info']
    dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %r." % f)
        assert False


def test_decompiling_switch0_x86_64():

    bin_path = os.path.join(test_location, "x86_64", "switch_0")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

    f = cfg.functions['main']
    dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model)

    if dec.codegen is not None:
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

        print(dec.codegen.text)
    else:
        print("Failed to decompile function %r." % f)
        assert False


def test_decompiling_switch1_x86_64():

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
    if dec.codegen is not None:
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

        print(dec.codegen.text)
    else:
        print("Failed to decompile function %r." % f)
        assert False


def test_decompiling_switch2_x86_64():

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
    if dec.codegen is not None:
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

        print(dec.codegen.text)
    else:
        print("Failed to decompile function %r." % f)
        assert False


def test_decompiling_true_x86_64_0():

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
    print(dec.codegen.text)
    if dec.codegen is not None:
        code = dec.codegen.text
        assert "switch" in code
        assert "case" in code
    else:
        print("Failed to decompile function %r." % f)
        assert False


def test_decompiling_true_x86_64_1():
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
    print(dec.codegen.text)
    code: str = dec.codegen.text

    # constant propagation was failing. see https://github.com/angr/angr/issues/2659
    assert code.count("32 <=") == 0 and code.count("32 >") == 0 and \
           code.count("((int)32) <=") == 0 and code.count("((int)32) >") == 0
    if "*(&stack_base-56:32)" in code:
        assert code.count("32") == 3
    else:
        assert code.count("32") == 2


def test_decompiling_true_a_x86_64_0():
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
    print(dec.codegen.text)

    assert dec.codegen.text.count("switch (") == 3  # there are three switch-cases in total


def test_decompiling_true_a_x86_64_1():

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
    print(dec.codegen.text)


def test_decompiling_true_1804_x86_64():
    # true in Ubuntu 18.04, with -O2, has special optimizations that
    # may mess up the way we structure loops and conditionals

    bin_path = os.path.join(test_location, "x86_64", "true_ubuntu1804")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(normalize=True, data_references=True)

    f = cfg.functions["usage"]
    dec = p.analyses.Decompiler(f, cfg=cfg.model)
    print(dec.codegen.text)


def test_decompiling_true_mips64():

    bin_path = os.path.join(test_location, "mips64", "true")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=False)
    cfg = p.analyses[CFGFast].prep()(normalize=True, data_references=True)

    all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes("MIPS64",
                                                                                                           "linux")

    f = cfg.functions['main']
    dec = p.analyses[Decompiler].prep()(f, cfg=cfg.model, optimization_passes=all_optimization_passes)
    # make sure strings exist
    assert '"coreutils"' in dec.codegen.text
    assert '"/usr/local/share/locale"' in dec.codegen.text
    assert '"--help"' in dec.codegen.text
    assert '"Jim Meyering"' in dec.codegen.text
    # make sure function calls exist
    assert "set_program_name(" in dec.codegen.text
    assert "setlocale(" in dec.codegen.text
    assert "usage();" in dec.codegen.text


def test_decompiling_1after909_verify_password():

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
    if dec.codegen is None:
        print("Failed to decompile function %r." % f)
        assert False

    code = dec.codegen.text
    print(code)
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
            assert "v0" in line and "v1" in line and "v2" in line, \
                "Failed to find v0, v1, and v2 in the same line. Is propagator over-propagating?"

    assert "= sprintf" not in code, "Failed to remove the unused return value of sprintf()"


def test_decompiling_1after909_doit():

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
    if dec.codegen is None:
        print("Failed to decompile function %r." % f)
        assert False

    code = dec.codegen.text
    print(code)
    # with EagerReturnSimplifier applied, there should be no goto!
    assert "goto" not in code.lower(), "Found goto statements. EagerReturnSimplifier might have failed."
    # with global variables discovered, there should not be any loads of constant addresses.
    assert "fflush(stdout);" in code.lower()

    assert code.count("access(") == 2, "The decompilation should contain 2 calls to access(), but instead %d calls are present." % code.count("access(")

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


def test_decompiling_libsoap():

    bin_path = os.path.join(test_location, "armel", "libsoap.so")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

    func = cfg.functions[0x41d000]
    dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
    if dec.codegen is not None:
        code = dec.codegen.text
        print(code)
        assert code
    else:
        print("Failed to decompile function %r." % func)
        assert False


def test_decompiling_no_arguments_in_variable_list():

    # function arguments should never appear in the variable list
    bin_path = os.path.join(test_location, "x86_64", "test_arrays")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
    _ = p.analyses[CompleteCallingConventionsAnalysis].prep()(recover_variables=True)

    func = cfg.functions['main']

    dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
    code = dec.codegen.text
    print(code)

    argc_name = " a0"  # update this variable once the decompiler picks up argument names from the common definition of
                       # main()
    assert argc_name in code
    assert code.count(argc_name) == 1  # it should only appear once

def test_decompiling_strings_c_representation():

    input_expected = [("""Foo"bar""", "\"Foo\\\"bar\""),
                      ("""Foo'bar""", "\"Foo'bar\"")]

    for (_input, expected) in input_expected:
        result = angr.analyses.decompiler.structured_codegen.c.CConstant.str_to_c_str(_input)
        assert result == expected

def test_decompiling_strings_local_strlen():
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

    code = dec.codegen.text
    print(code)
    # Make sure argument a0 is correctly typed to char*
    lines = code.split("\n")
    assert "local_strlen(char *a0)" in lines[0], "Argument a0 seems to be incorrectly typed: %s" % lines[0]


def test_decompiling_strings_local_strcat():
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

    code = dec.codegen.text
    print(code)
    # Make sure argument a0 is correctly typed to char*
    lines = code.split("\n")
    assert "local_strcat(char *a0, char *a1)" in lines[0], \
        "Argument a0 and a1 seem to be incorrectly typed: %s" % lines[0]


def test_decompiling_strings_local_strcat_with_local_strlen():
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

    code = dec.codegen.text
    print(code)
    # Make sure argument a0 is correctly typed to char*
    lines = code.split("\n")
    assert "local_strcat(char *a0, char *a1)" in lines[0], \
        "Argument a0 and a1 seem to be incorrectly typed: %s" % lines[0]


def test_decompilation_call_expr_folding():
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "call_expr_folding")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

    func_0 = cfg.functions['strlen_should_fold']
    opt = [ o for o in angr.analyses.decompiler.decompilation_options.options if o.param == "remove_dead_memdefs" ][0]
    dec = p.analyses[Decompiler].prep()(func_0, cfg=cfg.model, options=[(opt, True)])
    code = dec.codegen.text
    print(code)
    m = re.search(r"v(\d+) = \(int\)strlen\(&v(\d+)\);", code)  # e.g., s_428 = (int)strlen(&s_418);
    assert m is not None, "The result of strlen() should be directly assigned to a stack " \
                          "variable because of call-expression folding."
    assert m.group(1) != m.group(2)

    func_1 = cfg.functions['strlen_should_not_fold']
    dec = p.analyses[Decompiler].prep()(func_1, cfg=cfg.model)
    code = dec.codegen.text
    print(code)
    assert code.count("strlen(") == 1

    func_2 = cfg.functions['strlen_should_not_fold_into_loop']
    dec = p.analyses[Decompiler].prep()(func_2, cfg=cfg.model)
    code = dec.codegen.text
    print(code)
    assert code.count("strlen(") == 1


def test_decompilation_call_expr_folding_mips64_true():

    # This test is to ensure call expression folding correctly replaces call expressions in return statements
    bin_path = os.path.join(test_location, "mips64", "true")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

    func_0 = cfg.functions['version_etc']
    dec = p.analyses[Decompiler].prep()(func_0, cfg=cfg.model)
    code = dec.codegen.text
    print(code)
    assert "version_etc_va(" in code


def test_decompilation_call_expr_folding_x8664_calc():

    # This test is to ensure call expression folding do not re-use out-dated definitions when folding expressions
    bin_path = os.path.join(test_location, "x86_64", "calc")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
    _ = p.analyses.CompleteCallingConventions(recover_variables=True)

    func_0 = cfg.functions['main']
    dec = p.analyses[Decompiler].prep()(func_0, cfg=cfg.model)
    code = dec.codegen.text
    print(code)

    assert "root(" in code
    assert "strlen(" in code  # incorrect call expression folding would fold root() into printf() and remove strlen()
    assert "printf(" in code

    lines = code.split("\n")
    # make sure root() and strlen() appear within the same line
    for line in lines:
        if "root(" in line:
            assert "strlen(" in line


def test_decompilation_excessive_condition_removal():
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "bf")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

    func = cfg.functions[0x100003890]

    dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
    code = dec.codegen.text
    print(code)

    code = code.replace(" ", "").replace("\n", "")
    # s_1a += 1 should not be wrapped inside any if-statements. it is always reachable.
    assert "}v4+=1;}" in code or "}v4+=0x1;}" in code


def test_decompilation_excessive_goto_removal():
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "bf")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

    func = cfg.functions[0x100003890]

    dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
    code = dec.codegen.text
    print(code)

    assert "goto" not in code


def test_decompilation_switch_case_structuring_with_removed_nodes():

    # Some jump table entries are fully folded into their successors. Structurer should be able to handle this case.
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "union")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

    func = cfg.functions["build_date"]
    dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
    code = dec.codegen.text
    print(code)

    n = code.count("switch")
    assert n == 2, f"Expect two switch-case constructs, only found {n} instead."


def test_decompilation_x86_64_stack_arguments():

    # Arguments passed on the stack should not go missing
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "union")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

    func = cfg.functions["build_date"]

    # no dead memdef removal
    dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
    code = dec.codegen.text
    print(code)

    lines = code.split("\n")
    for line in lines:
        if "snprintf" in line:
            # The line should look like this:
            #   v0 = (int)snprintf(v32[8], (v43 + 0x1) * 0x2 + 0x1a, "%s, %.2d %s %d %.2d:%.2d:%.2d GMT\r\n", &v34,
            #   ((long long)v35), &v33, ((long long)v36 + 1900), ((long long)v35), ((long long)v35), ((long long)v35));
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
    code = dec.codegen.text
    print(code)

    lines = code.split("\n")
    for line in lines:
        if "snprintf" in line:
            # The line should look like this:
            #   v0 = (int)snprintf(v32[8], (v43 + 0x1) * 0x2 + 0x1a, "%s, %.2d %s %d %.2d:%.2d:%.2d GMT\r\n", &v34,
            #   ((long long)v35), &v33, ((long long)v36 + 1900), ((long long)v35), ((long long)v35), ((long long)v35));
            assert line.count(',') == 10, "There is a missing stack argument."
            break
    else:
        assert False, "The line with snprintf() is not found."


def test_decompiling_amp_challenge03_arm():
    bin_path = os.path.join(test_location, "armhf", "decompiler", "challenge_03")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
    p.analyses[CompleteCallingConventionsAnalysis].prep()(recover_variables=True)
    func = cfg.functions['main']

    dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
    code = dec.codegen.text
    print(code)

    # make sure there are no empty code blocks
    code = code.replace(" ", "").replace("\n", "")
    assert "{}" not in code, "Found empty code blocks in decompilation output. This may indicate some assignments " \
                             "are incorrectly removed."


def test_decompiling_fauxware_mipsel():
    bin_path = os.path.join(test_location, "mipsel", "fauxware")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
    func = cfg.functions['main']

    dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
    code = dec.codegen.text
    print(code)

    # The function calls must be correctly decompiled
    assert "puts(" in code
    assert "read(" in code
    assert "authenticate(" in code
    # The string references must be correctly recovered
    assert '"Username: "' in code
    assert '"Password: "' in code


def test_stack_canary_removal_x8664_extra_exits():

    # Test stack canary removal on functions with extra exit nodes (e.g., assert(false);) without stack canary checks
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "babyheap_level1_teaching1")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
    func = cfg.functions['main']

    dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
    code = dec.codegen.text
    print(code)

    # We should not find "__stack_chk_fail" in the code
    assert "__stack_chk_fail" not in code


def test_ifelseif_x8664():

    # nested if-else should be transformed to cascading if-elseif constructs
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "babyheap_level1_teaching1")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
    func = cfg.functions['main']

    dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
    code = dec.codegen.text

    print(code)
    assert code.count("else if") == 3


def test_decompiling_missing_function_call():
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "adams")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
    func = cfg.functions['main']

    dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
    code = dec.codegen.text

    print(code)
    # the call to fileno() should not go missing
    assert code.count("fileno") == 1

    code_without_spaces = code.replace(" ", "").replace("\n", "")
    # make sure all break statements are followed by either "case " or "}"
    replaced = code_without_spaces.replace("break;case", "")
    replaced = replaced.replace("break;}", "")
    assert "break" not in replaced


def test_decompiling_morton_my_message_callback():
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "morton")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
    p.analyses[CompleteCallingConventionsAnalysis].prep()(recover_variables=True)

    func = cfg.functions['my_message_callback']

    dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
    code = dec.codegen.text

    print(code)
    # we should not propagate generate_random() calls into function arguments without removing the original call
    # statement.
    assert code.count("generate_random(") == 3
    # we should be able to correctly figure out all arguments for mosquitto_publish() by analyzing call sites
    assert code.count("mosquitto_publish()") == 0
    assert code.count("mosquitto_publish(") == 6


def test_decompiling_morton_lib_handle__suback():
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "morton.libmosquitto.so.1")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)
    p.analyses[CompleteCallingConventionsAnalysis].prep()(recover_variables=True)

    func = cfg.functions.function(name='handle__suback', plt=False)

    dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
    code = dec.codegen.text

    print(code)
    assert "__stack_chk_fail" not in code  # stack canary checks should be removed by default


def test_decompiling_newburry_main():
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "newbury")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

    func = cfg.functions['main']

    dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
    code = dec.codegen.text

    print(code)
    # return statements should not be wrapped into a for statement
    assert re.search(r"for[^\n]*return[^\n]*;", code) is None


def test_single_instruction_loop():
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "level_12_teaching")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses[CFGFast].prep()(data_references=True, normalize=True)

    func = cfg.functions['main']

    dec = p.analyses[Decompiler].prep()(func, cfg=cfg.model)
    code = dec.codegen.text

    print(code)
    code_without_spaces = code.replace(" ", "").replace("\n", "")
    assert "while(true" not in code_without_spaces
    assert "for(" in code_without_spaces


def test_simple_strcpy():
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
    print(d.codegen.text)
    dw = d.codegen.cfunc.statements.statements[1]
    assert isinstance(dw, angr.analyses.decompiler.structured_codegen.c.CDoWhileLoop)
    stmts = dw.body.statements
    assert len(stmts) == 5
    assert stmts[1].lhs.unified_variable == stmts[0].rhs.unified_variable
    assert stmts[3].lhs.unified_variable == stmts[2].rhs.unified_variable
    assert stmts[4].lhs.operand.variable == stmts[2].lhs.variable
    assert stmts[4].rhs.operand.variable == stmts[0].lhs.variable
    assert dw.condition.lhs.expr.operand.variable == stmts[2].lhs.variable


def test_decompiling_nl_i386_pie():
    bin_path = os.path.join(test_location, "i386", "nl")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFGFast(normalize=True)
    p.analyses.CompleteCallingConventions(cfg=cfg, recover_variables=True)

    f = p.kb.functions['usage']
    d = p.analyses.Decompiler(f, cfg=cfg.model)
    print(d.codegen.text)

    assert '"Usage: %s [OPTION]... [FILE]...\\n"' in d.codegen.text
    assert '"Write each FILE to standard output, with line numbers added.\\nWith no FILE, or when FILE is -,' \
           ' read standard input.\\n\\n"' in d.codegen.text
    assert '"For complete documentation, run: info coreutils \'%s invocation\'\\n"' in d.codegen.text


def test_decompiling_x8664_cvs():
    bin_path = os.path.join(test_location, "x86_64", "cvs")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFGFast(normalize=True, show_progressbar=True)
    # p.analyses.CompleteCallingConventions(cfg=cfg, recover_variables=True)

    f = p.kb.functions['main']
    d = p.analyses.Decompiler(f, cfg=cfg.model, show_progressbar=True)
    print(d.codegen.text)

    # at the very least, it should decompile within a reasonable amount of time...
    # the switch-case must be recovered
    assert "switch (" in d.codegen.text


def test_decompiling_x8664_mv_O2():
    bin_path = os.path.join(test_location, "x86_64", "mv_-O2")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFGFast(normalize=True, show_progressbar=True)
    p.analyses.CompleteCallingConventions(cfg=cfg, recover_variables=True)

    f = p.kb.functions['main']
    d = p.analyses.Decompiler(f, cfg=cfg.model, show_progressbar=True)
    print(d.codegen.text)

    assert "(False)" not in d.codegen.text
    assert "None" not in d.codegen.text


def test_extern_decl():
    bin_path = os.path.join(test_location, "x86_64", "test_gdb_plugin")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFGFast(normalize=True)

    f = p.kb.functions['set_globals']
    d = p.analyses.Decompiler(f, cfg=cfg.model)
    print(d.codegen.text)

    assert "extern unsigned int a;" in d.codegen.text
    assert "extern unsigned int b;" in d.codegen.text
    assert "extern unsigned int c;" in d.codegen.text


if __name__ == "__main__":
    for k, v in list(globals().items()):
        if k.startswith('test_') and callable(v):
            v()
