import re
import os
import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_decompiling_all_x86_64():
    bin_path = os.path.join(test_location, "x86_64", "all")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses.CFG(data_references=True, normalize=True)
    for f in cfg.functions.values():
        if f.is_simprocedure:
            print("Skipping SimProcedure %s." % repr(f))
            continue
        dec = p.analyses.Decompiler(f, cfg=cfg.model)
        if dec.codegen is not None:
            print(dec.codegen.text)
        else:
            print("Failed to decompile function %s." % repr(f))


def test_decompiling_babypwn_i386():
    bin_path = os.path.join(test_location, "i386", "decompiler", "codegate2017_babypwn")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses.CFG(normalize=True, data_references=True)
    for f in cfg.functions.values():
        if f.is_simprocedure:
            print("Skipping SimProcedure %s." % repr(f))
            continue
        if f.addr not in (0x8048a71, 0x8048c6b):
            continue
        dec = p.analyses.Decompiler(f, cfg=cfg.model)
        if dec.codegen is not None:
            print(dec.codegen.text)
        else:
            print("Failed to decompile function %s." % repr(f))


def test_decompiling_loop_x86_64():
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "loop")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses.CFG(normalize=True, data_references=True)
    f = cfg.functions['loop']
    dec = p.analyses.Decompiler(f, cfg=cfg.model)
    if dec.codegen is not None:

        # it should be properly structured to a while loop without conditional breaks
        assert "break" not in dec.codegen.text

        print(dec.codegen.text)
    else:
        print("Failed to decompile function %s." % repr(f))


def test_decompiling_all_i386():
    bin_path = os.path.join(test_location, "i386", "all")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses.CFG(data_references=True, normalize=True)

    f = cfg.functions['main']
    dec = p.analyses.Decompiler(f, cfg=cfg.model)
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

    cfg = p.analyses.CFG(data_references=True, normalize=True)

    f = cfg.functions['main']
    dec = p.analyses.Decompiler(f, cfg=cfg.model)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %s." % repr(f))


def test_decompiling_mips_allcmps():
    bin_path = os.path.join(test_location, "mips", "allcmps")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses.CFG(collect_data_references=True, normalize=True)

    f = cfg.functions['main']
    dec = p.analyses.Decompiler(f, cfg=cfg.model)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %s." % repr(f))


def test_decompiling_linked_list():
    bin_path = os.path.join(test_location, "x86_64", "linked_list")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(normalize=True, data_references=True)

    f = cfg.functions['sum']
    dec = p.analyses.Decompiler(f, cfg=cfg.model)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %r." % f)
        assert False


def test_decompiling_dir_gcc_O0_free_ent():
    bin_path = os.path.join(test_location, "x86_64", "dir_gcc_-O0")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses.CFG(normalize=True)

    f = cfg.functions['free_ent']
    dec = p.analyses.Decompiler(f, cfg=cfg.model)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %r." % f)
        assert False


def test_decompiling_dir_gcc_O0_main():

    # tests loop structuring
    bin_path = os.path.join(test_location, "x86_64", "dir_gcc_-O0")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses.CFG(normalize=True)

    f = cfg.functions['main']
    dec = p.analyses.Decompiler(f, cfg=cfg.model)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %r." % f)
        assert False


def test_decompiling_dir_gcc_O0_emit_ancillary_info():
    bin_path = os.path.join(test_location, "x86_64", "dir_gcc_-O0")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses.CFG(normalize=True)

    f = cfg.functions['emit_ancillary_info']
    dec = p.analyses.Decompiler(f, cfg=cfg.model)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %r." % f)
        assert False


def test_decompiling_switch0_x86_64():

    bin_path = os.path.join(test_location, "x86_64", "switch_0")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(normalize=True, data_references=True)

    f = cfg.functions['main']
    dec = p.analyses.Decompiler(f, cfg=cfg.model)

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

    cfg = p.analyses.CFG(normalize=True, data_references=True)

    # disable eager returns simplifier
    all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes("AMD64",
                                                                                                           "linux")
    all_optimization_passes = [ p for p in all_optimization_passes
                                if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier ]

    f = cfg.functions['main']
    dec = p.analyses.Decompiler(f, cfg=cfg.model, optimization_passes=all_optimization_passes)
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

    cfg = p.analyses.CFG(normalize=True, data_references=True)

    # disable eager returns simplifier
    all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes("AMD64",
                                                                                                           "linux")
    all_optimization_passes = [ p for p in all_optimization_passes
                                if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier ]

    f = cfg.functions['main']
    dec = p.analyses.Decompiler(f, cfg=cfg.model, optimization_passes=all_optimization_passes)
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

    cfg = p.analyses.CFG(normalize=True, data_references=True)

    # disable eager returns simplifier
    all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes("AMD64",
                                                                                                           "linux")
    all_optimization_passes = [p for p in all_optimization_passes
                               if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier]

    f = cfg.functions[0x4048c0]
    dec = p.analyses.Decompiler(f, cfg=cfg.model, optimization_passes=all_optimization_passes)
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

    cfg = p.analyses.CFG(normalize=True, data_references=True)

    # disable eager returns simplifier
    all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes("AMD64",
                                                                                                           "linux")
    all_optimization_passes = [p for p in all_optimization_passes
                               if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier]

    f = cfg.functions[0x404dc0]
    dec = p.analyses.Decompiler(f, cfg=cfg.model, optimization_passes=all_optimization_passes)
    print(dec.codegen.text)
    code: str = dec.codegen.text

    # constant propagation was failing. see https://github.com/angr/angr/issues/2659
    assert code.count("32 <=") == 0
    assert code.count("32") == 2


def test_decompiling_true_a_x86_64_0():
    bin_path = os.path.join(test_location, "x86_64", "true_a")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses.CFG(normalize=True, data_references=True)

    # disable eager returns simplifier
    all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes("AMD64",
                                                                                                           "linux")
    all_optimization_passes = [p for p in all_optimization_passes
                               if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier]

    f = cfg.functions[0x401e60]
    dec = p.analyses.Decompiler(f, cfg=cfg.model, optimization_passes=all_optimization_passes)
    print(dec.codegen.text)


def test_decompiling_true_a_x86_64_1():

    bin_path = os.path.join(test_location, "x86_64", "true_a")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses.CFG(normalize=True, data_references=True)

    # disable eager returns simplifier
    all_optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes("AMD64",
                                                                                                           "linux")
    all_optimization_passes = [p for p in all_optimization_passes
                               if p is not angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier]

    f = cfg.functions[0x404410]
    dec = p.analyses.Decompiler(f, cfg=cfg.model, optimization_passes=all_optimization_passes)
    print(dec.codegen.text)


def test_decompiling_1after909():

    # the doit() function has an abnormal loop at 0x1d47 - 0x1da1 - 0x1d73

    bin_path = os.path.join(test_location, "x86_64", "1after909")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(normalize=True, data_references=True)

    # verify_password
    f = cfg.functions['verify_password']
    dec = p.analyses.Decompiler(f, cfg=cfg.model)
    if dec.codegen is not None:
        code = dec.codegen.text
        print(code)
        assert "stack_base" not in code, "Some stack variables are not recognized"
        assert "strncmp(v0, &v3, 0x40)" in code
        assert "strncmp(v0, &v3, 0x40);" not in code, "Call expressions folding failed for strncmp()"
    else:
        print("Failed to decompile function %r." % f)
        assert False

    # doit
    f = cfg.functions['doit']
    optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
        p.arch, p.simos.name
    )
    if angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier not in optimization_passes:
        optimization_passes += [
            angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier,
    ]
    dec = p.analyses.Decompiler(f, cfg=cfg.model, optimization_passes=optimization_passes)
    if dec.codegen is not None:
        code = dec.codegen.text
        print(code)
        # with EagerReturnSimplifier applied, there should be no goto!
        assert "goto" not in code.lower(), "Found goto statements. EagerReturnSimplifier might have failed."
        # with global variables discovered, there should not be any loads of constant addresses.
        assert "fflush(stdout);" in code.lower()
    else:
        print("Failed to decompile function %r." % f)
        assert False


def test_decompiling_libsoap():

    bin_path = os.path.join(test_location, "armel", "libsoap.so")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(data_references=True, normalize=True)

    func = cfg.functions[0x41d000]
    dec = p.analyses.Decompiler(func, cfg=cfg.model)
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

    cfg = p.analyses.CFG(data_references=True, normalize=True)
    _ = p.analyses.CompleteCallingConventions(recover_variables=True)

    func = cfg.functions['main']

    dec = p.analyses.Decompiler(func, cfg=cfg.model)
    code = dec.codegen.text
    print(code)

    argc_name = " a0"  # update this variable once the decompiler picks up argument names from the common definition of
                       # main()
    assert argc_name in code
    assert code.count(argc_name) == 1  # it should only appear once


def test_decompiling_strings_local_strlen():
    bin_path = os.path.join(test_location, "x86_64", "types", "strings")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(data_references=True, normalize=True)
    func = cfg.functions['local_strlen']

    _ = p.analyses.VariableRecoveryFast(func)
    cca = p.analyses.CallingConvention(func, cfg=cfg.model)
    func.calling_convention = cca.cc

    dec = p.analyses.Decompiler(func, cfg=cfg.model)
    assert dec.codegen is not None, "Failed to decompile function %r." % func

    code = dec.codegen.text
    print(code)
    # Make sure argument a0 is correctly typed to char*
    lines = code.split("\n")
    assert "local_strlen(char *a0)" in lines[0], "Argument a0 seems to be incorrectly typed: %s" % lines[0]


def test_decompiling_strings_local_strcat():
    bin_path = os.path.join(test_location, "x86_64", "types", "strings")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(data_references=True, normalize=True)
    func = cfg.functions['local_strcat']

    _ = p.analyses.VariableRecoveryFast(func)
    cca = p.analyses.CallingConvention(func, cfg=cfg.model)
    func.calling_convention = cca.cc

    dec = p.analyses.Decompiler(func, cfg=cfg.model)
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

    cfg = p.analyses.CFG(data_references=True, normalize=True)
    func_strlen = cfg.functions['local_strlen']
    _ = p.analyses.VariableRecoveryFast(func_strlen)
    cca = p.analyses.CallingConvention(func_strlen, cfg=cfg.model)
    func_strlen.calling_convention = cca.cc
    p.analyses.Decompiler(func_strlen, cfg=cfg.model)

    func = cfg.functions['local_strcat']

    _ = p.analyses.VariableRecoveryFast(func)
    cca = p.analyses.CallingConvention(func, cfg=cfg.model)
    func.calling_convention = cca.cc

    dec = p.analyses.Decompiler(func, cfg=cfg.model)
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

    cfg = p.analyses.CFG(data_references=True, normalize=True)

    func_0 = cfg.functions['strlen_should_fold']
    opt = [ o for o in angr.analyses.decompiler.decompilation_options.options if o.param == "remove_dead_memdefs" ][0]
    dec = p.analyses.Decompiler(func_0, cfg=cfg.model, options=[(opt, True)])
    code = dec.codegen.text
    print(code)
    m = re.search(r"v(\d+) = \(int\)strlen\(&v(\d+)\);", code)  # e.g., s_428 = (int)strlen(&s_418);
    assert m is not None, "The result of strlen() should be directly assigned to a stack " \
                          "variable because of call-expression folding."
    assert m.group(1) != m.group(2)

    func_1 = cfg.functions['strlen_should_not_fold']
    dec = p.analyses.Decompiler(func_1, cfg=cfg.model)
    code = dec.codegen.text
    print(code)
    assert code.count("strlen(") == 1

    func_2 = cfg.functions['strlen_should_not_fold_into_loop']
    dec = p.analyses.Decompiler(func_2, cfg=cfg.model)
    code = dec.codegen.text
    print(code)
    assert code.count("strlen(") == 1


def test_decompilation_excessive_condition_removal():
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "bf")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(data_references=True, normalize=True)

    func = cfg.functions[0x100003890]

    dec = p.analyses.Decompiler(func, cfg=cfg.model)
    code = dec.codegen.text
    print(code)

    code = code.replace(" ", "").replace("\n", "")
    # s_1a += 1 should not be wrapped inside any if-statements. it is always reachable.
    assert "}v4=v4+1;}" in code


def test_decompilation_excessive_goto_removal():
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "bf")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(data_references=True, normalize=True)

    func = cfg.functions[0x100003890]

    dec = p.analyses.Decompiler(func, cfg=cfg.model)
    code = dec.codegen.text
    print(code)

    assert "goto" not in code


def test_decompiling_fauxware_mipsel():
    bin_path = os.path.join(test_location, "mipsel", "fauxware")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(data_references=True, normalize=True)
    func = cfg.functions['main']

    dec = p.analyses.Decompiler(func, cfg=cfg.model)
    code = dec.codegen.text
    print(code)

    # The function calls must be correctly decompiled
    assert "puts(" in code
    assert "read(" in code
    assert "authenticate()" in code
    # The string references must be correctly recovered
    assert '"Username: "' in code
    assert '"Password: "' in code


def test_stack_canary_removal_x8664_extra_exits():

    # Test stack canary removal on functions with extra exit nodes (e.g., assert(false);) without stack canary checks
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "babyheap_level1_teaching1")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(data_references=True, normalize=True)
    func = cfg.functions['main']

    dec = p.analyses.Decompiler(func, cfg=cfg.model)
    code = dec.codegen.text
    print(code)

    # We should not find "__stack_chk_fail" in the code
    assert "__stack_chk_fail" not in code


def test_ifelseif_x8664():

    # nested if-else should be transformed to cascading if-elseif constructs
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "babyheap_level1_teaching1")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(data_references=True, normalize=True)
    func = cfg.functions['main']

    dec = p.analyses.Decompiler(func, cfg=cfg.model)
    code = dec.codegen.text

    print(code)
    assert code.count("else if") == 3


if __name__ == "__main__":
    for k, v in list(globals().items()):
        if k.startswith('test_') and callable(v):
            v()
