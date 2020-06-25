
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
        dec = p.analyses.Decompiler(f, cfg=cfg)
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
        dec = p.analyses.Decompiler(f, cfg=cfg)
        if dec.codegen is not None:
            print(dec.codegen.text)
        else:
            print("Failed to decompile function %s." % repr(f))


def test_decompiling_loop_x86_64():
    bin_path = os.path.join(test_location, "x86_64", "decompiler", "loop")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses.CFG(normalize=True, data_references=True)
    f = cfg.functions['loop']
    dec = p.analyses.Decompiler(f, cfg=cfg)
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
    dec = p.analyses.Decompiler(f, cfg=cfg)
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
    dec = p.analyses.Decompiler(f, cfg=cfg)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %s." % repr(f))


def test_decompiling_mips_allcmps():
    bin_path = os.path.join(test_location, "mips", "allcmps")
    p = angr.Project(bin_path, auto_load_libs=False, load_debug_info=True)

    cfg = p.analyses.CFG(collect_data_references=True, normalize=True)

    f = cfg.functions['main']
    dec = p.analyses.Decompiler(f, cfg=cfg)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %s." % repr(f))


def test_decompiling_linked_list():
    bin_path = os.path.join(test_location, "x86_64", "linked_list")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(normalize=True, data_references=True)

    f = cfg.functions['sum']
    dec = p.analyses.Decompiler(f, cfg=cfg)
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
    dec = p.analyses.Decompiler(f, cfg=cfg)
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
    dec = p.analyses.Decompiler(f, cfg=cfg)
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
    dec = p.analyses.Decompiler(f, cfg=cfg)
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
    dec = p.analyses.Decompiler(f, cfg=cfg)

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

    f = cfg.functions['main']
    dec = p.analyses.Decompiler(f, cfg=cfg)
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

    f = cfg.functions['main']
    dec = p.analyses.Decompiler(f, cfg=cfg)
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


def test_decompiling_1after999():

    # the doit() function has an abnormal loop at 0x1d47 - 0x1da1 - 0x1d73

    bin_path = os.path.join(test_location, "x86_64", "1after909")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(normalize=True, data_references=True)

    # verify_password
    f = cfg.functions['verify_password']
    dec = p.analyses.Decompiler(f, cfg=cfg)
    if dec.codegen is not None:
        code = dec.codegen.text
        print(code)
    else:
        print("Failed to decompile function %r." % f)
        assert False

    # doit
    f = cfg.functions['doit']
    optimization_passes = angr.analyses.decompiler.optimization_passes.get_default_optimization_passes(
        p.arch, p.simos.name
    ) + [
        angr.analyses.decompiler.optimization_passes.EagerReturnsSimplifier,
    ]
    dec = p.analyses.Decompiler(f, cfg=cfg, optimization_passes=optimization_passes)
    if dec.codegen is not None:
        code = dec.codegen.text
        print(code)
        # with EagerReturnSimplifier applied, there should be no goto!
        assert "goto" not in code.lower()
    else:
        print("Failed to decompile function %r." % f)
        assert False


def test_decompiling_libsoap():

    bin_path = os.path.join(test_location, "armel", "libsoap.so")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(data_references=True, normalize=True)

    func = cfg.functions[0x41d000]
    dec = p.analyses.Decompiler(func, cfg=cfg)
    if dec.codegen is not None:
        code = dec.codegen.text
        print(code)
        assert code
    else:
        print("Failed to decompile function %r." % func)
        assert False


def test_decompiling_strings_local_strlen():
    bin_path = os.path.join(test_location, "x86_64", "types", "strings")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(data_references=True, normalize=True)
    func = cfg.functions['local_strlen']

    _ = p.analyses.VariableRecoveryFast(func)
    cca = p.analyses.CallingConvention(func, cfg=cfg)
    func.calling_convention = cca.cc

    dec = p.analyses.Decompiler(func, cfg=cfg)
    assert dec.codegen is not None, "Failed to decompile function %r." % func

    code = dec.codegen.text
    print(code)
    # Make sure argument a0 is correctly typed to char*
    lines = code.split("\n")
    assert "local_strlen(char* a0)" in lines[0], "Argument a0 seems to be incorrectly typed: %s" % lines[0]


def test_decompiling_strings_local_strcat():
    bin_path = os.path.join(test_location, "x86_64", "types", "strings")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(data_references=True, normalize=True)
    func = cfg.functions['local_strcat']

    _ = p.analyses.VariableRecoveryFast(func)
    cca = p.analyses.CallingConvention(func, cfg=cfg)
    func.calling_convention = cca.cc

    dec = p.analyses.Decompiler(func, cfg=cfg)
    assert dec.codegen is not None, "Failed to decompile function %r." % func

    code = dec.codegen.text
    print(code)
    # Make sure argument a0 is correctly typed to char*
    lines = code.split("\n")
    assert "local_strcat(char* a0, char* a1)" in lines[0], \
        "Argument a0 and a1 seem to be incorrectly typed: %s" % lines[0]


def test_decompiling_strings_local_strcat_with_local_strlen():
    bin_path = os.path.join(test_location, "x86_64", "types", "strings")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(data_references=True, normalize=True)
    func_strlen = cfg.functions['local_strlen']
    _ = p.analyses.VariableRecoveryFast(func_strlen)
    cca = p.analyses.CallingConvention(func_strlen, cfg=cfg)
    func_strlen.calling_convention = cca.cc
    p.analyses.Decompiler(func_strlen, cfg=cfg)

    func = cfg.functions['local_strcat']

    _ = p.analyses.VariableRecoveryFast(func)
    cca = p.analyses.CallingConvention(func, cfg=cfg)
    func.calling_convention = cca.cc

    dec = p.analyses.Decompiler(func, cfg=cfg)
    assert dec.codegen is not None, "Failed to decompile function %r." % func

    code = dec.codegen.text
    print(code)
    # Make sure argument a0 is correctly typed to char*
    lines = code.split("\n")
    assert "local_strcat(char* a0, char* a1)" in lines[0], \
        "Argument a0 and a1 seem to be incorrectly typed: %s" % lines[0]


if __name__ == "__main__":
    for k, v in list(globals().items()):
        if k.startswith('test_') and callable(v):
            v()
