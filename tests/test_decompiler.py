
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


def test_decompiling_1after999_doit():

    # the doit() function has an abnormal loop at 0x1d47 - 0x1da1 - 0x1d73

    bin_path = os.path.join(test_location, "x86_64", "1after909")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(normalize=True, data_references=True)

    f = cfg.functions['doit']
    dec = p.analyses.Decompiler(f, cfg=cfg)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %r." % f)
        assert False


if __name__ == "__main__":
    for k, v in list(globals().items()):
        if k.startswith('test_') and callable(v):
            v()
