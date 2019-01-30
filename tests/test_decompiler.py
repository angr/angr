
import os

import angr

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests'))


def test_decompiling_all_x86_64():
    bin_path = os.path.join(test_location, "x86_64", "all")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(collect_data_references=True)
    for f in cfg.functions.values():
        if f.is_simprocedure:
            print("Skipping SimProcedure %s." % repr(f))
            continue
        dec = p.analyses.Decompiler(f, cfg=cfg)
        if dec.codegen is not None:
            print(dec.codegen.text)
        else:
            print("Failed to decompile function %s." % repr(f))


def test_decompiling_all_i386():
    bin_path = os.path.join(test_location, "i386", "all")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(collect_data_references=True)

    f = cfg.functions['main']
    dec = p.analyses.Decompiler(f, cfg=cfg)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %s." % repr(f))


def test_decompiling_aes_armel():
    bin_path = os.path.join(test_location, "armel", "aes")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(collect_data_references=True)

    f = cfg.functions['main']
    dec = p.analyses.Decompiler(f, cfg=cfg)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %s." % repr(f))


def test_decompiling_mips_allcmps():
    bin_path = os.path.join(test_location, "mips", "allcmps")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(collect_data_references=True)

    f = cfg.functions['main']
    dec = p.analyses.Decompiler(f, cfg=cfg)
    if dec.codegen is not None:
        print(dec.codegen.text)
    else:
        print("Failed to decompile function %s." % repr(f))

if __name__ == "__main__":
    test_decompiling_all_x86_64()
    test_decompiling_all_i386()
    test_decompiling_aes_armel()
    test_decompiling_mips_allcmps()
