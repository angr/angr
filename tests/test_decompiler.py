
import os

import angr

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests'))


def test_decompiling_all_x86_64():
    bin_path = os.path.join(test_location, "x86_64", "all")
    p = angr.Project(bin_path, auto_load_libs=False)

    cfg = p.analyses.CFG(collect_data_references=True)
    for f in cfg.functions.values():
        dec = p.analyses.Decompiler(f, cfg=cfg)
        if dec.codegen is not None:
            print(dec.codegen.text)
        else:
            print("Failed to decompile function %s." % repr(f))


if __name__ == "__main__":
    test_decompiling_all_x86_64()
