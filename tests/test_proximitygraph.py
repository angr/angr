import os

import angr

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


def test_fauxware():
    bin_path = os.path.join(test_location, "x86_64", "fauxware")
    proj = angr.Project(bin_path, auto_load_libs=False)

    cfg = proj.analyses.CFG(data_references=True, cross_references=True, normalize=True)
    func = cfg.kb.functions["main"]

    proj.analyses.Proximity(func, cfg.model, cfg.kb.xrefs)

    # once we have decompiled code, things are different...
    dec = proj.analyses.Decompiler(func, cfg=cfg.model)
    proj.analyses.Proximity(func, cfg.model, cfg.kb.xrefs, decompilation=dec)


if __name__ == "__main__":
    test_fauxware()
