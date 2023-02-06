import os

import angr
import angr.analyses.decompiler

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


def test_smoketest():
    p = angr.Project(os.path.join(test_location, "x86_64", "all"), auto_load_libs=False)
    cfg = p.analyses.CFG(normalize=True)

    main_func = cfg.kb.functions["main"]

    _ = p.analyses.RegionIdentifier(main_func)


if __name__ == "__main__":
    test_smoketest()
