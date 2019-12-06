import os

import angr
import angr.analyses.decompiler


def test_smoketest():
    binary_path = os.path.join(os.path.dirname(os.path.realpath(str(__file__))), '..', '..', 'binaries', 'tests', 'x86_64', 'all')
    proj = angr.Project(binary_path, auto_load_libs=False)

    cfg = proj.analyses.CFG()
    main_func = cfg.kb.functions['main']

    proj.analyses.Clinic(main_func)


if __name__ == "__main__":
    test_smoketest()
