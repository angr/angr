
import os

import nose.tools

import angr
import angr.analyses.decompiler

def test_smoketest():

    p = angr.Project(os.path.join('..', '..', 'binaries', 'tests', 'x86_64', 'all'), auto_load_libs=False)
    cfg = p.analyses.CFG(normalize=True)

    main_func = cfg.kb.functions['main']

    st = p.analyses.RegionIdentifier(main_func)

    import ipdb; ipdb.set_trace()


if __name__ == "__main__":
    test_smoketest()
