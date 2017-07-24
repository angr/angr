

import os

import nose.tools

import angr
from angr.analyses.clinic import Clinic


def test_smoketest():

    p = angr.Project(os.path.join('..', '..', 'binaries', 'tests', 'x86_64', 'all'), auto_load_libs=False)
    cfg = p.analyses.CFG(normalize=True)

    main_func = cfg.kb.functions['main']

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(main_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(main_func, graph=clinic.graph)

    # structure it
    st = p.analyses.Structurer(ri.region)

    import ipdb; ipdb.set_trace()


if __name__ == "__main__":
    test_smoketest()
