

import os

import nose.tools

import angr
import angr.analyses.decompiler


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

def test_simple_loop():

    p = angr.Project(os.path.join('..', '..', 'binaries', 'tests', 'x86_64', 'cfg_loop_unrolling'), auto_load_libs=False)
    cfg = p.analyses.CFG(normalize=True)

    test_func = cfg.kb.functions['test_func']

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(test_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(test_func, graph=clinic.graph)

    # structure it

    st = p.analyses.Structurer(next(node for node in ri.region.graph.nodes() if hasattr(node, 'graph')))

    import ipdb; ipdb.set_trace()

def test_recursive_structuring():
    p = angr.Project(os.path.join('..', '..', 'binaries', 'tests', 'x86_64', 'cfg_loop_unrolling'),
                     auto_load_libs=False)
    cfg = p.analyses.CFG(normalize=True)

    test_func = cfg.kb.functions['test_func']

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(test_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(test_func, graph=clinic.graph)

    # structure it
    rs = p.analyses.RecursiveStructurer(ri.region)

    codegen = p.analyses.StructuredCodeGenerator(rs.result)

    print codegen.text

    import ipdb; ipdb.set_trace()

def test_while_true_break():
    p = angr.Project(os.path.join('..', '..', 'binaries', 'tests', 'x86_64', 'test_decompiler_loops_O0'),
                     auto_load_libs=False)
    cfg = p.analyses.CFG(normalize=True)

    test_func = cfg.kb.functions['_while_true_break']

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(test_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(test_func, graph=clinic.graph)

    # structure it
    rs = p.analyses.RecursiveStructurer(ri.region)

    codegen = p.analyses.StructuredCodeGenerator(rs.result)

    print codegen.text

def test_while():
    p = angr.Project(os.path.join('..', '..', 'binaries', 'tests', 'x86_64', 'test_decompiler_loops_O0'),
                     auto_load_libs=False)
    cfg = p.analyses.CFG(normalize=True)

    test_func = cfg.kb.functions['_while']

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(test_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(test_func, graph=clinic.graph)

    # structure it
    rs = p.analyses.RecursiveStructurer(ri.region)

    codegen = p.analyses.StructuredCodeGenerator(rs.result)

    print codegen.text


if __name__ == "__main__":
    # test_smoketest()
    # test_simple_loop()
    test_recursive_structuring()
    # test_while_true_break()
    # test_while()
