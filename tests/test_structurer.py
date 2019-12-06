
import os

import nose.tools

import angr
import angr.analyses.decompiler

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


def test_smoketest():

    p = angr.Project(os.path.join(test_location, 'x86_64', 'all'), auto_load_libs=False)
    cfg = p.analyses.CFG(data_references=True, normalize=True)

    main_func = cfg.kb.functions['main']

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(main_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(main_func, graph=clinic.graph)

    # structure it
    st = p.analyses.Structurer(ri.region)  # pylint:disable=unused-variable

    # simplify it
    _ = p.analyses.RegionSimplifier(st.result)


def test_smoketest_cm3_firmware():

    p = angr.Project(os.path.join(test_location, 'armel', 'i2c_master_read-nucleol152re.elf'), auto_load_libs=False)
    cfg = p.analyses.CFG(normalize=True,
                         force_complete_scan=False)

    main_func = cfg.kb.functions['main']

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(main_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(main_func, graph=clinic.graph)

    # structure it
    st = p.analyses.Structurer(ri.region)  # pylint:disable=unused-variable


def test_simple():

    p = angr.Project(os.path.join(test_location, 'x86_64', 'all'), auto_load_libs=False)
    cfg = p.analyses.CFG(data_references=True, normalize=True)

    main_func = cfg.kb.functions['main']

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(main_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(main_func, graph=clinic.graph)

    # structure it
    rs = p.analyses.RecursiveStructurer(ri.region)

    # simplify it
    s = p.analyses.RegionSimplifier(rs.result)

    codegen = p.analyses.StructuredCodeGenerator(main_func, s.result, cfg=cfg)
    print(codegen.text)


def test_simple_loop():

    p = angr.Project(os.path.join(test_location, 'x86_64', 'cfg_loop_unrolling'), auto_load_libs=False)
    cfg = p.analyses.CFG(data_references=True, normalize=True)

    test_func = cfg.kb.functions['test_func']

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(test_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(test_func, graph=clinic.graph)

    # structure it
    rs = p.analyses.RecursiveStructurer(ri.region)

    # simplify it
    s = p.analyses.RegionSimplifier(rs.result)

    codegen = p.analyses.StructuredCodeGenerator(test_func, s.result, cfg=cfg)
    print(codegen.text)

    nose.tools.assert_greater(len(codegen.posmap._posmap), 1)
    nose.tools.assert_greater(len(codegen.nodemap), 1)


def test_recursive_structuring():
    p = angr.Project(os.path.join(test_location, 'x86_64', 'cfg_loop_unrolling'),
                     auto_load_libs=False)
    cfg = p.analyses.CFG(data_references=True, normalize=True)

    test_func = cfg.kb.functions['test_func']

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(test_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(test_func, graph=clinic.graph)

    # structure it
    rs = p.analyses.RecursiveStructurer(ri.region)

    # simplify it
    s = p.analyses.RegionSimplifier(rs.result)

    codegen = p.analyses.StructuredCodeGenerator(test_func, s.result, cfg=cfg)
    print(codegen.text)


def test_while_true_break():
    p = angr.Project(os.path.join(test_location, 'x86_64', 'test_decompiler_loops_O0'),
                     auto_load_libs=False)
    cfg = p.analyses.CFG(data_references=True, normalize=True)

    test_func = cfg.kb.functions['_while_true_break']

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(test_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(test_func, graph=clinic.graph)

    # structure it
    rs = p.analyses.RecursiveStructurer(ri.region)

    # simplify it
    s = p.analyses.RegionSimplifier(rs.result)

    codegen = p.analyses.StructuredCodeGenerator(test_func, s.result, cfg=cfg)

    print(codegen.text)


def test_while():
    p = angr.Project(os.path.join(test_location, 'x86_64', 'test_decompiler_loops_O0'),
                     auto_load_libs=False)
    cfg = p.analyses.CFG(data_references=True, normalize=True)

    test_func = cfg.kb.functions['_while']

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(test_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(test_func, graph=clinic.graph)

    # structure it
    rs = p.analyses.RecursiveStructurer(ri.region)

    # simplify it
    s = p.analyses.RegionSimplifier(rs.result)

    codegen = p.analyses.StructuredCodeGenerator(test_func, s.result, cfg=cfg)

    print(codegen.text)


if __name__ == "__main__":
    test_smoketest()
    test_simple()
    test_simple_loop()
    test_recursive_structuring()
    test_while_true_break()
    test_while()
    test_smoketest_cm3_firmware()
