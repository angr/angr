import os

import networkx

import angr
import angr.analyses.decompiler
from angr.analyses.decompiler.structuring import DreamStructurer

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests")


class DummyNode:
    def __init__(self, n):
        self.n = n

    def __hash__(self):
        return hash(self.n)

    def __eq__(self, other):
        return isinstance(other, DummyNode) and self.n == other.n or isinstance(other, int) and self.n == other

    @property
    def addr(self):
        return self.n

    def __repr__(self):
        return "<Node %d>" % self.n


def d(n):
    return DummyNode(n)


def D(*edge):
    return DummyNode(edge[0]), DummyNode(edge[1])


def test_region_identifier_0():
    g = networkx.DiGraph()

    #
    #       1
    #       |
    #       2
    #      / \
    #     3  4
    #     \  /
    #      5
    #      |
    #      6

    g.add_edges_from(
        [
            D(1, 2),
            D(2, 3),
            D(2, 4),
            D(3, 5),
            D(4, 5),
            D(5, 6),
        ]
    )

    ri = angr.analyses.decompiler.RegionIdentifier(None, graph=g)
    region = ri.region
    assert len(region.graph.nodes()) == 2


def test_region_identifier_1():
    g = networkx.DiGraph()

    #
    #        1
    #        |
    #        2
    #        | \
    #        | 3
    #        | /
    #        4
    #        |
    #        5
    #        | \
    #        | 6
    #        | /
    #        7
    #        |
    #        8

    g.add_edges_from(
        [
            D(1, 2),
            D(2, 3),
            D(3, 4),
            D(2, 4),
            D(4, 5),
            D(5, 6),
            D(6, 7),
            D(5, 7),
            D(7, 8),
        ]
    )

    ri = angr.analyses.decompiler.RegionIdentifier(None, graph=g)
    region = ri.region
    assert len(region.graph.nodes()) == 2


def test_smoketest():
    p = angr.Project(os.path.join(test_location, "x86_64", "all"), auto_load_libs=False, load_debug_info=True)
    cfg = p.analyses.CFG(data_references=True, normalize=True)

    main_func = cfg.kb.functions["main"]

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(main_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(main_func, graph=clinic.graph)

    # structure it
    st = p.analyses[DreamStructurer].prep()(ri.region)

    # simplify it
    _ = p.analyses.RegionSimplifier(main_func, st.result)


def test_smoketest_cm3_firmware():
    p = angr.Project(
        os.path.join(test_location, "armel", "i2c_master_read-nucleol152re.elf"),
        auto_load_libs=False,
        load_debug_info=True,
    )
    cfg = p.analyses.CFG(normalize=True, force_complete_scan=False)

    main_func = cfg.kb.functions["main"]

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(main_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(main_func, graph=clinic.graph)

    # structure it
    p.analyses[DreamStructurer].prep()(ri.region)


def test_simple():
    p = angr.Project(os.path.join(test_location, "x86_64", "all"), auto_load_libs=False, load_debug_info=True)
    cfg = p.analyses.CFG(data_references=True, normalize=True)

    main_func = cfg.kb.functions["main"]

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(main_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(main_func, graph=clinic.graph)

    # structure it
    rs = p.analyses.RecursiveStructurer(ri.region)

    # simplify it
    s = p.analyses.RegionSimplifier(main_func, rs.result)

    codegen = p.analyses.StructuredCodeGenerator(main_func, s.result, cfg=cfg)
    print(codegen.text)


def test_simple_loop():
    p = angr.Project(
        os.path.join(test_location, "x86_64", "cfg_loop_unrolling"), auto_load_libs=False, load_debug_info=True
    )
    cfg = p.analyses.CFG(data_references=True, normalize=True)

    test_func = cfg.kb.functions["test_func"]

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(test_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(test_func, graph=clinic.graph)

    # structure it
    rs = p.analyses.RecursiveStructurer(ri.region)

    # simplify it
    s = p.analyses.RegionSimplifier(test_func, rs.result)

    codegen = p.analyses.StructuredCodeGenerator(test_func, s.result, cfg=cfg)
    print(codegen.text)

    assert len(codegen.map_pos_to_node._posmap) > 1
    assert len(codegen.map_ast_to_pos) > 1


def test_recursive_structuring():
    p = angr.Project(
        os.path.join(test_location, "x86_64", "cfg_loop_unrolling"), auto_load_libs=False, load_debug_info=True
    )
    cfg = p.analyses.CFG(data_references=True, normalize=True)

    test_func = cfg.kb.functions["test_func"]

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(test_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(test_func, graph=clinic.graph)

    # structure it
    rs = p.analyses.RecursiveStructurer(ri.region)

    # simplify it
    s = p.analyses.RegionSimplifier(test_func, rs.result)

    codegen = p.analyses.StructuredCodeGenerator(test_func, s.result, cfg=cfg)
    print(codegen.text)


def test_while_true_break():
    p = angr.Project(
        os.path.join(test_location, "x86_64", "test_decompiler_loops_O0"), auto_load_libs=False, load_debug_info=True
    )
    cfg = p.analyses.CFG(data_references=True, normalize=True)

    test_func = cfg.kb.functions["_while_true_break"]

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(test_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(test_func, graph=clinic.graph)

    # structure it
    rs = p.analyses.RecursiveStructurer(ri.region)

    # simplify it
    s = p.analyses.RegionSimplifier(test_func, rs.result)

    codegen = p.analyses.StructuredCodeGenerator(test_func, s.result, cfg=cfg)

    print(codegen.text)


def test_while():
    p = angr.Project(
        os.path.join(test_location, "x86_64", "test_decompiler_loops_O0"), auto_load_libs=False, load_debug_info=True
    )
    cfg = p.analyses.CFG(data_references=True, normalize=True)

    test_func = cfg.kb.functions["_while"]

    # convert function blocks to AIL blocks
    clinic = p.analyses.Clinic(test_func)

    # recover regions
    ri = p.analyses.RegionIdentifier(test_func, graph=clinic.graph)

    # structure it
    rs = p.analyses.RecursiveStructurer(ri.region)

    # simplify it
    s = p.analyses.RegionSimplifier(test_func, rs.result)

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
