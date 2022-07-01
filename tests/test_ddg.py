#!/usr/bin/env python

import os
import logging
import time
import sys

l = logging.getLogger("angr.tests.test_ddg")

import angr

# Load the tests
test_location = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "..", "..", "binaries", "tests"
)


def perform_one(binary_path):
    proj = angr.Project(
        binary_path,
        load_options={"auto_load_libs": False},
        use_sim_procedures=True,
        default_analysis_mode="symbolic",
    )
    start = time.time()
    cfg = proj.analyses.CFGEmulated(
        context_sensitivity_level=2,
        keep_state=True,
        state_add_options=angr.sim_options.refs,  # refs are necessary for DDG to work
    )
    end = time.time()
    duration = end - start
    l.info("CFG generated in %f seconds.", duration)

    ddg = proj.analyses.DDG(cfg, start=cfg.functions["main"].addr)
    # There should be at least 400 nodes
    assert len(ddg.graph) >= 400

    from angr.code_location import CodeLocation

    # Memory dependency 1

    """
    00 | ------ IMark(0x400667, 3, 0) ------
    01 | t15 = GET:I64(rbp)
    02 | t14 = Add64(t15,0xfffffffffffffffc)
    03 | t17 = LDle:I32(t14)
    04 | t45 = 32Uto64(t17)
    05 | t16 = t45
    06 | PUT(rip) = 0x000000000040066a
    ...
    15 | ------ IMark(0x40066d, 4, 0) ------
    16 | t24 = Add64(t15,0xfffffffffffffffc)
    17 | t7 = LDle:I32(t24)
    18 | t5 = Add32(t7,0x00000001)
    19 | STle(t24) = t5
    20 | PUT(rip) = 0x0000000000400671
    """

    cl1 = CodeLocation(0x400667, ins_addr=0x400667,stmt_idx=3)
    in_edges = ddg.graph.in_edges([cl1], data=True)
    # Where the memory address comes from
    memaddr_src = CodeLocation(0x400667, ins_addr=0x400667, stmt_idx=2)
    # Where the data comes from
    data_src_0 = CodeLocation(0x40064C, ins_addr=0x40065e, stmt_idx=26)
    data_src_1 = CodeLocation(0x400667, ins_addr=0x40066d, stmt_idx=19)
    assert len(in_edges) == 3
    assert (data_src_0, cl1) in [(src, dst) for src, dst, _ in in_edges]
    assert (data_src_1, cl1) in [(src, dst) for src, dst, _ in in_edges]
    assert (
        memaddr_src,
        cl1,
        {"data": 14, "type": "tmp", "subtype": ("mem_addr",)},
    ) in in_edges


def test_ddg_0():
    binary_path = os.path.join(test_location, "x86_64", "datadep_test")
    perform_one(binary_path)


def run_all():
    functions = globals()
    all_functions = dict(
        filter(
            (lambda kv: kv[0].startswith("test_") and hasattr(kv[1], "__call__")),
            functions.items(),
        )
    )
    for f in sorted(all_functions.keys()):
        all_functions[f]()


if __name__ == "__main__":
    logging.getLogger("angr.analyses.cfg").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.ddg").setLevel(logging.DEBUG)

    if len(sys.argv) > 1:
        globals()["test_" + sys.argv[1]]()
    else:
        run_all()
