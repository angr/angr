#!/usr/bin/env python

import logging
import time
import sys

from os.path import join, dirname, realpath

l = logging.getLogger("angr.tests.test_dfg")

import nose
import angr
import pyvex

test_location = str(join(dirname(realpath(__file__)), "../../binaries/tests"))

def perform_one(binary_path):
    proj = angr.Project(join(test_location, binary_path),
                        load_options={'auto_load_libs': False},
                        )
    start = time.time()
    cfg = proj.analyses.CFGAccurate(context_sensitivity_level=2, fail_fast=True)
    end = time.time()
    duration = end - start
    l.info("CFG generated in %f seconds.", duration)

    dfg = proj.analyses.DFG(cfg=cfg, fail_fast=True)
    nose.tools.assert_true(len(dfg.dfgs) <= len(cfg.nodes()))
    for addr, d in dfg.dfgs.items():
        nose.tools.assert_true(cfg.get_any_node(addr) is not None)
        # We check there is not node that we ignored
        for n in d.nodes():
            nose.tools.assert_not_equal(n.tag, 'Ist_IMark')
            nose.tools.assert_not_equal(n.tag, 'Ist_AbiHint')
            nose.tools.assert_not_equal(n.tag, 'Ist_Exit')
            if n.tag == 'Ist_Put':
                nose.tools.assert_not_equal(n.offset, proj.arch.ip_offset)

        for (a, b) in d.edges():
            if isinstance(a, pyvex.IRExpr.IRExpr):
                # We check that there is no edge between two expressions/const
                nose.tools.assert_false(isinstance(b, pyvex.IRExpr.IRExpr))

                # If there is an edge coming from an expr/const it should be in
                # the dependencies of the other node
                # FIXME
                # Impossible to check because of the Unop optimization in the
                # DFG...
                # nose.tools.assert_true(a in b.expressions)
            elif hasattr(a, 'tmp'):
                # If there is an edge between a tmp and another node
                # be sure that this tmp is in the dependencies of this node
                tmps = [ ]
                for e in b.expressions:
                    if hasattr(e, 'tmp'):
                        tmps.append(e.tmp)

                nose.tools.assert_true(a.tmp in tmps)


def test_dfg_isalnum():
    perform_one("i386/isalnum")


def test_dfg_counter():
    perform_one("i386/counter")


def test_dfg_cfg_0():
    perform_one("x86_64/cfg_0")


def test_dfg_fauxware():
    perform_one("mips/fauxware")


def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_') and hasattr(v, '__call__')), functions.items()))
    for f in sorted(all_functions.keys()):
        all_functions[f]()


if __name__ == "__main__":
    l.setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.dfg").setLevel(logging.DEBUG)

    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        run_all()
