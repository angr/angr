#!/usr/bin/env python

import os
import logging
import time
l = logging.getLogger("angr.tests.slicing")

import nose

try:
    import standard_logging
    import angr_debug
except ImportError:
    pass

import angr
import simuvex

# Load the tests
test_location = str(os.path.dirname(os.path.realpath(__file__)))

def test_control_flow_slicing():
    slicing_test = angr.Project(test_location + "/blob/x86_64/cfg_1",
                                use_sim_procedures=True,
                                default_analysis_mode='symbolic')
    l.info("Control Flow Slicing")
    start = time.time()
    cfg = slicing_test.analyses.CFG(context_sensitivity_level=2)
    end = time.time()
    duration = end - start
    l.info("CFG generation is done in %f seconds.", duration)

    target = cfg.get_any_irsb(0x400594)
    bs = slicing_test.analyses.BackwardSlice(cfg, None, None, target, -1, control_flow_slice=True)
    anno_cfg = bs.annotated_cfg()
    nose.tools.assert_equal(anno_cfg.get_whitelisted_statements(0x40057c), None)
    nose.tools.assert_equal(anno_cfg.get_whitelisted_statements(0x400594), None)
    nose.tools.assert_equal(anno_cfg.get_whitelisted_statements(0x4005a4), [ ])

def test_backward_slicing():
    slicing_test = angr.Project(test_location + "/blob/x86_64/cfg_1",
                                use_sim_procedures=True,
                                default_analysis_mode='symbolic')
    l.info("Control Flow Slicing")
    start = time.time()
    cfg = slicing_test.analyses.CFG(context_sensitivity_level=2)
    end = time.time()
    duration = end - start
    l.info("CFG generation is done in %f seconds.", duration)

    cdg = slicing_test.analyses.CDG()
    ddg = slicing_test.analyses.DDG(cfg=cfg)

    target = cfg.get_any_irsb(0x4005d3)
    bs = slicing_test.analyses.BackwardSlice(cfg, cdg, ddg, target, -1, control_flow_slice=False)
    anno_cfg = bs.annotated_cfg()
    nose.tools.assert_not_equal(anno_cfg.get_whitelisted_statements(0x40057c), None)
    nose.tools.assert_not_equal(anno_cfg.get_whitelisted_statements(0x400594), None)
    nose.tools.assert_not_equal(anno_cfg.get_whitelisted_statements(0x4005a4), None)

if __name__ == "__main__":
    logging.getLogger("angr.cfg").setLevel(logging.DEBUG)
    test_control_flow_slicing()
    test_backward_slicing()
