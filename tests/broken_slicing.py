#!/usr/bin/env python

import logging
l = logging.getLogger("angr.tests.slicing")

import time
import nose
import angr

# Load the tests
import os
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

    target = cfg.get_any_node(0x400594)
    bs = slicing_test.analyses.BackwardSlice(cfg, None, None, target, -1, control_flow_slice=True)
    anno_cfg = bs.annotated_cfg()
    nose.tools.assert_equal(anno_cfg.get_whitelisted_statements(0x40057c), None)
    nose.tools.assert_equal(anno_cfg.get_whitelisted_statements(0x400594), None)
    nose.tools.assert_equal(anno_cfg.get_whitelisted_statements(0x4005a4), [ ])

def test_backward_slice():
    slicing_test = angr.Project(test_location + "/blob/x86_64/cfg_1",
                                use_sim_procedures=True,
                                default_analysis_mode='symbolic')
    l.info("Control Flow Slicing")
    start = time.time()
    cfg = slicing_test.analyses.CFG(context_sensitivity_level=2, keep_input_state=True)
    end = time.time()
    duration = end - start
    l.info("CFG generation is done in %f seconds.", duration)

    cdg = slicing_test.analyses.CDG()
    ddg = slicing_test.analyses.DDG(cfg=cfg)

    target = cfg.get_any_node(0x4005d3)
    bs = slicing_test.analyses.BackwardSlice(cfg, cdg, ddg, target, -1, control_flow_slice=False)
    anno_cfg = bs.annotated_cfg()
    nose.tools.assert_not_equal(anno_cfg.get_whitelisted_statements(0x40057c), None)
    nose.tools.assert_not_equal(anno_cfg.get_whitelisted_statements(0x400594), None)
    nose.tools.assert_not_equal(anno_cfg.get_whitelisted_statements(0x4005a4), None)

def test_last_branching_statement():
    slicing_test = angr.Project(test_location + '/blob/armel/fauxware',
                                use_sim_procedures=True)
    l.info('Testing _search_for_last_branching_statement.')

    '''
    The IRSB:
    IRSB {
       t0:Ity_I32 t1:Ity_I32 t2:Ity_I32 t3:Ity_I32 t4:Ity_I32 t5:Ity_I32 t6:Ity_I32 t7:Ity_I32 t8:Ity_I32 t9:Ity_I32 t10:Ity_I32 t11:Ity_I32 t12:Ity_I32 t13:Ity_I32 t14:Ity_I32 t15:Ity_I32 t16:Ity_I32 t17:Ity_I32 t18:Ity_I32 t19:Ity_I32 t20:Ity_I32 t21:Ity_I32 t22:Ity_I32 t23:Ity_I1 t24:Ity_I32

       00 | IR-NoOp
       01 | IR-NoOp
       02 | IR-NoOp
       03 | IR-NoOp
       04 | IR-NoOp
       05 | IR-NoOp
       06 | IR-NoOp
       07 | IR-NoOp
       08 | IR-NoOp
       09 | IR-NoOp
       10 | IR-NoOp
       11 | IR-NoOp
       12 | IR-NoOp
       13 | IR-NoOp
       14 | IR-NoOp
       15 | ------ IMark(0x86dc, 4, 0) ------
       16 | t1 = GET:I32(8)
       17 | t0 = t1
       18 | t2 = t0
       19 | PUT(20) = t2
       20 | PUT(68) = 0x000086e0
       21 | ------ IMark(0x86e0, 4, 0) ------
       22 | t14 = GET:I32(52)
       23 | t13 = Sub32(t14,0x00000024)
       24 | t3 = t13
       25 | t4 = GET:I32(52)
       26 | t5 = GET:I32(20)
       27 | STle(t3) = t5
       28 | PUT(68) = 0x000086e4
       29 | ------ IMark(0x86e4, 4, 0) ------
       30 | t16 = GET:I32(52)
       31 | t15 = Sub32(t16,0x00000024)
       32 | t6 = t15
       33 | t7 = GET:I32(52)
       34 | t8 = LDle:I32(t6)
       35 | PUT(20) = t8
       36 | PUT(68) = 0x000086e8
       37 | ------ IMark(0x86e8, 4, 0) ------
       38 | t9 = GET:I32(20)
       39 | t10 = 0x00000000
       40 | t11 = 0x00000000
       41 | PUT(72) = 0x00000002
       42 | PUT(76) = t9
       43 | PUT(80) = t10
       44 | PUT(84) = t11
       45 | PUT(68) = 0x000086ec
       46 | ------ IMark(0x86ec, 4, 0) ------
       47 | t18 = GET:I32(72)
       48 | t17 = Or32(t18,0x00000000)
       49 | t19 = GET:I32(76)
       50 | t20 = GET:I32(80)
       51 | t21 = GET:I32(84)
       52 | t22 = armg_calculate_condition(t17,t19,t20,t21):Ity_I32
       53 | t12 = t22
       54 | t23 = 32to1(t12)
       55 | if (t23) goto {Ijk_Boring} 0x86f8
       56 | PUT(68) = 0x000086f0
       57 | t24 = GET:I32(68)
       NEXT: PUT(68) = t24; Ijk_Boring
    }

    '''

    target = slicing_test.path_generator.blank_path(address=0x86dc).next_run
    target.irsb.pp()

    bs = slicing_test.analyses.BackwardSlice(None, None, None, target, -1, no_construct=True)

    stmt_idx, tmp = bs._last_branching_statement(target.statements)

    nose.tools.assert_equal(stmt_idx, 22)
    nose.tools.assert_equal(tmp, 23)

if __name__ == "__main__":
    try:
        __import__('standard_logging')
        __import__('angr_debug')
    except ImportError:
        pass

    logging.getLogger("angr.cfg").setLevel(logging.DEBUG)
    test_last_branching_statement()
    test_control_flow_slicing()
    test_backward_slice()
