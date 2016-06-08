import sys
import time
import os
import logging

import nose

import angr
import simuvex
import claripy

l = logging.getLogger("angr_tests")

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

vfg_0_addresses = {
    'x86_64': 0x40055c
}

def run_vfg_0(arch):
    proj = angr.Project(os.path.join(os.path.join(test_location, arch), "basic_buffer_overflows"),
                 use_sim_procedures=True,
                 default_analysis_mode='symbolic')

    cfg = proj.analyses.CFGAccurate(context_sensitivity_level=1)

    # For this test case, OPTIMIZE_IR does not work due to the way we are widening the states: an index variable
    # directly goes to 0xffffffff, and when OPTIMIZE_IR is used, it does a signed comparison with 0x27, which
    # eventually leads to the merged index variable covers all negative numbers and [0, 27]. This analysis result is
    # correct but not accurate, and we suffer from it in this test case.
    # The ultimate solution is to widen more carefully, or implement lookahead widening support.
    # TODO: Solve this issue later

    start = time.time()
    function_start = vfg_0_addresses[arch]
    vfg = proj.analyses.VFG(cfg, function_start=function_start, context_sensitivity_level=2, interfunction_level=4,
                            remove_options={ simuvex.s_options.OPTIMIZE_IR }
                            )
    end = time.time()
    duration = end - start

    l.info("VFG generation done in %f seconds.", duration)

    # TODO: These are very weak conditions. Make them stronger!
    nose.tools.assert_greater(len(vfg.final_states), 0)
    states = vfg.final_states
    nose.tools.assert_equal(len(states), 2)
    stack_check_fail = proj._extern_obj.get_pseudo_addr('symbol hook: __stack_chk_fail')
    nose.tools.assert_equal(set([ s.se.exactly_int(s.ip) for s in states ]),
                            {
                                stack_check_fail,
                                0x4005b4
                            })

    state = [ s for s in states if s.se.exactly_int(s.ip) == 0x4005b4 ][0]
    nose.tools.assert_true(claripy.backends.vsa.is_true(state.stack_read(12, 4) >= 0x28))

def broken_vfg_0():
    # Test for running VFG on a single function
    for arch in vfg_0_addresses:
        yield run_vfg_0, arch

vfg_1_addresses = {
    'x86_64': { 0x40071d, # main
                0x400510, # _puts
                0x40073e, # main
                0x400530, # _read
                0x400754, # main
                0x40076a, # main
                0x400774, # main
                0x40078a, # main
                0x4007a0, # main
                0x400664, # authenticate
                0x400550, # _strcmp
                0x40068e, # authenticate
                0x400699, # authenticate
                0x400560, # _open
                0x4006af, # authenticate
                0x4006c8, # authenticate
                0x4006db, # authenticate
                0x400692, # authenticate
                0x4006df, # authenticate
                0x4006e6, # authenticate
                0x4006eb, # authenticate
                0x4007bd, # main
                0x4006ed, # accepted
                0x4006fb, # accepted
                0x4007c7, # main
                0x4007c9, # main
                0x4006fd, # rejected
                0x400520, # _printf
                0x400713, # rejected
                0x400570, # _exit
            }
}

def run_vfg_1(arch):
    proj = angr.Project(
        os.path.join(os.path.join(test_location, arch), "fauxware"),
        use_sim_procedures=True,
    )

    cfg = proj.analyses.CFGAccurate()
    vfg = proj.analyses.VFG(cfg, function_start=0x40071d, context_sensitivity_level=10, interfunction_level=10)

    all_block_addresses = set([ n.addr for n in vfg.graph.nodes() ])
    nose.tools.assert_true(vfg_1_addresses[arch].issubset(all_block_addresses))

def test_vfg_1():
    # Test the code coverage of VFG
    for arch in vfg_1_addresses:
        yield run_vfg_1, arch

if __name__ == "__main__":
    # logging.getLogger("simuvex.plugins.abstract_memory").setLevel(logging.DEBUG)
    # logging.getLogger("simuvex.plugins.symbolic_memory").setLevel(logging.DEBUG)
    # logging.getLogger("angr.analyses.cfg").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.vfg").setLevel(logging.DEBUG)
    # Temporarily disable the warnings of claripy backend
    # logging.getLogger("claripy.backends.backend").setLevel(logging.ERROR)
    # logging.getLogger("claripy.claripy").setLevel(logging.ERROR)

    if len(sys.argv) == 1:
        # TODO: Actually run all tests
        # Run all tests

        g = globals()

        for f in g.keys():
            if f.startswith('test_') and hasattr(g[f], '__call__'):
                for test_func, arch_name in globals()[f]():
                    test_func(arch_name)

    else:
        f = 'test_' + sys.argv[1]
        if f in globals():
            func = globals()[f]
            if hasattr(func, '__call__'):
                for test_func, arch in func():
                    test_func(arch)
            else:
                print '"%s" does not exist, or is not a callable' % f
