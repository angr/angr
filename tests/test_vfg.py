import sys
import time
import os
import logging

import nose

import angr
import claripy

l = logging.getLogger("angr_tests")

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

vfg_buffer_overflow_addresses = {
    'x86_64': 0x40055c
}

def run_vfg_buffer_overflow(arch):
    proj = angr.Project(os.path.join(test_location, arch, "basic_buffer_overflows"),
                 use_sim_procedures=True,
                 default_analysis_mode='symbolic')

    cfg = proj.analyses.CFGEmulated(context_sensitivity_level=1)

    # For this test case, OPTIMIZE_IR does not work due to the way we are widening the states: an index variable
    # directly goes to 0xffffffff, and when OPTIMIZE_IR is used, it does a signed comparison with 0x27, which
    # eventually leads to the merged index variable covers all negative numbers and [0, 27]. This analysis result is
    # correct but not accurate, and we suffer from it in this test case.
    # The ultimate solution is to widen more carefully, or implement lookahead widening support.
    # TODO: Solve this issue later

    start = time.time()
    function_start = vfg_buffer_overflow_addresses[arch]
    vfg = proj.analyses.VFG(cfg, function_start=function_start, context_sensitivity_level=2, interfunction_level=4,
                            remove_options={ angr.options.OPTIMIZE_IR }
                            )
    end = time.time()
    duration = end - start

    l.info("VFG generation done in %f seconds.", duration)

    # TODO: These are very weak conditions. Make them stronger!
    nose.tools.assert_greater(len(vfg.final_states), 0)
    states = vfg.final_states
    nose.tools.assert_equal(len(states), 2)
    stack_check_fail = proj._extern_obj.get_pseudo_addr('symbol hook: __stack_chk_fail')
    nose.tools.assert_equal(set([ s.solver.eval_one(s.ip) for s in states ]),
                            {
                                stack_check_fail,
                                0x4005b4
                            })

    state = [ s for s in states if s.solver.eval_one(s.ip) == 0x4005b4 ][0]
    nose.tools.assert_true(claripy.backends.vsa.is_true(state.stack_read(12, 4) >= 0x28))

def broken_vfg_buffer_overflow():
    # Test for running VFG on a single function
    for arch in vfg_buffer_overflow_addresses:
        yield run_vfg_buffer_overflow, arch

#
# VFG test case 0
#

def test_vfg_0():
    yield run_vfg_0, 'x86_64'

def run_vfg_0(arch):
    proj = angr.Project(os.path.join(test_location, arch, "vfg_0"), load_options={'auto_load_libs': False})

    cfg = proj.analyses.CFG(normalize=True)
    main = cfg.functions.function(name='main')
    vfg = proj.analyses.VFG(cfg, start=main.addr, context_sensitivity_level=1, interfunction_level=3,
                            record_function_final_states=True, max_iterations=80,
                            )

    function_final_states = vfg._function_final_states
    nose.tools.assert_in(main.addr, function_final_states)

    final_state_main = next(iter(function_final_states[main.addr].values()))
    stdout = final_state_main.posix.dumps(1)

    nose.tools.assert_equal(stdout[:6], b"i = 64")
    # the following does not work without affine relation analysis
    # nose.tools.assert_equal(stdout, "i = 64, j = 63")

#
# VFG test case 1
#

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
        os.path.join(test_location, arch, "fauxware"),
        use_sim_procedures=True,
    )

    cfg = proj.analyses.CFGEmulated()
    vfg = proj.analyses.VFG(cfg, start=0x40071d, context_sensitivity_level=10, interfunction_level=10,
                            record_function_final_states=True
                            )

    all_block_addresses = set([ n.addr for n in vfg.graph.nodes() ])
    nose.tools.assert_true(vfg_1_addresses[arch].issubset(all_block_addresses))

    # return value for functions

    # function authenticate has only two possible return values: 0 and 1
    authenticate = cfg.functions.function(name='authenticate')
    nose.tools.assert_true(authenticate.addr in vfg.function_final_states)
    authenticate_final_states = vfg.function_final_states[authenticate.addr]
    nose.tools.assert_equal(len(authenticate_final_states), 1)
    authenticate_final_state = next(iter(authenticate_final_states.values()))
    nose.tools.assert_is_not_none(authenticate_final_state)
    nose.tools.assert_equal(authenticate_final_state.solver.eval_upto(authenticate_final_state.regs.rax, 3), [0, 1])

    # optimal execution tests
    # - the basic block after returning from `authenticate` should only be executed once
    nose.tools.assert_equal(vfg._execution_counter[0x4007b3], 1)
    # - the last basic block in `authenticate` should only be executed once (on a non-normalized CFG)
    nose.tools.assert_equal(vfg._execution_counter[0x4006eb], 1)

def test_vfg_1():
    # Test the code coverage of VFG
    for arch in vfg_1_addresses:
        yield run_vfg_1, arch

if __name__ == "__main__":
    # logging.getLogger("angr.state_plugins.abstract_memory").setLevel(logging.DEBUG)
    # logging.getLogger("angr.state_plugins.symbolic_memory").setLevel(logging.DEBUG)
    # logging.getLogger("angr.sim_state").setLevel(logging.DEBUG)
    # logging.getLogger("angr.state_plugins.symbolic_memory").setLevel(logging.DEBUG)
    # logging.getLogger("angr.analyses.cfg").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.vfg").setLevel(logging.DEBUG)
    # Temporarily disable the warnings of claripy backend
    # logging.getLogger("claripy.backends.backend").setLevel(logging.ERROR)
    # logging.getLogger("claripy.claripy").setLevel(logging.ERROR)

    if len(sys.argv) == 1:
        # TODO: Actually run all tests
        # Run all tests

        for f in list(globals().keys()):
            if f.startswith('test_') and hasattr(globals()[f], '__call__'):
                for test_func, arch_name in globals()[f]():
                    test_func(arch_name)

    else:
        f = 'test_' + sys.argv[1]
        if f in list(globals()):
            func = globals()[f]
            if hasattr(func, '__call__'):
                for test_func, arch_ in func():
                    test_func(arch_)
            else:
                print('"%s" does not exist, or is not a callable' % f)
