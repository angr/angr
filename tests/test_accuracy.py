import nose
import angr

import os
test_location = os.path.join(os.path.dirname(os.path.realpath(str(__file__))), '../../binaries/tests/')

arch_data = { # (steps, [hit addrs], finished)
    'x86_64':  (330, (0x1021c20, 0x1021980, 0x1021be0, 0x4004b0, 0x400440, 0x400570), True),  # Finishes
    'i386':    (213, (0x90198e0, 0x90195c0, 0x9019630, 0x90198a0, 0x8048370, 0x80482f8, 0x8048440), False),  # blocked on syscalls
    'ppc':     (62,  (0x11022f50, 0x11022eb0, 0x10000340, 0x100002e8), False),    # blocked on syscalls
    'ppc64':   (183, (0x11047490, 0x100003fc, 0x10000368), False),       # blocked on syscalls
    'mips':    (158, (0x1016f20, 0x400500, 0x400470), False),    # blocked on some very weird TLS initialization?
    'mips64':  (190, (0x12103b828, 0x120000870, 0x1200007e0), False),    # blocked on some io initialization
    'armel':   (153, (0x10154b8, 0x1108244, 0x83a8, 0x8348, 0x84b0), False),     # blocked on __kuser_cmpxchg
    'aarch64': (197, (0x1020b04, 0x400430, 0x4003b8, 0x400538), False),        # blocked on syscalls
}

def emulate(p, steps, hit_addrs, finished):
    state = p.factory.full_init_state(args=['./test_arrays'], add_options={angr.options.STRICT_PAGE_ACCESS, angr.options.ENABLE_NX, angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.USE_SYSTEM_TIMES})

    pg = p.factory.simulation_manager(state, resilience=True)
    pg2 = pg.run(until=lambda lpg: len(lpg.active) != 1)

    is_finished = False
    if len(pg2.active) > 0:
        state = pg2.active[0]
    elif len(pg2.deadended) > 0:
        state = pg2.deadended[0]
        is_finished = True
    elif len(pg2.errored) > 0:
        state = pg2.errored[0].state # ErroredState object!
    else:
        raise ValueError("The result does not contain a state we can use for this test?")

    nose.tools.assert_greater_equal(state.history.depth, steps)

    # this is some wonky control flow that asserts that the items in hit_addrs appear in the state in order.
    trace = state.history.bbl_addrs.hardcopy
    reqs = list(hit_addrs)
    while len(reqs) > 0:
        req = reqs.pop(0)
        while True:
            nose.tools.assert_greater(len(trace), 0)
            trace_head = trace.pop(0)
            if trace_head == req:
                break
            nose.tools.assert_not_in(trace_head, reqs)

    if finished:
        nose.tools.assert_true(is_finished)

def test_emulation():
    for arch in arch_data:
        steps, hit_addrs, finished = arch_data[arch]
        filepath = test_location + arch + '/test_arrays'
        p = angr.Project(filepath, use_sim_procedures=False)
        yield emulate, p, steps, hit_addrs, finished

def test_windows():
    yield emulate, angr.Project(test_location + 'i386/test_arrays.exe'), 49, [], False # blocked on GetLastError or possibly dynamic loading

def test_locale():
    p = angr.Project(test_location + 'i386/isalnum', use_sim_procedures=False)
    state = p.factory.full_init_state(args=['./isalnum'], add_options={angr.options.STRICT_PAGE_ACCESS})
    pg = p.factory.simgr(state)
    pg2 = pg.run(until=lambda lpg: len(lpg.active) != 1,
                  step_func=lambda lpg: lpg if len(lpg.active) == 1 else lpg.prune()
                 )
    nose.tools.assert_equal(len(pg2.active), 0)
    nose.tools.assert_equal(len(pg2.deadended), 1)
    nose.tools.assert_equal(pg2.deadended[0].history.events[-1].type, 'terminate')
    nose.tools.assert_equal(pg2.deadended[0].history.events[-1].objects['exit_code']._model_concrete.value, 0)


if __name__ == '__main__':
    print 'locale'
    test_locale()
    for func, a, b, c, d in test_emulation():
        print a.filename
        func(a, b, c, d)
    for func, a, b, c, d in test_windows():
        print a.filename
        func(a, b, c, d)
