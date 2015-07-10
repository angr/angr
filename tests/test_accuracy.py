import angr
import nose

import os
test_location = os.path.join(os.path.dirname(os.path.realpath(str(__file__))), '../../binaries/tests/')

arch_data = { # (steps, [hit addrs], finished)
    'x86_64':  (490, (0x1021c20, 0x1021980), False),  # AAAAAAAAAAAAAAAAAAAAAAA
    'i386':    (356, (0x90198e0, 0x90195c0, 0x9019630), False),  # blocked on syscalls on my libc, bogged down in initializers here....
    'ppc':     (197, (0x11022f50, 0x11022eb0, 0x10000340, 0x100002e8), False),  # blocked on syscalls
    'ppc64':   (184,  (0x11047490, 0x100003fc, 0x10000368), False),     # blocked on syscalls
    'mips':    (160, (0x1016f20, 0x400500, 0x400470), False),
    'mips64':  (191, (0x12103b828, 0x120000870, 0x1200007e0), False),
    'armel':   (154, (0x10154b8, 0x1108244, 0x83a8, 0x8348, 0x84b0), False),     # blocked on __kuser_cmpxchg
    'aarch64': (198, (0x1020b04, 0x400430, 0x4003b8, 0x400538), False),
}

def emulate(arch):
    steps, hit_addrs, finished = arch_data[arch]
    filepath = test_location + arch + '/test_arrays'
    p = angr.Project(filepath, use_sim_procedures=False)
    pg = p.path_group([p.path_generator.full_init(args=['./test_arrays'])])
    pg2 = pg.step(until=lambda lpg: len(lpg.active) != 1,
                  step_func=lambda lpg: lpg if len(lpg.active) == 1 else lpg.prune()
                  )

    is_finished = False
    if len(pg2.active) > 0:
        path = pg2.active[0]
    elif len(pg2.deadended) > 0:
        path = pg2.deadended[0]
        is_finished = True
    elif len(pg2.errored) > 0:
        path = pg2.errored[0]
    else:
        raise ValueError("This pathgroup does not contain a path we can use for this test?")

    nose.tools.assert_greater_equal(path.length, steps)

    # this is some wonky control flow that asserts that the items in hit_addrs appear in the path in order.
    trace = list(path.addr_backtrace)
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
        yield emulate, arch

if __name__ == '__main__':
    print 'x86_64'
    emulate('x86_64')
    print 'i386'
    emulate('i386')
    print 'ppc'
    emulate('ppc')
    print 'ppc64'
    emulate('ppc64')
    print 'mips'
    emulate('mips')
    print 'mips64'
    emulate('mips64')
    print 'armel'
    emulate('armel')
    print 'aarch64'
    emulate('aarch64')
