import gc
import os
import pickle
import logging
import sys
import nose
import angr

from nose.plugins.attrib import attr
from angr.state_plugins.history import HistoryIter

l = logging.getLogger("angr.tests")
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

target_addrs = {
    'i386': [ 0x080485C9 ],
    'x86_64': [ 0x4006ed ],
    'ppc': [ 0x1000060C ],
    'armel': [ 0x85F0 ],
    'android/arm': [ 0x4004cc ],
    'mips': [ 0x4009FC ]
}

avoid_addrs = {
    'i386': [ 0x080485DD,0x08048564 ],
    'x86_64': [ 0x4006aa,0x4006fd ],
    'ppc': [ 0x10000644,0x1000059C ],
    'armel': [ 0x86F8,0x857C ],
    'android/arm': [ 0x4004f0,0x400470 ],
    'mips': [ 0x400A10,0x400774 ]
}

corrupt_addrs = {
    'i386': [ 0x80486B6, 'bO\xcc', lambda s: s.memory.store(s.regs.esp, s.regs.eax) ],
    'x86_64': [ 0x400742, '\xd4&\xb0[\x41', lambda s: s.registers.store('rdx', 8) ],
    'ppc': [ 0x100006B8, '\x05\xad\xc2\xea', lambda s: s.registers.store('r5', 8) ],
    'armel': [ 0x8678, '\xbdM\xec3', lambda s: s.registers.store('r2', 8) ],
    'mips': [ 0x400918, '[\xf8\x96@'[::-1], lambda s: s.registers.store('a2', 8) ]
}

divergences = {
    'ppc': 0x10000588,
    'x86_64': 0x40068e,
    'i386': 0x8048559,
    'armel': 0x8568,
    'android/arm': 0x40045c,
    'mips': 0x40075c,
}

def run_fauxware(arch):
    p = angr.Project(os.path.join(test_location, arch, "fauxware"))
    results = p.factory.simgr().explore(find=target_addrs[arch], avoid=avoid_addrs[arch])
    stdin = results.found[0].posix.dumps(0)
    nose.tools.assert_equal('\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00', stdin)

    # test the divergence detection
    ancestor = results.found[0].history.closest_common_ancestor((results.avoid + results.active)[0].history)
    divergent_point = list(HistoryIter(results.found[0].history, end=ancestor))[0]
    #p.factory.block(divergent_point.addr).pp()
    assert divergent_point.recent_bbl_addrs[0] == divergences[arch]

def run_pickling(arch):
    p = angr.Project(os.path.join(test_location, arch, "fauxware"))
    pg = p.factory.simgr().run(n=10)
    pickled = pickle.dumps(pg, pickle.HIGHEST_PROTOCOL)
    del p
    del pg
    gc.collect()
    pg = pickle.loads(pickled)

    pg.explore(find=target_addrs[arch], avoid=avoid_addrs[arch])
    stdin = pg.found[0].posix.dumps(0)
    nose.tools.assert_equal('\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00', stdin)

def run_fastmem(arch):
    p = angr.Project(os.path.join(test_location, arch, "fauxware"))
    p.analyses.CongruencyCheck(throw=True).set_state_options(right_add_options={"FAST_REGISTERS"}).run()

def run_nodecode(arch):
    p = angr.Project(os.path.join(test_location, arch, "fauxware"))

    # screw up the instructions and make sure the test fails with nodecode
    for i,c in enumerate(corrupt_addrs[arch][1]):
        p.loader.memory[corrupt_addrs[arch][0] + i] = c
    boned = p.factory.simgr().explore(find=target_addrs[arch], avoid=avoid_addrs[arch])
    nose.tools.assert_true(len(boned.errored) >= 1)
    nose.tools.assert_true(isinstance(boned.errored[0].error, angr.SimIRSBNoDecodeError))
    nose.tools.assert_true(boned.errored[0].state.addr == corrupt_addrs[arch][0])

    # hook the instructions with the emulated stuff
    p.hook(corrupt_addrs[arch][0], corrupt_addrs[arch][2], length=len(corrupt_addrs[arch][1]))
    results = p.factory.simgr().explore(find=target_addrs[arch], avoid=avoid_addrs[arch])
    stdin = results.found[0].posix.dumps(0)
    nose.tools.assert_equal('\x00\x00\x00\x00\x00\x00\x00\x00\x00SOSNEAKY\x00', stdin)

def run_merge(arch):
    p = angr.Project(os.path.join(test_location, arch, "fauxware"))
    pg = p.factory.simgr()
    pg.explore()

    # release the unmergable data
    for s in pg.deadended:
        s.release_plugin('fs')
        if 3 in s.posix.fd:
            s.posix.close(3)

    pg.merge(stash='deadended', merge_key=lambda s: s.addr)

    path = pg.deadended[[ 'Welcome' in s for s in pg.mp_deadended.posix.dumps(1).mp_items ].index(True)]
    yes, no = path.history.merge_conditions
    inp = path.posix.stdin.content[2][0] # content of second packet
    try:
        assert 'SOSNEAKY' in path.se.eval(inp, cast_to=str, extra_constraints=(yes,))
        assert 'SOSNEAKY' not in path.se.eval(inp, cast_to=str, extra_constraints=(no,))
    except AssertionError:
        yes, no = no, yes
        assert 'SOSNEAKY' in path.se.eval(inp, cast_to=str, extra_constraints=(yes,))
        assert 'SOSNEAKY' not in path.se.eval(inp, cast_to=str, extra_constraints=(no,))

def test_merge():
    for arch in target_addrs:
        yield run_merge, arch

def test_fauxware():
    for arch in target_addrs:
        yield run_fauxware, arch

def test_pickling():
    for arch in corrupt_addrs:
        yield run_pickling, arch

@attr(speed='slow')
def test_fastmem():
    #for arch in target_addrs:
    #   yield run_fastmem, arch
    # TODO: add support for comparing flags of other architectures
    #yield run_fastmem, "i386"
    yield run_fastmem, "x86_64"
    #yield run_fastmem, "ppc"
    #yield run_fastmem, "mips"

def test_nodecode():
    for arch in corrupt_addrs:
        yield run_nodecode, arch

if __name__ == "__main__":

    if len(sys.argv) > 1:
        func_name = "test_%s" % sys.argv[1]
        for r, a in globals()[func_name]():
            r(a)

    else:
        g = globals().copy()
        for func_name, func in g.iteritems():
            if func_name.startswith("test_") and hasattr(func, '__call__'):
                for r, a in func():
                    r(a)
