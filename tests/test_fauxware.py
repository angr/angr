import gc
import os
import pickle
import logging
import sys
import angr

from angr.state_plugins.history import HistoryIter

l = logging.getLogger("angr.tests")
test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')

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
    'i386': [ 0x80486B6, b'bO\xcc', lambda s: s.memory.store(s.regs.esp, s.regs.eax) ],
    'x86_64': [ 0x400742, b'\xd4&\xb0[\x41', lambda s: s.registers.store('rdx', 8) ],
    'ppc': [ 0x100006B8, b'\x05\xad\xc2\xea', lambda s: s.registers.store('r5', 8) ],
    'armel': [ 0x8678, b'\xbdM\xec3', lambda s: s.registers.store('r2', 8) ],
    'mips': [ 0x400918, b'[\xf8\x96@'[::-1], lambda s: s.registers.store('a2', 8) ]
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
    p = angr.Project(os.path.join(test_location, arch, "fauxware"), auto_load_libs=False)
    results = p.factory.simulation_manager().explore(find=target_addrs[arch], avoid=avoid_addrs[arch])
    stdin = results.found[0].posix.dumps(0)
