import nose
import angr

import logging
l = logging.getLogger("angr.tests")

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

target_addrs = {
    'i386': [ 0x080485C9 ],
    'x86_64': [ 0x4006ed ],
    'ppc': [ 0x1000060C ],
    'armel': [ 0x85F0 ],
    'mips': [ 0x4009FC ]
}

avoid_addrs = {
    'i386': [ 0x080485DD,0x08048564 ],
    'x86_64': [ 0x4006aa,0x4006fd ],
    'ppc': [ 0x10000644,0x1000059C ],
    'armel': [ 0x86F8,0x857C ],
    'mips': [ 0x400A10,0x400774 ]
}

corrupt_addrs = {
    'i386': [ 0x80486B6, 'bO\xcc', lambda s: s.memory.store(s.regs.esp, s.regs.eax) ],
    'x86_64': [ 0x400742, '\xd4&\xb0[\x41', lambda s: s.registers.store('rdx', 8) ],
    'ppc': [ 0x100006B8, '\x05\xad\xc2\xea', lambda s: s.registers.store('r5', 8) ],
    'armel': [ 0x8678, '\xbdM\xec3', lambda s: s.registers.store('r2', 8) ],
    'mips': [ 0x400918, '[\xf8\x96@'[::-1], lambda s: s.registers.store('a2', 8) ]
}

def run_fauxware_override(arch):
    p = angr.Project(os.path.join(test_location, arch, "fauxware"), use_sim_procedures=False)
    s = p.factory.full_init_state()

    def overwrite_str(state):
        state.posix.get_fd(1).write_data("HAHA\0")

    #s.posix.queued_syscall_returns = [ ] #[ lambda s,run: __import__('ipdb').set_trace() ] * 1000
    s.posix.queued_syscall_returns.append(None) # let the mmap run
    s.posix.queued_syscall_returns.append(overwrite_str) # prompt for username
    s.posix.queued_syscall_returns.append(0) # username read
    s.posix.queued_syscall_returns.append(0) # newline read
    #s.posix.queued_syscall_returns.append(0) # prompt for password -- why isn't this called?
    s.posix.queued_syscall_returns.append(None) # password input
    s.posix.queued_syscall_returns.append(0) # password \n input

    results = p.factory.simgr(thing=s).explore(find=target_addrs[arch], avoid=avoid_addrs[arch])
    stdin = results.found[0].posix.dumps(0)
    nose.tools.assert_equal('SOSNEAKY', stdin)
    stdout = results.found[0].posix.dumps(1)
    nose.tools.assert_equal('HAHA\0', stdout)

def test_fauxware_override():
    #for arch in target_addrs:
    #   yield run_fauxware_override, arch
    yield run_fauxware_override, 'x86_64'

if __name__ == "__main__":
    #run_fauxware_override('x86_64')
    for r,a in test_fauxware_override():
        r(a)
