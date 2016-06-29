import nose
import angr
import tracer


import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../'))


from simuvex import s_options as so



REGS = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip', 'd']

def test_unicorn():
    p = angr.Project(os.path.join(test_location, 'binaries-private/cgc_qualifier_event/cgc/99c22c01_01'))

    s_unicorn = p.factory.entry_state(add_options=so.unicorn | {so.CGC_NO_SYMBOLIC_RECEIVE_LENGTH, so.STRICT_PAGE_ACCESS}, remove_options={so.LAZY_SOLVES}) # unicorn
    s_angr = p.factory.entry_state(add_options={so.CGC_NO_SYMBOLIC_RECEIVE_LENGTH, so.INITIALIZE_ZERO_REGISTERS, so.STRICT_PAGE_ACCESS}, remove_options={so.LAZY_SOLVES}) # pure angr

    pg_unicorn = p.factory.path_group(s_unicorn)
    pg_angr = p.factory.path_group(s_angr)
    print pg_angr, pg_unicorn

    # input = 'x\n\0\0\0\0'
    inp = 'L\x0alaehdamfeg\x0a10\x2f28\x2f2014\x0a-2147483647:-2147483647:-2147483647\x0ajfifloiblk\x0a126\x0a63\x0a47\x0a31\x0a3141\x0a719\x0a'

    stdin = s_unicorn.posix.get_file(0)
    stdin.write(inp, len(inp))
    stdin.seek(0)
    stdin.size = len(inp)

    stdin = s_angr.posix.get_file(0)
    stdin.write(inp, len(inp))
    stdin.seek(0)
    stdin.size = len(inp)

    tracer = tracer.Runner(p.filename, inp, record_trace=True)
    tracer.dynamic_trace()
    real_trace = tracer.trace

    pg_unicorn.run()
    uc_trace = pg_unicorn.one_errored.addr_trace.hardcopy + [pg_unicorn.one_errored.addr]
    pg_angr.run()
    angr_trace = pg_angr.one_errored.addr_trace.hardcopy + [pg_angr.one_errored.addr]
    uc_trace_filtered = [a for a in uc_trace if not p._extern_obj.contains_addr(a) and not p._syscall_obj.contains_addr(a)]

    nose.tools.assert_true(uc_trace_filtered == real_trace)
    nose.tools.assert_true(uc_trace == angr_trace)
    nose.tools.assert_equal(pg_angr.one_errored.error.addr, pg_unicorn.one_errored.error.addr)

def test_stops():
    p = angr.Project(os.path.join(test_location, 'binaries/tests/i386/uc_stop'))

    # test STOP_NORMAL, STOP_STOPPOINT
    s_normal = p.factory.entry_state(args=['a'], add_options=so.unicorn)
    s_normal.unicorn.max_steps = 100
    pg_normal = p.factory.path_group(s_normal).run()
    p_normal = pg_normal.one_deadended
    nose.tools.assert_equal(p_normal.trace.hardcopy, ['<SimUnicorn 0x8048340-0x8048320 with 2 steps (STOP_STOPPOINT)>', '<SimProcedure __libc_start_main>', '<SimUnicorn 0x8048520-0x8048575 with 15 steps (STOP_STOPPOINT)>', '<SimProcedure __libc_start_main>', '<SimUnicorn 0x80484b6-0x804844a with 100 steps (STOP_NORMAL)>', '<SimUnicorn 0x804844a-0x804850c with 8 steps (STOP_STOPPOINT)>', '<SimProcedure __libc_start_main>'])

    s_normal_angr = p.factory.entry_state(args=['a'])
    pg_normal_angr = p.factory.path_group(s_normal_angr).run()
    p_normal_angr = pg_normal_angr.one_deadended
    nose.tools.assert_equal(p_normal_angr.addr_trace.hardcopy, p_normal.addr_trace.hardcopy)

    # test STOP_SYMBOLIC
    s_symbolic = p.factory.entry_state(args=['a', 'a'], add_options=so.unicorn)
    pg_symbolic = p.factory.path_group(s_symbolic).run()
    p_symbolic = pg_symbolic.one_deadended
    nose.tools.assert_equal(p_symbolic.trace.hardcopy, ['<SimUnicorn 0x8048340-0x8048320 with 2 steps (STOP_STOPPOINT)>', '<SimProcedure __libc_start_main>', '<SimUnicorn 0x8048520-0x8048575 with 15 steps (STOP_STOPPOINT)>', '<SimProcedure __libc_start_main>', '<SimUnicorn 0x80484b6-0x80484e3 with 3 steps (STOP_SYMBOLIC)>', '<SimIRSB 0x8048457>', '<SimIRSB 0x804848c>', '<SimIRSB 0x80484e8>', '<SimIRSB 0x804850c>', '<SimProcedure __libc_start_main>'])

    s_symbolic_angr = p.factory.entry_state(args=['a', 'a'])
    pg_symbolic_angr = p.factory.path_group(s_symbolic_angr).run()
    p_symbolic_angr = pg_symbolic_angr.one_deadended
    nose.tools.assert_equal(p_symbolic_angr.addr_trace.hardcopy, p_symbolic.addr_trace.hardcopy)

    # test STOP_SEGFAULT
    s_segfault = p.factory.entry_state(args=['a', 'a', 'a', 'a', 'a', 'a', 'a'], add_options=so.unicorn | {so.STRICT_PAGE_ACCESS})
    pg_segfault = p.factory.path_group(s_segfault).run()
    p_segfault = pg_segfault.one_errored
    # TODO: fix the permissions segfault to commit if it's a MEM_FETCH
    # this will extend the last simunicorn one more block
    nose.tools.assert_equal(p_segfault.trace.hardcopy, ['<SimUnicorn 0x8048340-0x8048320 with 2 steps (STOP_STOPPOINT)>', '<SimProcedure __libc_start_main>', '<SimUnicorn 0x8048520-0x8048575 with 15 steps (STOP_STOPPOINT)>', '<SimProcedure __libc_start_main>', '<SimUnicorn 0x80484b6-0x8048506 with 3 steps (STOP_SEGFAULT)>', '<SimIRSB 0x80484a6>'])

    s_segfault_angr = p.factory.entry_state(args=['a', 'a', 'a', 'a', 'a', 'a', 'a'], add_options={so.STRICT_PAGE_ACCESS})
    pg_segfault_angr = p.factory.path_group(s_segfault_angr).run()
    p_segfault_angr = pg_segfault_angr.one_errored
    nose.tools.assert_equal(p_segfault_angr.addr_trace.hardcopy, p_segfault.addr_trace.hardcopy)
    nose.tools.assert_equal(p_segfault_angr.error.addr, p_segfault.error.addr)

def run_longinit(arch):
    p = angr.Project(os.path.join(test_location, 'binaries/tests/' + arch + '/longinit'))
    s_unicorn = p.factory.entry_state(add_options=so.unicorn) # unicorn
    pg = p.factory.path_group(s_unicorn)
    pg.explore()
    s = pg.deadended[0].state
    first = s.posix.files[0].content.load(0, 9)
    second = s.posix.files[0].content.load(9, 9)
    s.add_constraints(first == s.se.BVV('A'*9))
    s.add_constraints(second == s.se.BVV('B'*9))
    nose.tools.assert_equal(s.posix.dumps(1), "You entered AAAAAAAAA and BBBBBBBBB!\n")

def test_longinit_i386():
    run_longinit('i386')
def test_longinit_x86_64():
    run_longinit('x86_64')

def broken_palindrome():
    b = angr.Project(os.path.join(test_location, "binaries-private/cgc_scored_event_2/cgc/0b32aa01_01"))
    s_unicorn = b.factory.entry_state(add_options=so.unicorn, remove_options={so.LAZY_SOLVES}) # unicorn
    pg = b.factory.path_group(s_unicorn)
    angr.path_group.l.setLevel("DEBUG")
    pg.step(300)

def run_similarity(binpath, depth):
    b = angr.Project(os.path.join(test_location, binpath))
    cc = b.analyses.CongruencyCheck()
    nose.tools.assert_true(cc.check_state_options(
        left_add_options=so.unicorn,
        left_remove_options={so.LAZY_SOLVES, so.TRACK_MEMORY_MAPPING},
        right_add_options={so.INITIALIZE_ZERO_REGISTERS},
        right_remove_options={so.LAZY_SOLVES, so.TRACK_MEMORY_MAPPING},
        depth=depth
    ))

def test_fauxware():
    p = angr.Project(os.path.join(test_location, 'binaries/tests/i386/fauxware'))
    s_unicorn = p.factory.entry_state(add_options=so.unicorn) # unicorn
    pg = p.factory.path_group(s_unicorn)
    pg.explore()

    nose.tools.assert_equal(sorted(pg.mp_deadended.state.posix.dumps(1).mp_items), sorted((
        'Username: \nPassword: \nWelcome to the admin console, trusted user!\n',
        'Username: \nPassword: \nGo away!',
        'Username: \nPassword: \nWelcome to the admin console, trusted user!\n'
    )))

def test_fauxware_aggressive():
    p = angr.Project(os.path.join(test_location, 'binaries/tests/i386/fauxware'))
    s_unicorn = p.factory.entry_state(
        add_options=so.unicorn | { so.UNICORN_AGGRESSIVE_CONCRETIZATION },
        remove_options={ so.LAZY_SOLVES }
    ) # unicorn
    s_unicorn.unicorn.cooldown_symbolic_registers = 0
    s_unicorn.unicorn.cooldown_symbolic_memory = 0
    s_unicorn.unicorn.cooldown_nonunicorn_blocks = 0

    pg = p.factory.path_group(s_unicorn)
    pg.explore()

    nose.tools.assert_equal(len(pg.deadended), 1)

def timesout_similarity_01cf6c01(): run_similarity("binaries-private/cgc_qualifier_event/cgc/01cf6c01_01", 5170)
def timesout_similarity_38256a01(): run_similarity("binaries-private/cgc_qualifier_event/cgc/38256a01_01", 125)
def timesout_similarity_5821ad01(): run_similarity("binaries-private/cgc_qualifier_event/cgc/5821ad01_01", 125)
def timesout_similarity_5c921501(): run_similarity("binaries-private/cgc_qualifier_event/cgc/5c921501_01", 250)
def timesout_similarity_63cf1501(): run_similarity("binaries-private/cgc_qualifier_event/cgc/63cf1501_01", 125)
def timesout_similarity_6787bf01(): run_similarity("binaries-private/cgc_qualifier_event/cgc/6787bf01_01", 125)
def timesout_similarity_7185fe01(): run_similarity("binaries-private/cgc_qualifier_event/cgc/7185fe01_01", 500)
def timesout_similarity_ab957801(): run_similarity("binaries-private/cgc_qualifier_event/cgc/ab957801_01", 125)
def timesout_similarity_acedf301(): run_similarity("binaries-private/cgc_qualifier_event/cgc/acedf301_01", 600)
def timesout_similarity_d009e601(): run_similarity("binaries-private/cgc_qualifier_event/cgc/d009e601_01", 600)
def timesout_similarity_d4411101(): run_similarity("binaries-private/cgc_qualifier_event/cgc/d4411101_01", 500)
def timesout_similarity_eae6fa01(): run_similarity("binaries-private/cgc_qualifier_event/cgc/eae6fa01_01", 250)
def timesout_similarity_ee545a01(): run_similarity("binaries-private/cgc_qualifier_event/cgc/ee545a01_01", 1000)
def timesout_similarity_f5adc401(): run_similarity("binaries-private/cgc_qualifier_event/cgc/f5adc401_01", 250)

if __name__ == '__main__':
    import logging
    logging.getLogger('simuvex.plugins.unicorn').setLevel('DEBUG')
    logging.getLogger('simuvex.s_unicorn').setLevel('INFO')
    logging.getLogger('angr.factory').setLevel('DEBUG')
    logging.getLogger('angr.project').setLevel('DEBUG')

    import sys
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            print 'test_' + arg
            globals()['test_' + arg]()
    else:
        for fk, fv in globals().items():
            if fk.startswith('test_') and callable(fv):
                print fk
                fv()
