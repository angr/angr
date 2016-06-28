import nose
import angr

import logging
l = logging.getLogger("angr.tests.unicorn")
l.setLevel('DEBUG')
logging.getLogger('simuvex.plugins.unicorn').setLevel('DEBUG')
logging.getLogger('simuvex.s_unicorn').setLevel('INFO')
# logging.getLogger('angr.factory').setLevel('DEBUG')

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../'))


from simuvex import s_options as so



REGS = ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp', 'eip', 'd']

def dump_reg(s):
    # for k in dir(s.regs):
    for k in REGS:
        l.info('$%s = %r', k, getattr(s.regs, k))

def test_unicorn():
    p = angr.Project(os.path.join(test_location, 'binaries-private/cgc_qualifier_event/cgc/99c22c01_01'))

    s_unicorn = p.factory.entry_state(add_options=so.unicorn | {so.CGC_NO_SYMBOLIC_RECEIVE_LENGTH}, remove_options={so.LAZY_SOLVES}) # unicorn
    s_angr = p.factory.entry_state(add_options={so.CGC_NO_SYMBOLIC_RECEIVE_LENGTH, so.INITIALIZE_ZERO_REGISTERS}, remove_options={so.LAZY_SOLVES}) # pure angr
    # s_unicorn.options.add(so.UNICORN_DISABLE_NATIVE)

    dump_reg(s_unicorn)
    #s_unicorn.unicorn.max_steps = 1
    s_unicorn.unicorn.cooldown_symbolic_registers = 0
    s_unicorn.unicorn.cooldown_symbolic_memory = 0
    s_unicorn.unicorn.cooldown_nonunicorn_blocks = 0

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

    import tracer
    tracer = tracer.Runner(p.filename, inp, record_trace=True)
    tracer.dynamic_trace()
    real_trace = tracer.trace

    pg_unicorn.step(until=lambda lpg: len(lpg.one_active.addr_trace) >= 8200)
    uc_trace = pg_unicorn.active[0].addr_trace.hardcopy
    pg_angr.step(n=8200)
    angr_trace = pg_angr.active[0].addr_trace.hardcopy
    uc_trace_filtered = [a for a in uc_trace if not p._extern_obj.contains_addr(a) and not p._syscall_obj.contains_addr(a)]

    nose.tools.assert_true(uc_trace_filtered[:len(real_trace)] == real_trace)
    nose.tools.assert_true(uc_trace[:len(angr_trace)] == angr_trace)

    #cc = p.analyses.CongruencyCheck(throw=True)
    #cc.set_states(s_unicorn, s_angr)
    #cc.run()

    #import IPython; IPython.embed()

    #pg_unicorn.active[0].state.options.remove(so.UNICORN_FAST)

    # run explore
    # pg_unicorn.explore()
    # pg_angr.explore()
    #embed()

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
    #test_palindrome()
    #test_fauxware()
    #test_longinit()
    #test_unicorn()
    #test_similarity_01cf6c01()
    #test_similarity_7185fe01()
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
