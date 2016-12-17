import nose
import angr
import pickle

import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../'))

import simuvex
from simuvex import s_options as so

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
    nose.tools.assert_equal(p_symbolic.trace.hardcopy, ['<SimUnicorn 0x8048340-0x8048320 with 2 steps (STOP_STOPPOINT)>', '<SimProcedure __libc_start_main>', '<SimUnicorn 0x8048520-0x8048575 with 15 steps (STOP_STOPPOINT)>', '<SimProcedure __libc_start_main>', '<SimUnicorn 0x80484b6-0x80484e3 with 3 steps (STOP_SYMBOLIC_MEM)>', '<SimIRSB 0x8048457>', '<SimIRSB 0x804848c>', '<SimIRSB 0x80484e8>', '<SimIRSB 0x804850c>', '<SimProcedure __libc_start_main>'])

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

def test_fauxware():
    p = angr.Project(os.path.join(test_location, 'binaries/tests/i386/fauxware'))
    s_unicorn = p.factory.entry_state(add_options=so.unicorn) # unicorn
    pg = p.factory.path_group(s_unicorn)
    pg.explore()

    assert all("SimUnicorn" in ''.join(p.trace.hardcopy) for p in pg.deadended)
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

def run_similarity(binpath, depth, prehook=None):
    b = angr.Project(os.path.join(test_location, binpath))
    cc = b.analyses.CongruencyCheck(throw=True)
    cc.set_state_options(
        left_add_options=so.unicorn,
        left_remove_options={so.LAZY_SOLVES, so.TRACK_MEMORY_MAPPING, so.COMPOSITE_SOLVER},
        right_add_options={so.INITIALIZE_ZERO_REGISTERS},
        right_remove_options={so.LAZY_SOLVES, so.TRACK_MEMORY_MAPPING, so.COMPOSITE_SOLVER}
    )
    if prehook:
        cc.pg = prehook(cc.pg)
    cc.run(depth=depth)

def test_similarity_fauxware():
    def cooldown(pg):
        # gotta skip the initializers because of cpuid and RDTSC
        pg.one_left.state.unicorn.countdown_nonunicorn_blocks = 39
        return pg
    run_similarity("binaries/tests/i386/fauxware", 1000, prehook=cooldown)

def test_fp():
    type_cache = simuvex.s_type.parse_defns(open(os.path.join(test_location, 'binaries/tests_src/manyfloatsum.c')).read())
    p = angr.Project(os.path.join(test_location, 'binaries/tests/i386/manyfloatsum'))

    for function in ('sum_floats', 'sum_combo', 'sum_segregated', 'sum_doubles', 'sum_combo_doubles', 'sum_segregated_doubles'):
        cc = p.factory.cc(func_ty=type_cache[function])
        args = list(range(len(cc.func_ty.args)))
        answer = float(sum(args))
        addr = p.loader.main_bin.get_symbol(function).rebased_addr
        my_callable = p.factory.callable(addr, cc=cc)
        my_callable.set_base_state(p.factory.blank_state(add_options=so.unicorn))
        result = my_callable(*args)
        nose.tools.assert_false(result.symbolic)
        result_concrete = result.args[0]
        nose.tools.assert_equal(answer, result_concrete)

def test_unicorn_pickle():
    p = angr.Project(os.path.join(test_location, 'binaries/tests/i386/fauxware'))

    def _uni_state():
        # try pickling out paths that went through unicorn
        s_unicorn = p.factory.entry_state(add_options=so.unicorn)
        s_unicorn.unicorn.countdown_nonunicorn_blocks = 0
        s_unicorn.unicorn.countdown_symbolic_registers = 0
        s_unicorn.unicorn.cooldown_nonunicorn_blocks = 0
        s_unicorn.unicorn.cooldown_symbolic_registers = 0
        return s_unicorn

    pg = p.factory.path_group(_uni_state())
    pg.one_active.state.options.update(simuvex.o.unicorn)
    pg.step(until=lambda lpg: "SimUnicorn" in lpg.one_active.history._runstr)
    assert len(pg.active) > 0

    pgp = pickle.dumps(pg, -1)
    del pg
    import gc
    gc.collect()
    pg2 = pickle.loads(pgp)
    pg2.explore()

    nose.tools.assert_equal(sorted(pg2.mp_deadended.state.posix.dumps(1).mp_items), sorted((
        'Username: \nPassword: \nWelcome to the admin console, trusted user!\n',
        'Username: \nPassword: \nGo away!',
        'Username: \nPassword: \nWelcome to the admin console, trusted user!\n'
    )))

    # test the pickling of SimUnicorn itself
    p = angr.Project(os.path.join(test_location, 'binaries/tests/i386/fauxware'))
    pg = p.factory.path_group(_uni_state())
    pg.step(n=2)
    pg.one_active.step()
    assert isinstance(pg.one_active._run, simuvex.SimUnicorn)

    pgp = pickle.dumps(pg, -1)
    del pg
    gc.collect()
    pg2 = pickle.loads(pgp)
    assert isinstance(pg2.one_active._run, simuvex.SimUnicorn)
    pg2.explore()

    nose.tools.assert_equal(sorted(pg2.mp_deadended.state.posix.dumps(1).mp_items), sorted((
        'Username: \nPassword: \nWelcome to the admin console, trusted user!\n',
        'Username: \nPassword: \nGo away!',
        'Username: \nPassword: \nWelcome to the admin console, trusted user!\n'
    )))

def test_concrete_transmits():
    p = angr.Project(os.path.join(test_location, 'binaries/tests/cgc/PIZZA_00001'))
    inp = "320a310a0100000005000000330a330a340a".decode('hex')

    s_unicorn = p.factory.entry_state(add_options=so.unicorn | {so.CGC_NO_SYMBOLIC_RECEIVE_LENGTH})
    pg_unicorn = p.factory.path_group(s_unicorn)
    stdin = s_unicorn.posix.get_file(0)
    stdin.write(inp, len(inp))
    stdin.seek(0)
    stdin.size = len(inp)

    pg_unicorn.step(n=10)

    nose.tools.assert_equal(pg_unicorn.one_active.state.posix.dumps(1), '1) Add number to the array\n2) Add random number to the array\n3) Sum numbers\n4) Exit\nRandomness added\n1) Add number to the array\n2) Add random number to the array\n3) Sum numbers\n4) Exit\n  Index: \n1) Add number to the array\n2) Add random number to the array\n3) Sum numbers\n4) Exit\n')

if __name__ == '__main__':
    #import logging
    #logging.getLogger('simuvex.plugins.unicorn').setLevel('DEBUG')
    #logging.getLogger('simuvex.s_unicorn').setLevel('INFO')
    #logging.getLogger('angr.factory').setLevel('DEBUG')
    #logging.getLogger('angr.project').setLevel('DEBUG')

    import sys
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            print 'test_' + arg
            res = globals()['test_' + arg]()
            if hasattr(res, '__iter__'):
                for ft in res:
                    fo = ft[0]
                    fa = ft[1:]
                    print '...', fa
                    fo(*fa)
    else:
        for fk, fv in globals().items():
            if fk.startswith('test_') and callable(fv):
                print fk
                res = fv()
                if hasattr(res, '__iter__'):
                    for ft in res:
                        fo = ft[0]
                        fa = ft[1:]
                        print '...', fa
                        fo(*fa)
