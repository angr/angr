import nose
import angr
import pickle
import re
from angr import options as so
from nose.plugins.attrib import attr
import gc
import os

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..')



def _remove_addr_from_trace_item(trace_item_str):
    m = re.match(r"(<\S+ \S+) from 0x[0-9a-f]+(:[\s\S]+)", trace_item_str)
    if m is None:
        return None
    return m.group(1) + m.group(2)

def _compare_trace(trace, expected):

    nose.tools.assert_equal(len(trace), len(expected))

    for trace_item, expected_str in zip(trace, expected):
        trace_item_str = str(trace_item)
        if trace_item_str.startswith('<SimProcedure'):
            # we do not care if addresses of SimProcedures match, since they are not allocated in a deterministic way
            trace_item_str = _remove_addr_from_trace_item(trace_item_str)
            expected_str = _remove_addr_from_trace_item(expected_str)

        nose.tools.assert_equal(trace_item_str, expected_str)

def test_stops():
    p = angr.Project(os.path.join(test_location, 'binaries', 'tests', 'i386', 'uc_stop'))

    # test STOP_NORMAL, STOP_STOPPOINT
    s_normal = p.factory.entry_state(args=['a'], add_options=so.unicorn)
    s_normal.unicorn.max_steps = 100
    pg_normal = p.factory.simulation_manager(s_normal).run()
    p_normal = pg_normal.one_deadended
    _compare_trace(p_normal.history.descriptions, ['<Unicorn (STOP_STOPPOINT after 4 steps) from 0x8048340: 1 sat>', '<SimProcedure __libc_start_main from 0x8119990: 1 sat>', '<Unicorn (STOP_STOPPOINT after 14 steps) from 0x8048650: 1 sat>', '<SimProcedure __libc_start_main from 0x8400044: 1 sat>', '<Unicorn (STOP_NORMAL after 100 steps) from 0x80485b5: 1 sat>', '<Unicorn (STOP_STOPPOINT after 12 steps) from 0x804846f: 1 sat>', '<SimProcedure __libc_start_main from 0x8400048: 1 sat>'])

    s_normal_angr = p.factory.entry_state(args=['a'])
    pg_normal_angr = p.factory.simulation_manager(s_normal_angr).run()
    p_normal_angr = pg_normal_angr.one_deadended
    nose.tools.assert_equal(p_normal_angr.history.bbl_addrs.hardcopy, p_normal.history.bbl_addrs.hardcopy)

    # test STOP_STOPPOINT on an address that is not a basic block start
    s_stoppoints = p.factory.call_state(p.loader.find_symbol("main").rebased_addr, 1, [], add_options=so.unicorn)

    # this address is right before/after the bb for the stop_normal() function ends
    # we should not stop there, since that code is never hit
    stop_fake = [0x0804847c, 0x08048454]

    # this is an address inside main that is not the beginning of a basic block. we should stop here
    stop_in_bb = 0x08048638
    stop_bb = 0x08048633 # basic block of the above address
    pg_stoppoints = p.factory.simulation_manager(s_stoppoints).run(n=1, extra_stop_points=stop_fake + [stop_in_bb])
    nose.tools.assert_equal(len(pg_stoppoints.active), 1) # path should not branch
    p_stoppoints = pg_stoppoints.one_active
    nose.tools.assert_equal(p_stoppoints.addr, stop_bb) # should stop at bb before stop_in_bb
    _compare_trace(p_stoppoints.history.descriptions, ['<Unicorn (STOP_STOPPOINT after 111 steps) from 0x80485b5: 1 sat>'])

    # test STOP_SYMBOLIC_READ_SYMBOLIC_TRACKING_DISABLED
    s_symbolic_read_tracking_disabled = p.factory.entry_state(args=['a', 'a'], add_options=so.unicorn, remove_options={so.UNICORN_SYM_REGS_SUPPORT})
    pg_symbolic_read_tracking_disabled = p.factory.simulation_manager(s_symbolic_read_tracking_disabled).run()
    p_symbolic_read_tracking_disabled = pg_symbolic_read_tracking_disabled.one_deadended
    _compare_trace(p_symbolic_read_tracking_disabled.history.descriptions, ['<Unicorn (STOP_STOPPOINT after 4 steps) from 0x8048340: 1 sat>', '<SimProcedure __libc_start_main from 0x8119990: 1 sat>', '<Unicorn (STOP_STOPPOINT after 14 steps) from 0x8048650: 1 sat>', '<SimProcedure __libc_start_main from 0x8400044: 1 sat>', '<Unicorn (STOP_SYMBOLIC_READ_SYMBOLIC_TRACKING_DISABLED after 7 steps) from 0x80485b5: 1 sat>', '<IRSB from 0x804848a: 1 sat 3 unsat>', '<Unicorn (STOP_STOPPOINT after 3 steps) from 0x80484bb: 1 sat>', '<SimProcedure __libc_start_main from 0x8400048: 1 sat>'])

    s_symbolic_read_tracking_disabled_angr = p.factory.entry_state(args=['a', 'a'])
    pg_symbolic_read_tracking_disabled_angr = p.factory.simulation_manager(s_symbolic_read_tracking_disabled_angr).run()
    p_symbolic_read_tracking_disabled_angr = pg_symbolic_read_tracking_disabled_angr.one_deadended
    nose.tools.assert_equal(p_symbolic_read_tracking_disabled_angr.history.bbl_addrs.hardcopy, p_symbolic_read_tracking_disabled.history.bbl_addrs.hardcopy)

    # test STOP_SEGFAULT
    s_segfault = p.factory.entry_state(args=['a', 'a', 'a', 'a', 'a', 'a', 'a'], add_options=so.unicorn | {so.STRICT_PAGE_ACCESS, so.ENABLE_NX})
    pg_segfault = p.factory.simulation_manager(s_segfault).run()
    p_segfault = pg_segfault.errored[0].state
    # TODO: fix the permissions segfault to commit if it's a MEM_FETCH
    # this will extend the last simunicorn one more block
    _compare_trace(p_segfault.history.descriptions, ['<Unicorn (STOP_STOPPOINT after 4 steps) from 0x8048340: 1 sat>', '<SimProcedure __libc_start_main from 0x8119990: 1 sat>', '<Unicorn (STOP_STOPPOINT after 14 steps) from 0x8048650: 1 sat>', '<SimProcedure __libc_start_main from 0x8400044: 1 sat>', '<Unicorn (STOP_SEGFAULT after 7 steps) from 0x80485b5: 1 sat>', '<IRSB from 0x8048508: 1 sat>'])

    s_segfault_angr = p.factory.entry_state(args=['a', 'a', 'a', 'a', 'a', 'a', 'a'], add_options={so.STRICT_PAGE_ACCESS, so.ENABLE_NX})
    pg_segfault_angr = p.factory.simulation_manager(s_segfault_angr).run()
    p_segfault_angr = pg_segfault_angr.errored[0].state
    nose.tools.assert_equal(p_segfault_angr.history.bbl_addrs.hardcopy, p_segfault.history.bbl_addrs.hardcopy)
    nose.tools.assert_equal(pg_segfault_angr.errored[0].error.addr, pg_segfault.errored[0].error.addr)

    # test STOP_SYMBOLIC_READ_ADDR
    s_symbolic_read_addr = p.factory.entry_state(args=['a'] * 8, add_options=so.unicorn)
    pg_symbolic_read_addr = p.factory.simulation_manager(s_symbolic_read_addr).run()
    p_symbolic_read_addr = pg_symbolic_read_addr.one_deadended
    _compare_trace(p_symbolic_read_addr.history.descriptions, ['<Unicorn (STOP_STOPPOINT after 4 steps) from 0x8048340: 1 sat>', '<SimProcedure __libc_start_main from 0x8119990: 1 sat>', '<Unicorn (STOP_STOPPOINT after 14 steps) from 0x8048650: 1 sat>', '<SimProcedure __libc_start_main from 0x8400044: 1 sat>', '<Unicorn (STOP_STOPPOINT after 10 steps) from 0x80485b5: 1 sat>', '<SimProcedure __libc_start_main from 0x8400048: 1 sat>'])

    s_symbolic_read_addr_angr = p.factory.entry_state(args=['a'] * 8)
    pg_symbolic_read_addr_angr = p.factory.simulation_manager(s_symbolic_read_addr_angr).run()
    p_symbolic_read_addr_angr = pg_symbolic_read_addr_angr.one_deadended
    nose.tools.assert_equal(p_symbolic_read_addr_angr.history.bbl_addrs.hardcopy, p_symbolic_read_addr.history.bbl_addrs.hardcopy)

    # test STOP_SYMBOLIC_WRITE_ADDR
    s_symbolic_write_addr = p.factory.entry_state(args=['a'] * 9, add_options=so.unicorn)
    pg_symbolic_write_addr = p.factory.simulation_manager(s_symbolic_write_addr).run()
    p_symbolic_write_addr = pg_symbolic_write_addr.one_deadended
    _compare_trace(p_symbolic_write_addr.history.descriptions, ['<Unicorn (STOP_STOPPOINT after 4 steps) from 0x8048340: 1 sat>', '<SimProcedure __libc_start_main from 0x8119990: 1 sat>', '<Unicorn (STOP_STOPPOINT after 14 steps) from 0x8048650: 1 sat>', '<SimProcedure __libc_start_main from 0x8400044: 1 sat>', '<Unicorn (STOP_STOPPOINT after 10 steps) from 0x80485b5: 1 sat>', '<SimProcedure __libc_start_main from 0x8400048: 1 sat>'])

    s_symbolic_write_addr_angr = p.factory.entry_state(args=['a'] * 9)
    pg_symbolic_write_addr_angr = p.factory.simulation_manager(s_symbolic_write_addr_angr).run()
    p_symbolic_write_addr_angr = pg_symbolic_write_addr_angr.one_deadended
    nose.tools.assert_equal(p_symbolic_write_addr_angr.history.bbl_addrs.hardcopy, p_symbolic_write_addr.history.bbl_addrs.hardcopy)

    # test STOP_SYMBOLIC_BLOCK_EXIT
    s_symbolic_exit = p.factory.entry_state(args=['a'] * 10, add_options=so.unicorn)
    pg_symbolic_exit = p.factory.simulation_manager(s_symbolic_exit).run()
    p_symbolic_exit = pg_symbolic_exit.one_deadended
    _compare_trace(p_symbolic_exit.history.descriptions, ['<Unicorn (STOP_STOPPOINT after 4 steps) from 0x8048340: 1 sat>', '<SimProcedure __libc_start_main from 0x8119990: 1 sat>', '<Unicorn (STOP_STOPPOINT after 14 steps) from 0x8048650: 1 sat>', '<SimProcedure __libc_start_main from 0x8400044: 1 sat>', '<Unicorn (STOP_SYMBOLIC_BLOCK_EXIT_STMT after 7 steps) from 0x80485b5: 1 sat>', '<IRSB from 0x804855d: 2 sat 1 unsat>', '<Unicorn (STOP_STOPPOINT after 4 steps) from 0x8048587: 1 sat>', '<SimProcedure __libc_start_main from 0x8400048: 1 sat>'])

    s_symbolic_exit_angr = p.factory.entry_state(args=['a'] * 10)
    pg_symbolic_exit_angr = p.factory.simulation_manager(s_symbolic_exit_angr).run()
    p_symbolic_exit_angr = pg_symbolic_exit_angr.one_deadended
    nose.tools.assert_equal(p_symbolic_exit_angr.history.bbl_addrs.hardcopy, p_symbolic_exit.history.bbl_addrs.hardcopy)

def run_longinit(arch):
    p = angr.Project(os.path.join(test_location, 'binaries', 'tests', arch, 'longinit'))
    s_unicorn = p.factory.entry_state(add_options=so.unicorn, remove_options={so.SHORT_READS})
    pg = p.factory.simulation_manager(s_unicorn, save_unconstrained=True, save_unsat=True)
    pg.explore()
    s = pg.deadended[0]
    (first, _), (second, _) = s.posix.stdin.content
    s.add_constraints(first == s.solver.BVV(b'A'*9))
    s.add_constraints(second == s.solver.BVV(b'B'*9))
    nose.tools.assert_equal(s.posix.dumps(1), b"You entered AAAAAAAAA and BBBBBBBBB!\n")

def test_longinit_i386():
    run_longinit('i386')
def test_longinit_x86_64():
    run_longinit('x86_64')

def test_fauxware_arm():
    p = angr.Project(os.path.join(test_location, 'binaries', 'tests', 'armel', 'fauxware'))
    s_unicorn = p.factory.entry_state(add_options=so.unicorn) # unicorn
    pg = p.factory.simulation_manager(s_unicorn)
    pg.explore()
    assert all("Unicorn" in ''.join(p.history.descriptions.hardcopy) for p in pg.deadended)
    nose.tools.assert_equal(sorted(pg.mp_deadended.posix.dumps(1).mp_items), sorted((
        b'Username: \nPassword: \nWelcome to the admin console, trusted user!\n',
        b'Username: \nPassword: \nGo away!',
        b'Username: \nPassword: \nWelcome to the admin console, trusted user!\n'
    )))


def test_fauxware():
    p = angr.Project(os.path.join(test_location, 'binaries', 'tests', 'i386', 'fauxware'))
    s_unicorn = p.factory.entry_state(add_options=so.unicorn) # unicorn
    pg = p.factory.simulation_manager(s_unicorn)
    pg.explore()

    assert all("Unicorn" in ''.join(p.history.descriptions.hardcopy) for p in pg.deadended)
    nose.tools.assert_equal(sorted(pg.mp_deadended.posix.dumps(1).mp_items), sorted((
        b'Username: \nPassword: \nWelcome to the admin console, trusted user!\n',
        b'Username: \nPassword: \nGo away!',
        b'Username: \nPassword: \nWelcome to the admin console, trusted user!\n'
    )))

def test_fauxware_aggressive():
    p = angr.Project(os.path.join(test_location, 'binaries', 'tests', 'i386', 'fauxware'))
    s_unicorn = p.factory.entry_state(
        add_options=so.unicorn | { so.UNICORN_AGGRESSIVE_CONCRETIZATION },
        remove_options={ so.LAZY_SOLVES }
    ) # unicorn
    s_unicorn.unicorn.cooldown_symbolic_stop = 2
    s_unicorn.unicorn.cooldown_unsupported_stop = 2
    s_unicorn.unicorn.cooldown_nonunicorn_blocks = 0

    pg = p.factory.simulation_manager(s_unicorn)
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
        cc.simgr = prehook(cc.simgr)
    cc.run(depth=depth)

@attr(speed='slow')
def test_similarity_fauxware():
    def cooldown(pg):
        # gotta skip the initializers because of cpuid and RDTSC
        pg.one_left.unicorn.countdown_nonunicorn_blocks = 39
        return pg
    run_similarity(os.path.join("binaries", "tests", "i386", "fauxware"), 1000, prehook=cooldown)

def test_fp():
    with open(os.path.join(test_location, 'binaries', 'tests_src', 'manyfloatsum.c')) as fp:
        type_cache = angr.sim_type.parse_defns(fp.read())
    p = angr.Project(os.path.join(test_location, 'binaries', 'tests', 'i386', 'manyfloatsum'))

    for function in ('sum_floats', 'sum_combo', 'sum_segregated', 'sum_doubles', 'sum_combo_doubles', 'sum_segregated_doubles'):
        cc = p.factory.cc(func_ty=type_cache[function])
        args = list(range(len(cc.func_ty.args)))
        answer = float(sum(args))
        addr = p.loader.find_symbol(function).rebased_addr
        my_callable = p.factory.callable(addr, cc=cc)
        my_callable.set_base_state(p.factory.blank_state(add_options=so.unicorn))
        result = my_callable(*args)
        nose.tools.assert_false(result.symbolic)
        result_concrete = result.args[0]
        nose.tools.assert_equal(answer, result_concrete)

def test_unicorn_pickle():
    p = angr.Project(os.path.join(test_location, 'binaries', 'tests', 'i386', 'fauxware'))

    def _uni_state():
        # try pickling out paths that went through unicorn
        s_unicorn = p.factory.entry_state(add_options=so.unicorn)
        s_unicorn.unicorn.countdown_nonunicorn_blocks = 0
        s_unicorn.unicorn.countdown_symbolic_stop = 0
        s_unicorn.unicorn.cooldown_nonunicorn_blocks = 0
        s_unicorn.unicorn.cooldown_symbolic_stop = 2
        return s_unicorn

    pg = p.factory.simulation_manager(_uni_state())
    pg.one_active.options.update(so.unicorn)
    pg.run(until=lambda lpg: "Unicorn" in lpg.one_active.history.recent_description)
    assert len(pg.active) > 0

    pgp = pickle.dumps(pg, -1)
    del pg
    gc.collect()
    pg2 = pickle.loads(pgp)
    pg2.explore()

    nose.tools.assert_equal(sorted(pg2.mp_deadended.posix.dumps(1).mp_items), sorted((
        b'Username: \nPassword: \nWelcome to the admin console, trusted user!\n',
        b'Username: \nPassword: \nGo away!',
        b'Username: \nPassword: \nWelcome to the admin console, trusted user!\n'
    )))

    # test the pickling of SimUnicorn itself
    p = angr.Project(os.path.join(test_location, 'binaries', 'tests', 'i386', 'fauxware'))
    pg = p.factory.simulation_manager(_uni_state())
    pg.run(n=2)
    assert p.factory.successors(pg.one_active).sort == 'Unicorn'

    pgp = pickle.dumps(pg, -1)
    del pg
    gc.collect()
    pg2 = pickle.loads(pgp)
    pg2.explore()

    nose.tools.assert_equal(sorted(pg2.mp_deadended.posix.dumps(1).mp_items), sorted((
        b'Username: \nPassword: \nWelcome to the admin console, trusted user!\n',
        b'Username: \nPassword: \nGo away!',
        b'Username: \nPassword: \nWelcome to the admin console, trusted user!\n'
    )))

def test_concrete_transmits():
    p = angr.Project(os.path.join(test_location, 'binaries', 'tests', 'cgc', 'PIZZA_00001'))
    inp = bytes.fromhex("320a310a0100000005000000330a330a340a")

    s_unicorn = p.factory.entry_state(add_options=so.unicorn | {so.CGC_NO_SYMBOLIC_RECEIVE_LENGTH}, stdin=inp, flag_page=b'\0'*4096)
    pg_unicorn = p.factory.simulation_manager(s_unicorn)
    pg_unicorn.run(n=10)

    nose.tools.assert_equal(pg_unicorn.one_active.posix.dumps(1), b'1) Add number to the array\n2) Add random number to the array\n3) Sum numbers\n4) Exit\nRandomness added\n1) Add number to the array\n2) Add random number to the array\n3) Sum numbers\n4) Exit\n  Index: \n1) Add number to the array\n2) Add random number to the array\n3) Sum numbers\n4) Exit\n')

def test_inspect():
    p = angr.Project(os.path.join(test_location, 'binaries', 'tests', 'i386', 'uc_stop'))

    def main_state(argc, add_options=None):
        add_options = add_options or so.unicorn
        main_addr = p.loader.find_symbol("main").rebased_addr
        return p.factory.call_state(main_addr, argc, [], add_options=add_options)

    # test breaking on specific addresses
    s_break_addr = main_state(1)
    addr0 = 0x08048479 # at the beginning of a basic block, at end of stop_normal function
    addr1 = 0x080485d0 # this is at the beginning of main, in the middle of a basic block
    addr2 = 0x08048461 # another non-bb address, at the start of stop_normal
    addr3 = 0x0804847c # address of a block that should not get hit (stop_symbolc function)
    addr4 = 0x08048632 # another address that shouldn't get hit, near end of main
    hits = { addr0 : 0, addr1: 0, addr2: 0, addr3: 0, addr4: 0 }

    def create_addr_action(addr):
        def action(_state):
            hits[addr] += 1
        return action

    for addr in [addr0, addr1, addr2]:
        s_break_addr.inspect.b("instruction", instruction=addr, action=create_addr_action(addr))

    pg_instruction = p.factory.simulation_manager(s_break_addr)
    pg_instruction.run()
    nose.tools.assert_equal(hits[addr0], 1)
    nose.tools.assert_equal(hits[addr1], 1)
    nose.tools.assert_equal(hits[addr2], 1)
    nose.tools.assert_equal(hits[addr3], 0)
    nose.tools.assert_equal(hits[addr4], 0)

    # test breaking on every instruction
    def collect_trace(options):
        s_break_every = main_state(1, add_options=options)
        trace = []
        def action_every(state):
            trace.append(state.addr)
        s_break_every.inspect.b("instruction", action=action_every)
        pg_break_every = p.factory.simulation_manager(s_break_every)
        pg_break_every.run()
    nose.tools.assert_equal(collect_trace(so.unicorn), collect_trace(set()))

def test_explore():
    p = angr.Project(os.path.join(test_location, 'binaries', 'tests', 'i386', 'uc_stop'))

    def main_state(argc, add_options=None):
        add_options = add_options or so.unicorn
        main_addr = p.loader.find_symbol("main").rebased_addr
        return p.factory.call_state(main_addr, argc, [], add_options=add_options)

    addr = 0x08048479
    s_explore = main_state(1)
    pg_explore_find = p.factory.simulation_manager(s_explore)
    pg_explore_find.explore(find=addr)
    nose.tools.assert_equal(len(pg_explore_find.found), 1)
    nose.tools.assert_equal(pg_explore_find.found[0].addr, addr)

    pg_explore_avoid = p.factory.simulation_manager(s_explore)
    pg_explore_avoid.explore(avoid=addr)
    nose.tools.assert_equal(len(pg_explore_avoid.avoid), 1)
    nose.tools.assert_equal(pg_explore_avoid.avoid[0].addr, addr)


def test_single_step():
    p = angr.Project(os.path.join(test_location, 'binaries', 'tests', 'i386', 'uc_stop'))


    def main_state(argc, add_options=None):
        add_options = add_options or so.unicorn
        main_addr = p.loader.find_symbol("main").rebased_addr
        return p.factory.call_state(main_addr, argc, [], add_options=add_options)

    s_main = main_state(1)

    step1 = s_main.block().instruction_addrs[1]
    successors1 = s_main.step(num_inst=1).successors
    nose.tools.assert_equal(len(successors1), 1)
    nose.tools.assert_equal(successors1[0].addr, step1)

    step5 = s_main.block().instruction_addrs[5]
    successors2 = successors1[0].step(num_inst=4).successors
    nose.tools.assert_equal(len(successors2), 1)
    nose.tools.assert_equal(successors2[0].addr, step5)

if __name__ == '__main__':
    import logging
    logging.getLogger('angr.state_plugins.unicorn_engine').setLevel('DEBUG')
    logging.getLogger('angr.engines.unicorn_engine').setLevel('INFO')
    logging.getLogger('angr.factory').setLevel('DEBUG')
    logging.getLogger('angr.project').setLevel('DEBUG')
    #logging.getLogger('claripy.backends.backend_z3').setLevel('DEBUG')

    import sys
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            print('test_' + arg)
            res = globals()['test_' + arg]()
            if hasattr(res, '__iter__'):
                for ft in res:
                    fo = ft[0]
                    fa = ft[1:]
                    print('...', fa)
                    fo(*fa)
    else:
        for fk, fv in list(globals().items()):
            if fk.startswith('test_') and callable(fv):
                print(fk)
                res = fv()
                if hasattr(res, '__iter__'):
                    for ft in res:
                        fo = ft[0]
                        fa = ft[1:]
                        print('...', fa)
                        fo(*fa)