import logging
import claripy
import pickle
import nose
import ana
import gc

from angr import SimState

def test_state():
    s = SimState(arch='AMD64')
    s.registers.store('sp', 0x7ffffffffff0000)
    nose.tools.assert_equals(s.se.eval(s.registers.load('sp')), 0x7ffffffffff0000)

    s.stack_push(s.se.BVV("ABCDEFGH"))
    nose.tools.assert_equals(s.se.eval(s.registers.load('sp')), 0x7fffffffffefff8)
    s.stack_push(s.se.BVV("IJKLMNOP"))
    nose.tools.assert_equals(s.se.eval(s.registers.load('sp')), 0x7fffffffffefff0)

    a = s.stack_pop()
    nose.tools.assert_equals(s.se.eval(s.registers.load('sp')), 0x7fffffffffefff8)
    nose.tools.assert_equals(s.se.eval(a, cast_to=str), "IJKLMNOP")

    b = s.stack_pop()
    nose.tools.assert_equals(s.se.eval(s.registers.load('sp')), 0x7ffffffffff0000)
    nose.tools.assert_equals(s.se.eval(b, cast_to=str), "ABCDEFGH")

#@nose.tools.timed(10)
def test_state_merge():
    a = SimState(arch='AMD64', mode='symbolic')
    a.memory.store(1, a.se.BVV(42, 8))

    b = a.copy()
    c = b.copy()
    a.memory.store(2, a.memory.load(1, 1)+1)
    b.memory.store(2, b.memory.load(1, 1)*2)
    c.memory.store(2, c.memory.load(1, 1)/2)

    # make sure the byte at 1 is right
    nose.tools.assert_equal(a.se.eval(a.memory.load(1, 1)), 42)
    nose.tools.assert_equal(b.se.eval(b.memory.load(1, 1)), 42)
    nose.tools.assert_equal(c.se.eval(c.memory.load(1, 1)), 42)

    # make sure the byte at 2 is right
    nose.tools.assert_equal(a.se.eval(a.memory.load(2, 1)), 43)
    nose.tools.assert_equal(b.se.eval(b.memory.load(2, 1)), 84)
    nose.tools.assert_equal(c.se.eval(c.memory.load(2, 1)), 21)

    # the byte at 2 should be unique for all before the merge
    nose.tools.assert_true(a.se.unique(a.memory.load(2, 1)))
    nose.tools.assert_true(b.se.unique(b.memory.load(2, 1)))
    nose.tools.assert_true(c.se.unique(c.memory.load(2, 1)))

    logging.getLogger('angr.state_plugins.symbolic_memory').setLevel(logging.DEBUG)
    m, merge_conditions, merging_occurred = a.merge(b, c)
    logging.getLogger('angr.state_plugins.symbolic_memory').setLevel(logging.WARNING)

    nose.tools.assert_true(merging_occurred)
    #nose.tools.assert_equals(sorted(m.se.eval_upto(merge_flag, 10)), [ 0,1,2 ])
    assert len(merge_conditions) == 3

    # the byte at 2 should now *not* be unique for a
    nose.tools.assert_false(m.se.unique(m.memory.load(2, 1)))
    nose.tools.assert_true(a.se.unique(a.memory.load(2, 1)))
    nose.tools.assert_true(b.se.unique(b.memory.load(2, 1)))
    nose.tools.assert_true(c.se.unique(c.memory.load(2, 1)))

    # the byte at 2 should have the three values
    nose.tools.assert_items_equal(m.se.eval_upto(m.memory.load(2, 1), 10), (43, 84, 21))

    # we should be able to select them by adding constraints
    a_a = m.copy()
    a_a.add_constraints(merge_conditions[0])
    nose.tools.assert_true(a_a.se.unique(a_a.memory.load(2, 1)))
    nose.tools.assert_equal(a_a.se.eval(a_a.memory.load(2, 1)), 43)

    a_b = m.copy()
    a_b.add_constraints(merge_conditions[1])
    nose.tools.assert_true(a_b.se.unique(a_b.memory.load(2, 1)))
    nose.tools.assert_equal(a_b.se.eval(a_b.memory.load(2, 1)), 84)

    a_c = m.copy()
    a_c.add_constraints(merge_conditions[2])
    nose.tools.assert_true(a_c.se.unique(a_c.memory.load(2, 1)))
    nose.tools.assert_equal(a_c.se.eval(a_c.memory.load(2, 1)), 21)

    # test different sets of plugins
    a = SimState(arch='AMD64', mode='symbolic')
    nose.tools.assert_true(a.has_plugin('memory'))
    nose.tools.assert_true(a.has_plugin('registers'))
    nose.tools.assert_false(a.has_plugin('libc'))

    b = a.copy()
    a.get_plugin('libc')
    nose.tools.assert_true(a.has_plugin('libc'))
    nose.tools.assert_false(b.has_plugin('libc'))
    c = a.copy().merge(b.copy())[0]
    d = b.copy().merge(a.copy())[0]
    nose.tools.assert_true(c.has_plugin('libc'))
    nose.tools.assert_true(d.has_plugin('libc'))

    # test merging posix with different open files
    a = SimState(arch='AMD64', mode='symbolic')
    b = a.copy()
    a.posix.get_file(3)
    nose.tools.assert_equal(len(a.posix.files), 4)
    nose.tools.assert_equal(len(b.posix.files), 3)
    c = a.copy().merge(b.copy())[0]
    d = b.copy().merge(a.copy())[0]
    nose.tools.assert_equal(len(c.posix.files), 4)
    nose.tools.assert_equal(len(d.posix.files), 4)

def test_state_merge_static():
    # With abstract memory
    # Aligned memory merging
    a = SimState(arch='AMD64', mode='static')

    addr = a.se.ValueSet(32, 'global', 0, 8)
    a.memory.store(addr, a.se.BVV(42, 32))
    # Clear a_locs, so further writes will not try to merge with value 42
    a.memory.regions['global']._alocs = { }

    b = a.copy()
    c = a.copy()
    a.memory.store(addr, a.se.BVV(50, 32), endness='Iend_LE')
    b.memory.store(addr, a.se.BVV(60, 32), endness='Iend_LE')
    c.memory.store(addr, a.se.BVV(70, 32), endness='Iend_LE')

    merged, _, _ = a.merge(b, c)
    actual = claripy.backends.vsa.convert(merged.memory.load(addr, 4))
    expected = claripy.backends.vsa.convert(a.se.SI(bits=32, stride=10, lower_bound=50, upper_bound=70))
    nose.tools.assert_true(actual.identical(expected))

def setup():
    ana.set_dl(ana.DirDataLayer('/tmp/picklez'))
def teardown():
    ana.set_dl(ana.SimpleDataLayer())

@nose.with_setup(setup, teardown)
def test_state_pickle():
    s = SimState(arch="AMD64")
    s.memory.store(100, s.se.BVV(0x4141414241414241424300, 88), endness='Iend_BE')
    s.regs.rax = 100

    sp = pickle.dumps(s)
    del s
    gc.collect()
    s = pickle.loads(sp)
    nose.tools.assert_equals(s.se.eval(s.memory.load(100, 10), cast_to=str), "AAABAABABC")

def test_global_condition():
    s = SimState(arch="AMD64")

    s.regs.rax = 10
    old_rax = s.regs.rax
    with s.with_condition(False):
        nose.tools.assert_false(s.se.satisfiable())
        s.regs.rax = 20
    nose.tools.assert_is(s._global_condition, None)
    nose.tools.assert_is(old_rax, s.regs.rax)

    with s.with_condition(True):
        s.regs.rax = 20
    nose.tools.assert_is(s._global_condition, None)
    nose.tools.assert_is_not(old_rax, s.regs.rax)
    nose.tools.assert_is(s.se.BVV(20, s.arch.bits), s.regs.rax)

    with s.with_condition(s.regs.rbx != 0):
        s.regs.rax = 25
    nose.tools.assert_is(s._global_condition, None)
    nose.tools.assert_is_not(s.se.BVV(25, s.arch.bits), s.regs.rax)

    with s.with_condition(s.regs.rbx != 1):
        s.regs.rax = 30
    nose.tools.assert_is(s._global_condition, None)
    nose.tools.assert_is_not(s.se.BVV(30, s.arch.bits), s.regs.rax)

    with s.with_condition(s.regs.rbx == 0):
        nose.tools.assert_equals(s.se.eval_upto(s.regs.rbx, 10), [ 0 ])
        nose.tools.assert_items_equal(s.se.eval_upto(s.regs.rax, 10), [ 30 ])
    with s.with_condition(s.regs.rbx == 1):
        nose.tools.assert_equals(s.se.eval_upto(s.regs.rbx, 10), [ 1 ])
        nose.tools.assert_items_equal(s.se.eval_upto(s.regs.rax, 10), [ 25 ])


if __name__ == '__main__':
    test_state()
    test_state_merge()
    test_state_merge_static()
    test_state_pickle()
    test_global_condition()
