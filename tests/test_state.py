import simuvex
import nose
import logging

from simuvex import SimState

def test_state():
    s = simuvex.SimState(arch='AMD64')
    s.registers.store('sp', 0x7ffffffffff0000)
    nose.tools.assert_equals(s.se.any_int(s.registers.load('sp')), 0x7ffffffffff0000)

    s.stack_push(s.BVV("ABCDEFGH"))
    nose.tools.assert_equals(s.se.any_int(s.registers.load('sp')), 0x7fffffffffefff8)
    s.stack_push(s.BVV("IJKLMNOP"))
    nose.tools.assert_equals(s.se.any_int(s.registers.load('sp')), 0x7fffffffffefff0)

    a = s.stack_pop()
    nose.tools.assert_equals(s.se.any_int(s.registers.load('sp')), 0x7fffffffffefff8)
    nose.tools.assert_equals(s.se.any_str(a), "IJKLMNOP")

    b = s.stack_pop()
    nose.tools.assert_equals(s.se.any_int(s.registers.load('sp')), 0x7ffffffffff0000)
    nose.tools.assert_equals(s.se.any_str(b), "ABCDEFGH")

#@nose.tools.timed(10)
def test_state_merge():
    a = SimState(mode='symbolic')
    a.memory.store(1, a.se.BitVecVal(42, 8))

    b = a.copy()
    c = b.copy()
    a.memory.store(2, a.memory.load(1, 1)+1)
    b.memory.store(2, b.memory.load(1, 1)*2)
    c.memory.store(2, c.memory.load(1, 1)/2)

    # make sure the byte at 1 is right
    nose.tools.assert_equal(a.se.any_int(a.memory.load(1, 1)), 42)
    nose.tools.assert_equal(b.se.any_int(b.memory.load(1, 1)), 42)
    nose.tools.assert_equal(c.se.any_int(c.memory.load(1, 1)), 42)

    # make sure the byte at 2 is right
    nose.tools.assert_equal(a.se.any_int(a.memory.load(2, 1)), 43)
    nose.tools.assert_equal(b.se.any_int(b.memory.load(2, 1)), 84)
    nose.tools.assert_equal(c.se.any_int(c.memory.load(2, 1)), 21)

    # the byte at 2 should be unique for all before the merge
    nose.tools.assert_true(a.se.unique(a.memory.load(2, 1)))
    nose.tools.assert_true(b.se.unique(b.memory.load(2, 1)))
    nose.tools.assert_true(c.se.unique(c.memory.load(2, 1)))

    logging.getLogger('simuvex.plugins.symbolic_memory').setLevel(logging.DEBUG)
    m, merge_flag, merging_occurred = a.merge(b, c)
    logging.getLogger('simuvex.plugins.symbolic_memory').setLevel(logging.WARNING)

    nose.tools.assert_true(merging_occurred)
    nose.tools.assert_equals(sorted(m.se.any_n_int(merge_flag, 10)), [ 0,1,2 ])

    # the byte at 2 should now *not* be unique for a
    nose.tools.assert_false(m.se.unique(m.memory.load(2, 1)))
    nose.tools.assert_true(a.se.unique(a.memory.load(2, 1)))
    nose.tools.assert_true(b.se.unique(b.memory.load(2, 1)))
    nose.tools.assert_true(c.se.unique(c.memory.load(2, 1)))

    # the byte at 2 should have the three values
    nose.tools.assert_items_equal(m.se.any_n_int(m.memory.load(2, 1), 10), (43, 84, 21))

    # we should be able to select them by adding constraints
    a_a = m.copy()
    a_a.add_constraints(merge_flag == 0)
    nose.tools.assert_true(a_a.se.unique(a_a.memory.load(2, 1)))
    nose.tools.assert_equal(a_a.se.any_int(a_a.memory.load(2, 1)), 43)

    a_b = m.copy()
    a_b.add_constraints(merge_flag == 1)
    nose.tools.assert_true(a_b.se.unique(a_b.memory.load(2, 1)))
    nose.tools.assert_equal(a_b.se.any_int(a_b.memory.load(2, 1)), 84)

    a_c = m.copy()
    a_c.add_constraints(merge_flag == 2)
    nose.tools.assert_true(a_c.se.unique(a_c.memory.load(2, 1)))
    nose.tools.assert_equal(a_c.se.any_int(a_c.memory.load(2, 1)), 21)

    # test different sets of plugins
    a = SimState(mode='symbolic')
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
    a = SimState(mode='symbolic')
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
    a = SimState(mode='static')
    se = a.se

    addr = a.se.ValueSet(region='global', bits=32, val=8)
    a.memory.store(addr, a.se.BitVecVal(42, 32))
    # Clear a_locs, so further writes will not try to merge with value 42
    a.memory.regions['global']._alocs = { }

    b = a.copy()
    c = a.copy()
    a.memory.store(addr, a.se.BitVecVal(50, 32), endness='Iend_LE')
    b.memory.store(addr, a.se.BitVecVal(60, 32), endness='Iend_LE')
    c.memory.store(addr, a.se.BitVecVal(70, 32), endness='Iend_LE')

    merged, _, _ = a.merge(b, c)
    nose.tools.assert_true(merged.memory.load(addr, 4).identical(a.se.SI(bits=32, stride=10, lower_bound=50, upper_bound=70)))

if __name__ == '__main__':
    test_state()
    test_state_merge()
    test_state_merge_static()
