import simuvex
import nose

from simuvex import SimState

#def broken_symvalue():
#   # concrete symvalue
#   zero = SimValue(se.BVV(0, 64))
#   nose.tools.assert_false(zero.is_symbolic())
#   nose.tools.assert_equal(zero.any_int(), 0)
#   nose.tools.assert_raises(ConcretizingException, zero.exactly_n, 2)
#
#   # symbolic symvalue
#   x = se.BVS('x', 64)
#   sym = SimValue(x, constraints = [ x > 100, x < 200 ])
#   nose.tools.assert_true(sym.is_symbolic())
#   nose.tools.assert_equal(sym.min_int(), 101)
#   nose.tools.assert_equal(sym.max_int(), 199)
#   nose.tools.assert_items_equal(sym.any_n_int(99), range(101, 200))
#   nose.tools.assert_raises(ConcretizingException, zero.exactly_n, 102)

def test_concretization_strategies():
    initial_memory = {0: 'A', 1: 'B', 2: 'C', 3: 'D'}

    s = SimState(memory_backer=initial_memory)

    # sanity check
    nose.tools.assert_equal(s.se.any_n_str(s.memory.load(3, 1), 2), ['D'])

    x = s.se.BVS('x', s.arch.bits)
    s.add_constraints(x >= 1)

    ss = s.copy()
    nose.tools.assert_equal(ss.se.any_n_str(ss.memory.load(x, 1), 2), ['B'])

    ss = s.copy()
    ss.options.add(simuvex.o.CONSERVATIVE_READ_STRATEGY)
    nose.tools.assert_true('symbolic' in next(iter(ss.memory.load(x, 1).variables)))

#def test_concretization():
#   s = SimState(arch="AMD64", mode="symbolic")
#   dst = s.se.BVV(0x41424300, 32)
#   dst_addr = s.se.BVV(0x1000, 64)
#   s.memory.store(dst_addr, dst, 4)
#
#   print "MEM KEYS", s.memory.mem.keys()
#   print "REG KEYS", s.registers.mem.keys()
#
#   print "TO NATIVE..."
#   s.set_native(True)
#   print "... done"
#
#   vv = s.native_env.vexecute(pyvex.IRExpr.Load("Iend_BE", "Ity_I32", pyvex.IRExpr.Const(pyvex.IRConst.U64(0x1000))))
#   nose.tools.assert_equals(vv.str[:4], 'ABC\x00')
#   s.native_env.vexecute(pyvex.IRSB(bytes='\xb8\x41\x42\x43\x44'))
#
#   #import IPython; IPython.embed()
#   print "FROM NATIVE..."
#   s.set_native(False)
#   print "... done"
#
#   nose.tools.assert_equals(s.reg_value(16).se.any_int(), 0x44434241)
#   print "YEAH"

#@nose.tools.timed(10)
def broken_symbolic_write():
    s = SimState(arch='AMD64', mode='symbolic')

    addr = s.se.BVS('addr', 64)
    s.add_constraints(s.se.Or(addr == 10, addr == 20, addr == 30))
    nose.tools.assert_equals(len(s.se.any_n_int(addr, 10)), 3)

    s.memory.store(10, s.se.BVV(1, 8))
    s.memory.store(20, s.se.BVV(2, 8))
    s.memory.store(30, s.se.BVV(3, 8))

    nose.tools.assert_true(s.se.unique(s.memory.load(10, 1)))
    nose.tools.assert_true(s.se.unique(s.memory.load(20, 1)))
    nose.tools.assert_true(s.se.unique(s.memory.load(30, 1)))

    #print "CONSTRAINTS BEFORE:", s.constraints._solver.constraints
    #s.memory.store(addr, s.se.BVV(255, 8), strategy=['symbolic','any'], limit=100)
    s.memory.store(addr, s.se.BVV(255, 8))
    nose.tools.assert_true(s.satisfiable())
    print "GO TIME"
    nose.tools.assert_equals(len(s.se.any_n_int(addr, 10)), 3)
    nose.tools.assert_items_equal(s.se.any_n_int(s.memory.load(10, 1), 3), [ 1, 255 ])
    nose.tools.assert_items_equal(s.se.any_n_int(s.memory.load(20, 1), 3), [ 2, 255 ])
    nose.tools.assert_items_equal(s.se.any_n_int(s.memory.load(30, 1), 3), [ 3, 255 ])
    nose.tools.assert_equals(len(s.se.any_n_int(addr, 10)), 3)

    # see if it works when constraining the write address
    sa = s.copy()
    sa.add_constraints(addr == 20)
    nose.tools.assert_true(sa.satisfiable())
    nose.tools.assert_items_equal(sa.se.any_n_int(sa.memory.load(10, 1), 3), [ 1 ])
    nose.tools.assert_items_equal(sa.se.any_n_int(sa.memory.load(20, 1), 3), [ 255 ])
    nose.tools.assert_items_equal(sa.se.any_n_int(sa.memory.load(30, 1), 3), [ 3 ])
    nose.tools.assert_items_equal(sa.se.any_n_int(addr, 10), [ 20 ])

    # see if it works when constraining a value to the written one
    sv = s.copy()
    sv.add_constraints(sv.memory.load(30, 1) == 255)
    nose.tools.assert_true(sv.satisfiable())
    nose.tools.assert_items_equal(sv.se.any_n_int(sv.memory.load(10, 1), 3), [ 1 ])
    nose.tools.assert_items_equal(sv.se.any_n_int(sv.memory.load(20, 1), 3), [ 2 ])
    nose.tools.assert_items_equal(sv.se.any_n_int(sv.memory.load(30, 1), 3), [ 255 ])
    nose.tools.assert_items_equal(sv.se.any_n_int(addr, 10), [ 30 ])

    # see if it works when constraining a value to the unwritten one
    sv = s.copy()
    sv.add_constraints(sv.memory.load(30, 1) == 3)
    nose.tools.assert_true(sv.satisfiable())
    nose.tools.assert_items_equal(sv.se.any_n_int(sv.memory.load(10, 1), 3), [ 1, 255 ])
    nose.tools.assert_items_equal(sv.se.any_n_int(sv.memory.load(20, 1), 3), [ 2, 255 ])
    nose.tools.assert_items_equal(sv.se.any_n_int(sv.memory.load(30, 1), 3), [ 3 ])
    nose.tools.assert_items_equal(sv.se.any_n_int(addr, 10), [ 10, 20 ])

    s = SimState(arch='AMD64', mode='symbolic')
    s.memory.store(0, s.se.BVV(0x4141414141414141, 64))
    length = s.se.BVS("length", 32)
    #s.memory.store(0, s.se.BVV(0x4242424242424242, 64), symbolic_length=length)
    s.memory.store(0, s.se.BVV(0x4242424242424242, 64))

    for i in range(8):
        ss = s.copy()
        ss.add_constraints(length == i)
        nose.tools.assert_equal(ss.se.any_str(s.memory.load(0, 8)), "B"*i + "A"*(8-i))

    print "GROOVY"

if __name__ == '__main__':
    test_concretization_strategies()
