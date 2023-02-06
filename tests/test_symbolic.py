import angr

# def broken_symvalue():
#   # concrete symvalue
#   zero = SimValue(se.BVV(0, 64))
#   assert not zero.is_symbolic()
#   assert zero.eval() == 0
#
#   # symbolic symvalue
#   x = se.BVS('x', 64)
#   sym = SimValue(x, constraints = [ x > 100, x < 200 ])
#   assert sym.is_symbolic()
#   assert sym.min_int() == 101
#   assert sym.max_int() == 199
#   assert sym.eval_upto(99) == range(101, 200)


def test_concretization_strategies():
    initial_memory = {0: b"A", 1: b"B", 2: b"C", 3: b"D"}

    s = angr.SimState(arch="AMD64", dict_memory_backer=initial_memory)

    # sanity check
    assert s.solver.eval_upto(s.memory.load(3, size=1), 2, cast_to=bytes) == [b"D"]

    x = s.solver.BVS("x", s.arch.bits)
    s.add_constraints(x >= 1)
    s.add_constraints(x <= 3)

    ss = s.copy()
    assert tuple(sorted(ss.solver.eval_upto(ss.memory.load(x, 1), 10, cast_to=bytes))) == (b"B", b"C", b"D")

    ss = s.copy()
    x = s.solver.BVS("x", s.arch.bits)
    s.add_constraints(x >= 1)
    ss.options.add(angr.options.CONSERVATIVE_READ_STRATEGY)
    ss.memory._create_default_read_strategies()
    assert "symbolic" in next(iter(ss.memory.load(x, 1).variables))


# def test_concretization():
#   s = angr.SimState(arch="AMD64", mode="symbolic")
#   dst = s.solver.BVV(0x41424300, 32)
#   dst_addr = s.solver.BVV(0x1000, 64)
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
#   assert vv.str[:4] == 'ABC\x00'
#   s.native_env.vexecute(pyvex.IRSB(bytes='\xb8\x41\x42\x43\x44'))
#
#   #import IPython; IPython.embed()
#   print "FROM NATIVE..."
#   s.set_native(False)
#   print "... done"
#
#   assert s.reg_value(16).solver.eval() == 0x44434241
#   print "YEAH"


def broken_symbolic_write():
    s = angr.SimState(arch="AMD64", mode="symbolic")

    addr = s.solver.BVS("addr", 64)
    s.add_constraints(s.solver.Or(addr == 10, addr == 20, addr == 30))
    assert len(s.solver.eval_upto(addr, 10)) == 3

    s.memory.store(10, s.solver.BVV(1, 8))
    s.memory.store(20, s.solver.BVV(2, 8))
    s.memory.store(30, s.solver.BVV(3, 8))

    assert s.solver.unique(s.memory.load(10, 1))
    assert s.solver.unique(s.memory.load(20, 1))
    assert s.solver.unique(s.memory.load(30, 1))

    # print "CONSTRAINTS BEFORE:", s.constraints._solver.constraints
    # s.memory.store(addr, s.solver.BVV(255, 8), strategy=['symbolic','any'], limit=100)
    s.memory.store(addr, s.solver.BVV(255, 8))
    assert s.satisfiable()

    assert len(s.solver.eval_upto(addr, 10)) == 3
    assert s.solver.eval_upto(s.memory.load(10, 1), 3) == [1, 255]
    assert s.solver.eval_upto(s.memory.load(20, 1), 3) == [2, 255]
    assert s.solver.eval_upto(s.memory.load(30, 1), 3) == [3, 255]
    assert len(s.solver.eval_upto(addr, 10)) == 3

    # see if it works when constraining the write address
    sa = s.copy()
    sa.add_constraints(addr == 20)
    assert sa.satisfiable()
    assert sa.solver.eval_upto(sa.memory.load(10, 1), 3) == [1]
    assert sa.solver.eval_upto(sa.memory.load(20, 1), 3) == [255]
    assert sa.solver.eval_upto(sa.memory.load(30, 1), 3) == [3]
    assert sa.solver.eval_upto(addr, 10) == [20]

    # see if it works when constraining a value to the written one
    sv = s.copy()
    sv.add_constraints(sv.memory.load(30, 1) == 255)
    assert sv.satisfiable()
    assert sv.solver.eval_upto(sv.memory.load(10, 1), 3) == [1]
    assert sv.solver.eval_upto(sv.memory.load(20, 1), 3) == [2]
    assert sv.solver.eval_upto(sv.memory.load(30, 1), 3) == [255]
    assert sv.solver.eval_upto(addr, 10) == [30]

    # see if it works when constraining a value to the unwritten one
    sv = s.copy()
    sv.add_constraints(sv.memory.load(30, 1) == 3)
    assert sv.satisfiable()
    assert sv.solver.eval_upto(sv.memory.load(10, 1), 3) == [1, 255]
    assert sv.solver.eval_upto(sv.memory.load(20, 1), 3) == [2, 255]
    assert sv.solver.eval_upto(sv.memory.load(30, 1), 3) == [3]
    assert sv.solver.eval_upto(addr, 10) == [10, 20]

    s = angr.SimState(arch="AMD64", mode="symbolic")
    s.memory.store(0, s.solver.BVV(0x4141414141414141, 64))
    length = s.solver.BVS("length", 32)
    # s.memory.store(0, s.solver.BVV(0x4242424242424242, 64), symbolic_length=length)
    s.memory.store(0, s.solver.BVV(0x4242424242424242, 64))

    for i in range(8):
        ss = s.copy()
        ss.add_constraints(length == i)
        assert ss.solver.eval(s.memory.load(0, 8), cast_to=bytes) == b"B" * i + b"A" * (8 - i)


def test_unsat_core():
    s = angr.SimState(arch="AMD64", mode="symbolic", add_options={angr.options.CONSTRAINT_TRACKING_IN_SOLVER})
    x = s.solver.BVS("x", 32)
    s.add_constraints(s.solver.BVV(0, 32) == x)
    s.add_constraints(s.solver.BVV(1, 32) == x)

    assert not s.satisfiable()
    unsat_core = s.solver.unsat_core()
    assert len(unsat_core) == 2


if __name__ == "__main__":
    test_unsat_core()
    test_concretization_strategies()
