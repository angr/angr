import time

import claripy
import nose

from angr.storage.paged_memory import SimPagedMemory
from angr import SimState, SIM_PROCEDURES
from angr import options as o
from angr.state_plugins import SimSystemPosix
from angr.storage.file import SimFile


def test_copy():
    s = SimState(arch="AMD64")
    s.memory.store(0x100, "ABCDEFGHIJKLMNOP")
    s.memory.store(0x200, "XXXXXXXXXXXXXXXX")
    x = s.se.BVS('size', s.arch.bits)
    s.add_constraints(s.se.ULT(x, 10))
    s.memory.copy_contents(0x200, 0x100, x)

    nose.tools.assert_equals(sorted(s.se.eval_upto(x, 100)), range(10))
    result = s.memory.load(0x200, 5)
    nose.tools.assert_equals(sorted(s.se.eval_upto(result, 100, cast_to=str)), [ "ABCDE", "ABCDX", "ABCXX", "ABXXX", "AXXXX", "XXXXX" ])
    nose.tools.assert_equals(sorted(s.se.eval_upto(result, 100, cast_to=str, extra_constraints=[x==3])), [ "ABCXX" ])

    s = SimState(arch="AMD64")
    s.register_plugin('posix', SimSystemPosix(stdin=SimFile(name='stdin', content='ABCDEFGHIJKLMNOP', has_end=True)))
    s.memory.store(0x200, "XXXXXXXXXXXXXXXX")
    x = s.se.BVS('size', s.arch.bits)
    s.add_constraints(s.se.ULT(x, 10))

    s.posix.get_fd(0).read(0x200, x)
    nose.tools.assert_equals(sorted(s.se.eval_upto(x, 100)), range(10))
    result = s.memory.load(0x200, 5)
    nose.tools.assert_equals(sorted(s.se.eval_upto(result, 100, cast_to=str)), [ "ABCDE", "ABCDX", "ABCXX", "ABXXX", "AXXXX", "XXXXX" ])
    nose.tools.assert_equals(sorted(s.se.eval_upto(result, 100, cast_to=str, extra_constraints=[x==3])), [ "ABCXX" ])

    s = SimState(arch="AMD64")
    s.register_plugin('posix', SimSystemPosix(stdin=SimFile(name='stdin', content='ABCDEFGHIJKLMNOP')))
    s.memory.store(0x200, "XXXXXXXXXXXXXXXX")
    x = s.se.BVS('size', s.arch.bits)
    s.add_constraints(s.se.ULT(x, 10))

    read_proc = SIM_PROCEDURES['posix']['read']()
    ret_x = read_proc.execute(s, arguments=(0, 0x200, x)).ret_expr
    nose.tools.assert_equals(sorted(s.se.eval_upto(x, 100)), range(10))
    result = s.memory.load(0x200, 5)
    nose.tools.assert_equals(sorted(s.se.eval_upto(result, 100, cast_to=str)), [ "ABCDE", "ABCDX", "ABCXX", "ABXXX", "AXXXX", "XXXXX" ])
    nose.tools.assert_equals(sorted(s.se.eval_upto(result, 100, cast_to=str, extra_constraints=[x==3])), [ "ABCXX" ])

    nose.tools.assert_equals(sorted(s.se.eval_upto(ret_x, 100)), range(10))
    nose.tools.assert_equals(sorted(s.se.eval_upto(result, 100, cast_to=str, extra_constraints=[ret_x==3])), [ "ABCXX" ])

def _concrete_memory_tests(s):
    # Store a 4-byte variable to memory directly...
    s.memory.store(100, s.se.BVV(0x1337, 32))
    # ... then load it
    print 'loading'
    expr = s.memory.load(100, 4)
    nose.tools.assert_is(expr, s.se.BVV(0x1337, 32))
    expr = s.memory.load(100, 2)
    nose.tools.assert_is(expr, s.se.BVV(0, 16))
    expr = s.memory.load(102, 2)
    nose.tools.assert_is(expr, s.se.BVV(0x1337, 16))

    # partially symbolic
    expr = s.memory.load(102, 4)
    assert expr.length == 32
    assert s.se.min(expr) == 0x13370000
    assert s.se.max(expr) == 0x1337ffff

    # partial overwrite
    s.memory.store(101, s.se.BVV(0x1415, 16))
    expr = s.memory.load(101, 3)
    nose.tools.assert_is(expr, s.se.BVV(0x141537, 24))
    expr = s.memory.load(100, 2)
    assert s.se.min(expr) == 0x14
    expr = s.memory.load(102, 2)
    nose.tools.assert_is(expr, s.se.BVV(0x1537, 16))
    expr = s.memory.load(102, 2, endness="Iend_LE")
    nose.tools.assert_is(expr, s.se.BVV(0x3715, 16))

    s.memory.store(0x100, s.se.BVV("AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"), endness="Iend_LE")
    expr = s.memory.load(0x104, 13)
    assert expr is s.se.BVV("GGGGFFFFEEEED")

    # branching
    s2 = s.copy()
    s2a = s2.copy()
    s2b = s2.copy()

    s2a.memory.store(0x100, s.se.BVV("A"))
    s2b.memory.store(0x100, s.se.BVV("B"))
    assert s2b.memory.load(0x100, 1) is s.se.BVV("B")
    assert s2a.memory.load(0x100, 1) is s.se.BVV("A")


## pylint: disable=R0904
#@nose.tools.timed(10)
def test_memory():
    initial_memory = { 0: 'A', 1: 'A', 2: 'A', 3: 'A', 10: 'B' }
    s = SimState(arch="AMD64", memory_backer=initial_memory, add_options={o.REVERSE_MEMORY_NAME_MAP, o.REVERSE_MEMORY_HASH_MAP})

    _concrete_memory_tests(s)
    # concrete address and partially symbolic result
    expr = s.memory.load(2, 4)
    expr = s.memory.load(2, 4)
    expr = s.memory.load(2, 4)
    expr = s.memory.load(2, 4)
    nose.tools.assert_true(s.se.symbolic(expr))
    nose.tools.assert_false(s.se.unique(expr))
    nose.tools.assert_greater_equal(s.se.eval(expr), 0x41410000)
    nose.tools.assert_less_equal(s.se.eval(expr), 0x41420000)
    nose.tools.assert_equal(s.se.min_int(expr), 0x41410000)
    nose.tools.assert_equal(s.se.max_int(expr), 0x4141ffff)

    # concrete address and concrete result
    expr = s.memory.load(0, 4) # Returns: a z3 BVS representing 0x41414141
    nose.tools.assert_false(s.se.symbolic(expr))
    nose.tools.assert_equal(s.se.eval(expr), 0x41414141)

    # symbolicize
    v = s.memory.make_symbolic("asdf", 0, length=4)
    nose.tools.assert_equal(v.size(), 32)
    nose.tools.assert_true(s.se.unique(v))
    nose.tools.assert_equal(s.se.eval(v), 0x41414141)

    expr = s.memory.load(0, 4) # Returns: a z3 BVS representing 0x41414141
    nose.tools.assert_true(s.se.symbolic(expr))
    nose.tools.assert_equal(s.se.eval(expr), 0x41414141)
    nose.tools.assert_true(s.se.unique(expr))

    c = s.se.BVS('condition', 8)
    expr = s.memory.load(10, 1, condition=c==1, fallback=s.se.BVV('X'))
    nose.tools.assert_equal(s.se.eval_upto(expr, 10, cast_to=str, extra_constraints=[c==1]), [ 'B' ])
    nose.tools.assert_equal(s.se.eval_upto(expr, 10, cast_to=str, extra_constraints=[c!=1]), [ 'X' ])

    x = s.se.BVS('ref_test', 16, explicit_name=True)
    s.memory.store(0x1000, x)
    s.memory.store(0x2000, x)
    nose.tools.assert_equal(set(s.memory.addrs_for_name('ref_test')), set((0x1000,0x1001,0x2000,0x2001)))
    nose.tools.assert_equal(set(s.memory.addrs_for_hash(hash(x))), set((0x1000, 0x1001, 0x2000, 0x2001)))

    s2 = s.copy()
    y = s2.se.BVS('ref_test2', 16, explicit_name=True)
    s2.memory.store(0x2000, y)
    assert s2.memory.load(0x2000, 2) is y
    assert s.memory.load(0x2000, 2) is x
    nose.tools.assert_equal(set(s.memory.addrs_for_name('ref_test')), set((0x1000,0x1001,0x2000,0x2001)))
    nose.tools.assert_equal(set(s.memory.addrs_for_hash(hash(x))), set((0x1000,0x1001,0x2000,0x2001)))
    nose.tools.assert_equal(set(s2.memory.addrs_for_name('ref_test')), set((0x1000, 0x1001)))
    nose.tools.assert_equal(set(s2.memory.addrs_for_hash(hash(x))), set((0x1000, 0x1001)))
    nose.tools.assert_equal(set(s2.memory.addrs_for_name('ref_test2')), set((0x2000, 0x2001)))
    nose.tools.assert_equal(set(s2.memory.addrs_for_hash(hash(y))), set((0x2000, 0x2001)))

    s.memory.store(0x3000, s.se.BVS('replace_old', 32, explicit_name=True))
    s.memory.store(0x3001, s.se.BVV('AB'))
    nose.tools.assert_equal(set(s.memory.addrs_for_name('replace_old')), set((0x3000, 0x3003)))
    nose.tools.assert_equal(s.se.eval_upto(s.memory.load(0x3001, 2), 10, cast_to=str), ["AB"])

    n = s.se.BVS('replace_new', 32, explicit_name=True)
    c = s.se.BVS('replace_cool', 32, explicit_name=True)

    mo = s.memory.memory_objects_for_name('replace_old')
    nose.tools.assert_equal(len(mo), 1)
    s.memory.replace_memory_object(next(iter(mo)), n)
    nose.tools.assert_equal(set(s.memory.addrs_for_name('replace_old')), set())
    nose.tools.assert_equal(set(s.memory.addrs_for_name('replace_new')), set((0x3000, 0x3003)))
    nose.tools.assert_equal(s.se.eval_upto(s.memory.load(0x3001, 2), 10, cast_to=str), ["AB"])

    s.memory.store(0x4000, s.se.If(n == 0, n+10, n+20))

    nose.tools.assert_equal(set(s.memory.addrs_for_name('replace_new')), set((0x3000, 0x3003, 0x4000, 0x4001, 0x4002, 0x4003)))
    s.memory.replace_all(n, c)
    nose.tools.assert_equal(set(s.memory.addrs_for_name('replace_old')), set())
    nose.tools.assert_equal(set(s.memory.addrs_for_name('replace_new')), set())
    nose.tools.assert_equal(set(s.memory.addrs_for_name('replace_cool')), set((0x3000, 0x3003, 0x4000, 0x4001, 0x4002, 0x4003)))
    nose.tools.assert_equal(s.se.eval_upto(s.memory.load(0x3001, 2), 10, cast_to=str), ["AB"])

    z = s.se.BVV(0, 32)
    s.memory.replace_all(c, z)
    nose.tools.assert_equal(set(s.memory.addrs_for_name('replace_old')), set())
    nose.tools.assert_equal(set(s.memory.addrs_for_name('replace_new')), set())
    nose.tools.assert_equal(set(s.memory.addrs_for_name('replace_cool')), set())
    nose.tools.assert_equal(s.se.eval_upto(s.memory.load(0x3001, 2), 10, cast_to=str), ["AB"])
    nose.tools.assert_equal(s.se.eval_upto(s.memory.load(0x3000, 4), 10), [0x00414200])
    nose.tools.assert_equal(s.se.eval_upto(s.memory.load(0x4000, 4), 10), [0x0000000a])

    # symbolic length
    x = s.se.BVV(0x11223344, 32)
    y = s.se.BVV(0xAABBCCDD, 32)
    n = s.se.BVS('size', 32)
    s.memory.store(0x5000, x)
    s.memory.store(0x5000, y, size=n)
    nose.tools.assert_equal(set(s.se.eval_upto(s.memory.load(0x5000, 4), 10)), { 0x11223344, 0xAA223344, 0xAABB3344, 0xAABBCC44, 0xAABBCCDD })

    s1 = s.copy()
    s1.add_constraints(n == 1)
    nose.tools.assert_equal(set(s1.se.eval_upto(s1.memory.load(0x5000, 4), 10)), { 0xAA223344 })

    s4 = s.copy()
    s4.add_constraints(n == 4)
    nose.tools.assert_equal(set(s4.se.eval_upto(s4.memory.load(0x5000, 4), 10)), { 0xAABBCCDD })

    # condition without fallback
    x = s.se.BVV(0x11223344, 32)
    y = s.se.BVV(0xAABBCCDD, 32)
    c = s.se.BVS('condition', 32)
    s.memory.store(0x6000, x)
    s.memory.store(0x6000, y, condition=c==1)
    nose.tools.assert_equal(set(s.se.eval_upto(s.memory.load(0x6000, 4), 10)), { 0x11223344, 0xAABBCCDD })

    s0 = s.copy()
    s0.add_constraints(c == 0)
    nose.tools.assert_equal(set(s0.se.eval_upto(s0.memory.load(0x6000, 4), 10)), { 0x11223344 })

    s1 = s.copy()
    s1.add_constraints(c == 1)
    nose.tools.assert_equal(set(s1.se.eval_upto(s1.memory.load(0x6000, 4), 10)), { 0xAABBCCDD })

    # condition with symbolic size
    x = s.se.BVV(0x11223344, 32)
    y = s.se.BVV(0xAABBCCDD, 32)
    c = s.se.BVS('condition', 32)
    n = s.se.BVS('size', 32)
    s.memory.store(0x8000, x)
    s.memory.store(0x8000, y, condition=c==1, size=n)

    s0 = s.copy()
    s0.add_constraints(c == 0)
    nose.tools.assert_equal(set(s0.se.eval_upto(s0.memory.load(0x8000, 4), 10)), { 0x11223344 })

    s1 = s.copy()
    s1.add_constraints(c == 1)
    nose.tools.assert_equal(set(s1.se.eval_upto(s1.memory.load(0x8000, 4), 10)), { 0x11223344, 0xAA223344, 0xAABB3344, 0xAABBCC44, 0xAABBCCDD })

def test_cased_store():
    initial_memory = { 0: 'A', 1: 'A', 2: 'A', 3: 'A' }
    so = SimState(arch="AMD64", memory_backer=initial_memory)

    # sanity check
    nose.tools.assert_equal(so.se.eval_upto(so.memory.load(0, 4), 2, cast_to=str), ['AAAA'])

    # the values
    values = [
        None,
        so.se.BVV('B'),
        so.se.BVV('CC'),
        so.se.BVV('DDD'),
        so.se.BVV('EEEE')
    ]

    # try the write
    s = so.copy()
    x = s.se.BVS('x', 32)
    s.memory.store_cases(0, values, [ x == i for i in range(len(values)) ])
    for i,v in enumerate(values):
        v = '' if v is None else s.se.eval(v, cast_to=str)
        w = s.se.eval_upto(s.memory.load(0, 4), 2, cast_to=str, extra_constraints=[x==i])
        nose.tools.assert_equal(w, [v.ljust(4, 'A')])

    # and now with a fallback
    y = s.se.BVS('y', 32)
    s.memory.store_cases(0, values, [ y == i for i in range(len(values)) ], fallback=s.se.BVV('XXXX'))
    for i,v in enumerate(values):
        v = '' if v is None else s.se.eval(v, cast_to=str)
        w = s.se.eval_upto(s.memory.load(0, 4), 2, cast_to=str, extra_constraints=[y==i])
        nose.tools.assert_equal(w, [v.ljust(4, 'X')])

    # and now with endness
    y = s.se.BVS('y', 32)
    s.memory.store_cases(0, values, [ y == i for i in range(len(values)) ], fallback=s.se.BVV('XXXX'), endness="Iend_LE")
    for i,v in enumerate(values):
        v = '' if v is None else s.se.eval(v, cast_to=str)
        w = s.se.eval_upto(s.memory.load(0, 4), 2, cast_to=str, extra_constraints=[y==i])
        print w, v.rjust(4, 'X')
        nose.tools.assert_equal(w, [v.rjust(4, 'X')])

    # and write all Nones
    s = so.copy()
    z = s.se.BVS('z', 32)
    s.memory.store_cases(0, [ None, None, None ], [ z == 0, z == 1, z == 2])
    for i in range(len(values)):
        w = s.se.eval_upto(s.memory.load(0, 4), 2, cast_to=str, extra_constraints=[z==i])
        nose.tools.assert_equal(w, ['AAAA'])

    # and all Nones with a fallback
    u = s.se.BVS('w', 32)
    s.memory.store_cases(0, [ None, None, None ], [ u == 0, u == 1, u == 2], fallback=s.se.BVV('WWWW'))
    for i,v in enumerate(values):
        w = s.se.eval_upto(s.memory.load(0, 4), 2, cast_to=str, extra_constraints=[u==i])
        nose.tools.assert_equal(w, ['WWWW'])

    # and all identical values
    s = so.copy()
    #t = s.se.BVS('t', 32)
    s.memory.store_cases(0, [ s.se.BVV('AA'), s.se.BVV('AA'), s.se.BVV('AA') ], [ u == 0, u == 1, u == 2], fallback=s.se.BVV('AA'))
    r = s.memory.load(0, 2)
    nose.tools.assert_equal(r.op, 'BVV')
    nose.tools.assert_equal(s.se.eval_upto(r, 2, cast_to=str), ['AA'])

    # and all identical values, with varying fallback
    s = so.copy()
    #t = s.se.BVS('t', 32)
    s.memory.store_cases(0, [ s.se.BVV('AA'), s.se.BVV('AA'), s.se.BVV('AA') ], [ u == 0, u == 1, u == 2], fallback=s.se.BVV('XX'))
    r = s.memory.load(0, 2)
    nose.tools.assert_equal(sorted(s.se.eval_upto(r, 3, cast_to=str)), ['AA', 'XX'])

    # and some identical values
    s = so.copy()
    #q = s.se.BVS('q', 32)
    values = [ 'AA', 'BB', 'AA' ]
    s.memory.store_cases(0, [ s.se.BVV(v) for v in values ], [ u == i for i in range(len(values))], fallback=s.se.BVV('XX'))
    r = s.memory.load(0, 2)
    for i,v in enumerate(values + ['XX']):
        w = s.se.eval_upto(s.memory.load(0, 2), 2, cast_to=str, extra_constraints=[u==i])
        nose.tools.assert_equal(w, [(values+['XX'])[i]])

def test_abstract_memory():
    initial_memory = {0: 'A', 1: 'B', 2: 'C', 3: 'D'}

    s = SimState(mode='static',
                 arch="AMD64",
                 memory_backer=initial_memory,
                 add_options={o.ABSTRACT_SOLVER, o.ABSTRACT_MEMORY})
    se = s.se

    def to_vs(region, offset):
        return s.se.VS(s.arch.bits, region, 0, offset)

    # Load a single-byte constant from global region
    expr = s.memory.load(to_vs('global', 2), 1)
    nose.tools.assert_equal(s.se.eval(expr), 0x43)
    nose.tools.assert_equal(s.se.max_int(expr), 0x43)
    nose.tools.assert_equal(s.se.min_int(expr), 0x43)

    # Store a single-byte constant to global region
    s.memory.store(to_vs('global', 1), s.se.BVV(ord('D'), 8), 1)
    expr = s.memory.load(to_vs('global', 1), 1)
    nose.tools.assert_equal(s.se.eval(expr), 0x44)

    # Store a single-byte StridedInterval to global region
    si_0 = s.se.BVS('unnamed', 8, 10, 20, 2)
    s.memory.store(to_vs('global', 4), si_0)

    # Load the single-byte StridedInterval from global region
    expr = s.memory.load(to_vs('global', 4), 1)
    nose.tools.assert_equal(s.se.min_int(expr), 10)
    nose.tools.assert_equal(s.se.max_int(expr), 20)
    nose.tools.assert_equal(s.se.eval_upto(expr, 100), [10, 12, 14, 16, 18, 20])

    # Store a two-byte StridedInterval object to global region
    si_1 = s.se.BVS('unnamed', 16, 10, 20, 2)
    s.memory.store(to_vs('global', 5), si_1)

    # Load the two-byte StridedInterval object from global region
    expr = s.memory.load(to_vs('global', 5), 2)
    nose.tools.assert_true(claripy.backends.vsa.identical(expr, si_1))

    # Store a four-byte StridedInterval object to global region
    si_2 = s.se.BVS('unnamed', 32, 8000, 9000, 2)
    s.memory.store(to_vs('global', 7), si_2)

    # Load the four-byte StridedInterval object from global region
    expr = s.memory.load(to_vs('global', 7), 4)
    nose.tools.assert_true(claripy.backends.vsa.identical(expr, s.se.BVS('unnamed', 32, 8000, 9000, 2)))

    # Test default values
    s.options.remove(o.SYMBOLIC_INITIAL_VALUES)
    expr = s.memory.load(to_vs('global', 100), 4)
    nose.tools.assert_true(claripy.backends.vsa.identical(expr, s.se.BVS('unnamed', 32, 0, 0, 0)))

    # Test default values (symbolic)
    s.options.add(o.SYMBOLIC_INITIAL_VALUES)
    expr = s.memory.load(to_vs('global', 104), 4)
    nose.tools.assert_true(claripy.backends.vsa.identical(expr, s.se.BVS('unnamed', 32, 0, 0xffffffff, 1)))
    nose.tools.assert_true(claripy.backends.vsa.identical(expr, s.se.BVS('unnamed', 32, -0x80000000, 0x7fffffff, 1)))

    #
    # Merging
    #

    # Merging two one-byte values
    s.memory.store(to_vs('function_merge', 0), s.se.BVS('unnamed', 8, 0x10, 0x10, 0))
    a = s.copy()
    a.memory.store(to_vs('function_merge', 0), s.se.BVS('unnamed', 8, 0x20, 0x20, 0))

    b = s.merge(a)[0]
    expr = b.memory.load(to_vs('function_merge', 0), 1)
    nose.tools.assert_true(claripy.backends.vsa.identical(expr, s.se.BVS('unnamed', 8, 0x10, 0x20, 0x10)))

    #  |  MO(value_0)  |
    #  |  MO(value_1)  |
    # 0x20          0x24
    # Merge one byte in value_0/1 means merging the entire MemoryObject
    a = s.copy()
    a.memory.store(to_vs('function_merge', 0x20), se.SI(bits=32, stride=0, lower_bound=0x100000, upper_bound=0x100000))
    b = s.copy()
    b.memory.store(to_vs('function_merge', 0x20), se.SI(bits=32, stride=0, lower_bound=0x100001, upper_bound=0x100001))
    c = a.merge(b)[0]
    expr = c.memory.load(to_vs('function_merge', 0x20), 4)
    nose.tools.assert_true(claripy.backends.vsa.identical(expr, se.SI(bits=32, stride=1, lower_bound=0x100000, upper_bound=0x100001)))
    c_mem = c.memory.regions['function_merge'].memory.mem
    object_set = set([ c_mem[0x20], c_mem[0x20], c_mem[0x22], c_mem[0x23]])
    nose.tools.assert_equal(len(object_set), 1)

    a = s.copy()
    a.memory.store(to_vs('function_merge', 0x20), se.SI(bits=32, stride=0x100000, lower_bound=0x100000, upper_bound=0x200000))
    b = s.copy()
    b.memory.store(to_vs('function_merge', 0x20), se.SI(bits=32, stride=0, lower_bound=0x300000, upper_bound=0x300000))
    c = a.merge(b)[0]
    expr = c.memory.load(to_vs('function_merge', 0x20), 4)
    nose.tools.assert_true(claripy.backends.vsa.identical(expr, se.SI(bits=32, stride=0x100000, lower_bound=0x100000, upper_bound=0x300000)))
    object_set = set([c_mem[0x20], c_mem[0x20], c_mem[0x22], c_mem[0x23]])
    nose.tools.assert_equal(len(object_set), 1)

    #
    # Widening
    #

    a = s.se.SI(bits=32, stride=1, lower_bound=1, upper_bound=2)
    b = s.se.SI(bits=32, stride=1, lower_bound=1, upper_bound=3)
    a = a.reversed
    b = b.reversed
    #widened = a.widen(b)
    # TODO: Added a proper test case
    #print widened.reversed

    # We are done!
    # Restore the old claripy standalone object
    # claripy.set_claripy(old_claripy_standalone)

def test_abstract_memory_find():
    initial_memory = { 1: 'A', 2: 'B', 3: '\x00' }

    s = SimState(mode='static',
                 arch="AMD64",
                 memory_backer=initial_memory,
                 add_options={o.ABSTRACT_SOLVER, o.ABSTRACT_MEMORY})

    se = s.se
    BVV = se.BVV
    VS = se.VS
    SI = se.SI

    s.memory.store(4, se.TSI(bits=64))

    def to_vs(region, offset):
        return VS(s.arch.bits, region, 0, offset)

    r, _, _ = s.memory.find(to_vs('global', 1), BVV(ord('A'), 8))

    r_model = claripy.backends.vsa.convert(r)
    s_expected = claripy.backends.vsa.convert(SI(bits=64, to_conv=1))
    nose.tools.assert_true(isinstance(r_model, claripy.vsa.ValueSet))
    nose.tools.assert_equal(r_model.regions.keys(), [ 'global' ])
    nose.tools.assert_true(claripy.backends.vsa.identical(r_model.regions['global'], s_expected))

    r, _, _ = s.memory.find(to_vs('global', 1), BVV(ord('B'), 8))
    r_model = claripy.backends.vsa.convert(r)
    s_expected = claripy.backends.vsa.convert(SI(bits=64, to_conv=2))
    nose.tools.assert_true(isinstance(r_model, claripy.vsa.ValueSet))
    nose.tools.assert_equal(r_model.regions.keys(), ['global'])
    nose.tools.assert_true(claripy.backends.vsa.identical(r_model.regions['global'], s_expected))

    r, _, _ = s.memory.find(to_vs('global', 1), BVV(0, 8))
    r_model = claripy.backends.vsa.convert(r)
    s_expected = claripy.backends.vsa.convert(SI(bits=64, to_conv=3))
    nose.tools.assert_true(isinstance(r_model, claripy.vsa.ValueSet))
    nose.tools.assert_equal(r_model.regions.keys(), ['global'])
    nose.tools.assert_true(claripy.backends.vsa.identical(r_model.regions['global'], s_expected))

    # Find in StridedIntervals
    r, _, _ = s.memory.find(to_vs('global', 4), BVV(0, 8), max_search=8)
    r_model = claripy.backends.vsa.convert(r)
    s_expected = claripy.backends.vsa.convert(SI(bits=64, stride=1, lower_bound=4, upper_bound=11))
    nose.tools.assert_true(isinstance(r_model, claripy.vsa.ValueSet))
    nose.tools.assert_equal(r_model.regions.keys(), ['global'])
    nose.tools.assert_true(claripy.backends.vsa.identical(r_model.regions['global'], s_expected))

#@nose.tools.timed(10)
def test_registers():
    s = SimState(arch='AMD64')
    expr = s.registers.load('rax')
    nose.tools.assert_true(s.se.symbolic(expr))

    s.registers.store('rax', 0x31)
    expr = s.registers.load('rax')
    nose.tools.assert_false(s.se.symbolic(expr))
    nose.tools.assert_equals(s.se.eval(expr), 0x00000031)

def test_fullpage_write():
    s = SimState(arch='AMD64')
    a = s.se.BVV('A'*0x2000)
    s.memory.store(0, a)
    #assert len(s.memory.mem._pages) == 2
    #assert len(s.memory.mem._pages[0].keys()) == 0
    #assert len(s.memory.mem._pages[1].keys()) == 0
    assert s.memory.load(0, 0x2000) is a
    assert a.variables != s.memory.load(0x2000, 1).variables

    s = SimState(arch='AMD64')
    a = s.se.BVV('A'*2)
    s.memory.store(0x1000, a)
    s.memory.store(0x2000, a)
    assert a.variables == s.memory.load(0x2000, 1).variables
    assert a.variables == s.memory.load(0x2001, 1).variables
    assert a.variables != s.memory.load(0x2002, 1).variables

    s = SimState(arch='AMD64')
    x = s.se.BVV('X')
    a = s.se.BVV('A'*0x1000)
    s.memory.store(1, x)
    s2 = s.copy()
    s2.memory.store(0, a)
    assert len(s.memory.changed_bytes(s2.memory)) == 0x1000

    s = SimState(arch='AMD64')
    s.memory._maximum_symbolic_size = 0x2000000
    a = s.se.BVS('A', 0x1000000*8)
    s.memory.store(0, a)
    b = s.memory.load(0, 0x1000000)
    assert b is a

def test_symbolic_write():
    s = SimState(arch='AMD64', add_options={o.SYMBOLIC_WRITE_ADDRESSES})
    x = s.se.BVS('x', 64)
    y = s.se.BVS('y', 64)
    a = s.se.BVV('A'*0x10)
    b = s.se.BVV('B')
    c = s.se.BVV('C')
    d = s.se.BVV('D')

    s.memory.store(0x10, a)
    s.add_constraints(x >= 0x10, x < 0x20)
    s.memory.store(x, b)

    for i in range(0x10, 0x20):
        assert len(s.se.eval_upto(s.memory.load(i, 1), 10)) == 2

    s.memory.store(x, c)
    for i in range(0x10, 0x20):
        assert len(s.se.eval_upto(s.memory.load(i, 1), 10)) == 2

    s2 = s.copy()
    s2.add_constraints(y >= 0x10, y < 0x20)
    s2.memory.store(y, d)
    for i in range(0x10, 0x20):
        assert len(s2.se.eval_upto(s2.memory.load(i, 1), 10)) == 3

def test_concrete_memset():

    def _individual_test(state, base, val, size):
        # time it
        start = time.time()
        memset = SIM_PROCEDURES['libc']['memset']().execute(
            state, arguments=[base, state.se.BVV(val, 8), size]
        )
        elapsed = time.time() - start

        # should be done within 1 second
        nose.tools.assert_less_equal(elapsed, 5)
        # the result should be good
        byt_0 = memset.state.memory.load(base, 1)
        nose.tools.assert_equal(s.se.eval_upto(byt_0, 10), [val])
        byt_1 = memset.state.memory.load(base+1, 1)
        nose.tools.assert_equal(s.se.eval_upto(byt_1, 10), [val])
        byt_2 = memset.state.memory.load(base+size-1, 1)
        nose.tools.assert_equal(s.se.eval_upto(byt_2, 10), [val])

    BASE = 0x800000
    SIZE = 0x200000

    # Writes many zeros
    VAL = 0
    s = SimState(arch='AMD64')
    _individual_test(s, BASE, VAL, SIZE)

    # Writes many ones
    VAL = 1
    s = SimState(arch='AMD64')
    _individual_test(s, BASE, VAL, SIZE)

def test_false_condition():
    s = SimState(arch='AMD64')

    asdf = s.se.BVV('asdf')
    fdsa = s.se.BVV('fdsa')
    s.memory.store(0x1000, asdf)
    s.memory.store(0x1000, fdsa, condition=s.se.false)
    s.memory.store(0, fdsa, condition=s.se.false)

    assert s.memory.load(0x1000, 4) is asdf
    assert 0 not in s.memory.mem._pages

def test_paged_memory_membacker_equal_size():
    membacker = {0: claripy.BVV(0, 8), 1: claripy.BVV(1, 8), 2: claripy.BVV(2, 8)}

    simmem = SimPagedMemory(memory_backer=membacker, page_size=len(membacker))
    simmem[0] #pylint:disable=pointless-statement

def test_load_bytes():
    s = SimState(arch='AMD64')
    asdf = s.se.BVS('asdf', 0x1000*8)
    s.memory.store(0x4000, asdf)
    items = s.memory.mem.load_objects(0x4000, 0x1000)
    assert len(items) == 1

    fdsa = s.se.BVV('fdsa')
    s.memory.store(0x4004, fdsa)
    items = s.memory.mem.load_objects(0x4000, 0x1000)
    assert len(items) == 3

    items = s.memory.mem.load_objects(0x8000, 0x2000)
    assert len(items) == 0

def test_fast_memory():
    s = SimState(arch='AMD64', add_options={o.FAST_REGISTERS, o.FAST_MEMORY})

    s.regs.rax = 0x4142434445464748
    s.regs.rbx = 0x5555555544444444
    assert (s.regs.rax == 0x4142434445464748).is_true()
    assert (s.regs.rbx == 0x5555555544444444).is_true()

    _concrete_memory_tests(s)

def test_crosspage_read():
    state = SimState(arch='ARM')
    state.regs.sp = 0x7fff0008
    state.stack_push(0x44556677)
    state.stack_push(0x1)
    state.stack_push(0x2)
    state.stack_push(0x3)
    state.stack_push(0x4)
    state.stack_push(0x99887766)
    state.stack_push(0x5)
    state.stack_push(0x105c8)
    state.stack_push(0x11223344)
    state.stack_push(0x10564)

    r = state.memory.load(state.regs.sp, 40)
    assert "77665544" in state.solver.eval(r, cast_to=str).encode('hex')
    #assert s.solver.eval(r, 2) == ( 0xffeeddccbbaa998877665544, )

if __name__ == '__main__':
    test_crosspage_read()
    test_fast_memory()
    test_load_bytes()
    test_false_condition()
    test_symbolic_write()
    test_fullpage_write()
    test_memory()
    test_copy()
    test_cased_store()
    test_abstract_memory()
    test_abstract_memory_find()
    test_registers()
    test_concrete_memset()
    test_paged_memory_membacker_equal_size()
