#!/usr/bin/env python

import nose
import logging
l = logging.getLogger("simuvex.test")

import random

try:
    # pylint: disable=W0611
    import standard_logging
    import angr_debug
except ImportError:
    pass

import simuvex

#from simuvex import SimMemory
from simuvex import SimState
from simuvex import s_ccall, SimProcedures
import pyvex
#import vexecutor

strstr = SimProcedures['libc.so.6']['strstr']
strtok_r = SimProcedures['libc.so.6']['strtok_r']
strcmp = SimProcedures['libc.so.6']['strcmp']
strchr = SimProcedures['libc.so.6']['strchr']
strncmp = SimProcedures['libc.so.6']['strncmp']
strlen = SimProcedures['libc.so.6']['strlen']
strncpy = SimProcedures['libc.so.6']['strncpy']
strcpy = SimProcedures['libc.so.6']['strcpy']
sprintf = SimProcedures['libc.so.6']['sprintf']
memset = SimProcedures['libc.so.6']['memset']
memcpy = SimProcedures['libc.so.6']['memcpy']
memcmp = SimProcedures['libc.so.6']['memcmp']

## pylint: disable=R0904
#@nose.tools.timed(10)
def test_memory():
    initial_memory = { 0: 'A', 1: 'A', 2: 'A', 3: 'A', 10: 'B' }
    s = SimState(arch="AMD64", memory_backer=initial_memory)

    # Store a 4-byte variable to memory directly...
    s.memory.store(100, s.se.BitVecVal(0x1337, 32))
    # ... then load it
    expr = s.memory.load(100, 4)[0]
    nose.tools.assert_equal(expr._model, s.se.BitVecVal(0x1337, 32)._model)
    expr = s.memory.load(100, 2)[0]
    nose.tools.assert_equal(expr._model, s.se.BitVecVal(0, 16)._model)
    expr = s.memory.load(102, 2)[0]
    nose.tools.assert_equal(expr._model, s.se.BitVecVal(0x1337, 16)._model)

    # concrete address and partially symbolic result
    expr = s.memory.load(2, 4)[0]
    nose.tools.assert_true(s.se.symbolic(expr))
    nose.tools.assert_false(s.se.unique(expr))
    nose.tools.assert_greater_equal(s.se.any_int(expr), 0x41410000)
    nose.tools.assert_less_equal(s.se.any_int(expr), 0x41420000)
    nose.tools.assert_equal(s.se.min_int(expr), 0x41410000)
    nose.tools.assert_equal(s.se.max_int(expr), 0x4141ffff)

    # concrete address and concrete result
    expr = s.memory.load(0, 4)[0] # Returns: a z3 BitVec representing 0x41414141
    nose.tools.assert_false(s.se.symbolic(expr))
    nose.tools.assert_equal(s.se.any_int(expr), 0x41414141)

    # symbolicize
    v = s.memory.make_symbolic(0, 4, "asdf")
    nose.tools.assert_equal(v.size(), 32)
    nose.tools.assert_true(s.se.unique(v))
    nose.tools.assert_equal(s.se.any_int(v), 0x41414141)

    expr = s.memory.load(0, 4)[0] # Returns: a z3 BitVec representing 0x41414141
    nose.tools.assert_true(s.se.symbolic(expr))
    nose.tools.assert_equal(s.se.any_int(expr), 0x41414141)
    nose.tools.assert_true(s.se.unique(expr))

    c = s.BV('condition', 8)
    expr, constraints = s.memory.load(10, 1, condition=c==1, fallback=s.BVV('X'))
    s.add_constraints(*constraints)
    nose.tools.assert_equal(s.se.any_n_str(expr, 10, extra_constraints=[c==1]), [ 'B' ])
    nose.tools.assert_equal(s.se.any_n_str(expr, 10, extra_constraints=[c!=1]), [ 'X' ])

def test_abstractmemory():
    initial_memory_global = {0: 'A', 1: 'B', 2: 'C', 3: 'D'}
    initial_memory = {'global': initial_memory_global}

    s = SimState(mode='static', arch="AMD64", memory_backer=initial_memory, options=[simuvex.o.ABSTRACT_MEMORY], add_options={simuvex.o.ABSTRACT_SOLVER})

    # Load a single-byte constant from global region
    expr = s.memory.load('global', 2, 1)[0]
    nose.tools.assert_equal(s.se.any_int(expr), 0x43)
    nose.tools.assert_equal(s.se.max_int(expr), 0x43)
    nose.tools.assert_equal(s.se.min_int(expr), 0x43)

    # Store a single-byte constant to global region
    s.memory.store('global', 1, s.se.BitVecVal(ord('D'), 8))
    expr = s.memory.load('global', 1, 1)[0]
    nose.tools.assert_equal(s.se.any_int(expr), 0x44)

    # Store a single-byte StridedInterval to global region
    si_0 = s.se.StridedInterval(bits=8, stride=2, lower_bound=10, upper_bound=20)
    s.memory.store('global', 1, si_0)

    # Load the single-byte StridedInterval from global region
    expr = s.memory.load('global', 1, 1)[0]
    nose.tools.assert_equal(s.se.min_int(expr), 10)
    nose.tools.assert_equal(s.se.max_int(expr), 20)
    nose.tools.assert_equal(s.se.any_n_int(expr, 100), [10, 12, 14, 16, 18, 20])

    # Store a two-byte StridedInterval object to global region
    si_1 = s.se.StridedInterval(bits=16, stride=2, lower_bound=10, upper_bound=20)
    s.memory.store('global', 1, si_1)

    # Load the two-byte StridedInterval object from global region
    expr = s.memory.load('global', 1, 2)[0]
    nose.tools.assert_equal(expr._model, si_1)

    # Store a four-byte StridedInterval object to global region
    si_2 = s.se.StridedInterval(bits=32, stride=2, lower_bound=8000, upper_bound=9000)
    s.memory.store('global', 1, si_2)

    # Load the four-byte StridedInterval object from global region
    expr = s.memory.load('global', 1, 4)[0]
    nose.tools.assert_equal(expr._model, s.se.StridedInterval(bits=32, stride=1, lower_bound=0x1f00, upper_bound=0x23ff))

#@nose.tools.timed(10)
def test_registers():
    s = simuvex.SimAMD64().make_state()
    expr = s.reg_expr('rax')
    nose.tools.assert_true(s.se.symbolic(expr))

    s.store_reg('rax', 0x31)
    expr = s.reg_expr('rax')
    nose.tools.assert_false(s.se.symbolic(expr))
    nose.tools.assert_equals(s.se.any_int(expr), 0x00000031)

def test_state():
    s = simuvex.SimAMD64().make_state()
    nose.tools.assert_equals(s.se.any_int(s.reg_expr('sp')), 0x7ffffffffff0000)

    s.stack_push(s.BVV("ABCDEFGH"))
    nose.tools.assert_equals(s.se.any_int(s.reg_expr('sp')), 0x7fffffffffefff8)
    s.stack_push(s.BVV("IJKLMNOP"))
    nose.tools.assert_equals(s.se.any_int(s.reg_expr('sp')), 0x7fffffffffefff0)

    a = s.stack_pop()
    nose.tools.assert_equals(s.se.any_int(s.reg_expr('sp')), 0x7fffffffffefff8)
    nose.tools.assert_equals(s.se.any_str(a), "IJKLMNOP")

    b = s.stack_pop()
    nose.tools.assert_equals(s.se.any_int(s.reg_expr('sp')), 0x7ffffffffff0000)
    nose.tools.assert_equals(s.se.any_str(b), "ABCDEFGH")

#def test_symvalue():
#    # concrete symvalue
#    zero = SimValue(se.BitVecVal(0, 64))
#    nose.tools.assert_false(zero.is_symbolic())
#    nose.tools.assert_equal(zero.any_int(), 0)
#    nose.tools.assert_raises(ConcretizingException, zero.exactly_n, 2)
#
#    # symbolic symvalue
#    x = se.BitVec('x', 64)
#    sym = SimValue(x, constraints = [ x > 100, x < 200 ])
#    nose.tools.assert_true(sym.is_symbolic())
#    nose.tools.assert_equal(sym.min_int(), 101)
#    nose.tools.assert_equal(sym.max_int(), 199)
#    nose.tools.assert_items_equal(sym.any_n_int(99), range(101, 200))
#    nose.tools.assert_raises(ConcretizingException, zero.exactly_n, 102)

#@nose.tools.timed(10)
def test_state_merge():
    a = SimState(mode='symbolic')
    a.store_mem(1, a.se.BitVecVal(42, 8))

    b = a.copy()
    c = b.copy()
    a.store_mem(2, a.mem_expr(1, 1)+1)
    b.store_mem(2, b.mem_expr(1, 1)*2)
    c.store_mem(2, c.mem_expr(1, 1)/2)

    # make sure the byte at 1 is right
    nose.tools.assert_equal(a.se.any_int(a.mem_expr(1, 1)), 42)
    nose.tools.assert_equal(b.se.any_int(b.mem_expr(1, 1)), 42)
    nose.tools.assert_equal(c.se.any_int(c.mem_expr(1, 1)), 42)

    # make sure the byte at 2 is right
    nose.tools.assert_equal(a.se.any_int(a.mem_expr(2, 1)), 43)
    nose.tools.assert_equal(b.se.any_int(b.mem_expr(2, 1)), 84)
    nose.tools.assert_equal(c.se.any_int(c.mem_expr(2, 1)), 21)

    # the byte at 2 should be unique for all before the merge
    nose.tools.assert_true(a.se.unique(a.mem_expr(2, 1)))
    nose.tools.assert_true(b.se.unique(b.mem_expr(2, 1)))
    nose.tools.assert_true(c.se.unique(c.mem_expr(2, 1)))

    merge_val = a.merge(b, c)

    # the byte at 2 should now *not* be unique for a
    nose.tools.assert_false(a.se.unique(a.mem_expr(2, 1)))
    nose.tools.assert_true(b.se.unique(b.mem_expr(2, 1)))
    nose.tools.assert_true(c.se.unique(c.mem_expr(2, 1)))

    # the byte at 2 should have the three values
    nose.tools.assert_items_equal(a.se.any_n_int(a.mem_expr(2, 1), 10), (43, 84, 21))

    # we should be able to select them by adding constraints
    a_a = a.copy()
    a_a.add_constraints(merge_val == 0)
    nose.tools.assert_true(a_a.se.unique(a_a.mem_expr(2, 1)))
    nose.tools.assert_equal(a_a.se.any_int(a_a.mem_expr(2, 1)), 43)

    a_b = a.copy()
    a_b.add_constraints(merge_val == 1)
    nose.tools.assert_true(a_b.se.unique(a_b.mem_expr(2, 1)))
    nose.tools.assert_equal(a_b.se.any_int(a_b.mem_expr(2, 1)), 84)

    a_c = a.copy()
    a_c.add_constraints(merge_val == 2)
    nose.tools.assert_true(a_c.se.unique(a_c.mem_expr(2, 1)))
    nose.tools.assert_equal(a_c.se.any_int(a_c.mem_expr(2, 1)), 21)

#@nose.tools.timed(10)
def test_ccall():
    s = SimState(arch="AMD64")

    l.debug("Testing amd64_actions_ADD")
    l.debug("(8-bit) 1 + 1...")
    arg_l = s.se.BitVecVal(1, 8)
    arg_r = s.se.BitVecVal(1, 8)
    ret = s_ccall.pc_actions_ADD(s, 8, arg_l, arg_r, 0)
    nose.tools.assert_equal(ret, 0)

    l.debug("(32-bit) (-1) + (-2)...")
    arg_l = s.se.BitVecVal(-1, 32)
    arg_r = s.se.BitVecVal(-1, 32)
    ret = s_ccall.pc_actions_ADD(s, 32, arg_l, arg_r, 0)
    nose.tools.assert_equal(ret, 0b101010)

    l.debug("Testing pc_actions_SUB")
    l.debug("(8-bit) 1 - 1...",)
    arg_l = s.se.BitVecVal(1, 8)
    arg_r = s.se.BitVecVal(1, 8)
    ret = s_ccall.pc_actions_SUB(s, 8, arg_l, arg_r, 0)
    nose.tools.assert_equal(ret, 0b010100)

    l.debug("(32-bit) (-1) - (-2)...")
    arg_l = s.se.BitVecVal(-1, 32)
    arg_r = s.se.BitVecVal(-1, 32)
    ret = s_ccall.pc_actions_SUB(s, 32, arg_l, arg_r, 0)
    nose.tools.assert_equal(ret, 0)

#@nose.tools.timed(10)
def test_inline_strlen():
    s = SimState(arch="AMD64", mode="symbolic")

    l.info("fully concrete string")
    a_str = s.se.BitVecVal(0x41414100, 32)
    a_addr = s.se.BitVecVal(0x10, 64)
    s.store_mem(a_addr, a_str, endness="Iend_BE")
    a_len = SimProcedures['libc.so.6']['strlen'](s, inline=True, arguments=[a_addr]).ret_expr
    nose.tools.assert_true(s.se.unique(a_len))
    nose.tools.assert_equal(s.se.any_int(a_len), 3)

    l.info("concrete-terminated string")
    b_str = s.se.Concat(s.BV("mystring", 24), s.se.BitVecVal(0, 8))
    b_addr = s.se.BitVecVal(0x20, 64)
    s.store_mem(b_addr, b_str, endness="Iend_BE")
    b_len = SimProcedures['libc.so.6']['strlen'](s, inline=True, arguments=[b_addr]).ret_expr
    nose.tools.assert_equal(s.se.max_int(b_len), 3)
    nose.tools.assert_items_equal(s.se.any_n_int(b_len, 10), (0,1,2,3))

    l.info("fully unconstrained")
    u_addr = s.se.BitVecVal(0x50, 64)
    u_len_sp = SimProcedures['libc.so.6']['strlen'](s, inline=True, arguments=[u_addr])
    u_len = u_len_sp.ret_expr
    nose.tools.assert_equal(len(s.se.any_n_int(u_len, 100)), s['libc'].buf_symbolic_bytes)
    nose.tools.assert_equal(s.se.max_int(u_len), s['libc'].buf_symbolic_bytes-1)

    #print u_len_sp.se.maximum_null

    #s.add_constraints(u_len < 16)

    nose.tools.assert_equal(s.se.any_n_int(s.mem_expr(0x50 + u_len, 1), 300), [0])

    #
    # This tests if a strlen can influence a symbolic str.
    #
    l.info("Trying to influence length.")
    s = SimState(arch="AMD64", mode="symbolic")
    str_c = s.BV("some_string", 8*16)
    c_addr = s.se.BitVecVal(0x10, 64)
    s.store_mem(c_addr, str_c, endness='Iend_BE')
    c_len = SimProcedures['libc.so.6']['strlen'](s, inline=True, arguments=[c_addr]).ret_expr
    nose.tools.assert_equal(len(s.se.any_n_int(c_len, 100)), s['libc'].buf_symbolic_bytes)
    nose.tools.assert_equal(s.se.max_int(c_len), s['libc'].buf_symbolic_bytes-1)

    one_s = s.copy()
    one_s.add_constraints(c_len == 1)
    nose.tools.assert_equal(one_s.se.any_str(str_c).index('\x00'), 1)
    str_test = one_s.mem_expr(c_addr, 2, endness='Iend_BE')
    nose.tools.assert_equal(len(one_s.se.any_n_str(str_test, 300)), 255)

    for i in range(16):
        test_s = s.copy()
        test_s.add_constraints(c_len == i)
        str_test = test_s.mem_expr(c_addr, i + 1, endness='Iend_BE')
        nose.tools.assert_equal(test_s.se.any_str(str_test).index('\x00'), i)
        for j in range(i):
            nose.tools.assert_false(test_s.se.unique(test_s.mem_expr(c_addr+j, 1)))

#@nose.tools.timed(10)
def test_inline_strcmp():
    s = SimState(arch="AMD64", mode="symbolic")
    str_a = s.se.BitVecVal(0x41414100, 32)
    str_b = s.BV("mystring", 32)

    a_addr = s.se.BitVecVal(0x10, 64)
    b_addr = s.se.BitVecVal(0xb0, 64)

    s.store_mem(a_addr, str_a, endness="Iend_BE")
    s.store_mem(b_addr, str_b, endness="Iend_BE")

    s_cmp = s.copy()
    cmpres = SimProcedures['libc.so.6']['strcmp'](s_cmp, inline=True, arguments=[a_addr, b_addr]).ret_expr
    s_match = s_cmp.copy()
    s_nomatch = s_cmp.copy()
    s_match.add_constraints(cmpres == 0)
    s_nomatch.add_constraints(cmpres != 0)

    nose.tools.assert_true(s_match.se.unique(str_b))
    nose.tools.assert_false(s_nomatch.se.unique(str_b))
    nose.tools.assert_equal(s_match.se.any_str(str_b), "AAA\x00")

    s_ncmp = s.copy()
    ncmpres = SimProcedures['libc.so.6']['strncmp'](s_ncmp, inline=True, arguments=[a_addr, b_addr, s.se.BitVecVal(2, s.arch.bits)]).ret_expr
    s_match = s_ncmp.copy()
    s_nomatch = s_ncmp.copy()
    s_match.add_constraints(ncmpres == 0)
    s_nomatch.add_constraints(ncmpres != 0)

    nose.tools.assert_false(s_match.se.unique(str_b))
    nose.tools.assert_true(s_match.se.unique(s_match.mem_expr(b_addr, 2)))
    nose.tools.assert_equal(len(s_match.se.any_n_int(s_match.mem_expr(b_addr, 3), 300)), 256)
    nose.tools.assert_false(s_nomatch.se.unique(str_b))

    l.info("concrete a, symbolic b")
    s = SimState(arch="AMD64", mode="symbolic")
    str_a = s.se.BitVecVal(0x41424300, 32)
    str_b = s.BV("mystring", 32)
    a_addr = s.se.BitVecVal(0x10, 64)
    b_addr = s.se.BitVecVal(0xb0, 64)
    s.store_mem(a_addr, str_a, endness="Iend_BE")
    s.store_mem(b_addr, str_b, endness="Iend_BE")

    s_cmp = s.copy()
    cmpres = strncmp(s_cmp, inline=True, arguments=[a_addr, b_addr, s.se.BitVecVal(2, s_cmp.arch.bits)]).ret_expr
    s_match = s_cmp.copy()
    s_nomatch = s_cmp.copy()
    s_match.add_constraints(cmpres == 0)
    s_nomatch.add_constraints(cmpres != 0)

    nose.tools.assert_true(s_match.se.solution(str_b, 0x41420000))
    nose.tools.assert_true(s_match.se.solution(str_b, 0x41421234))
    nose.tools.assert_true(s_match.se.solution(str_b, 0x41424300))
    nose.tools.assert_false(s_nomatch.se.solution(str_b, 0x41420000))
    nose.tools.assert_false(s_nomatch.se.solution(str_b, 0x41421234))
    nose.tools.assert_false(s_nomatch.se.solution(str_b, 0x41424300))

    l.info("symbolic a, symbolic b")
    s = SimState(arch="AMD64", mode="symbolic")
    a_addr = s.se.BitVecVal(0x10, 64)
    b_addr = s.se.BitVecVal(0xb0, 64)

    s_cmp = s.copy()
    cmpres = strcmp(s_cmp, inline=True, arguments=[a_addr, b_addr]).ret_expr
    s_match = s_cmp.copy()
    s_nomatch = s_cmp.copy()
    s_match.add_constraints(cmpres == 0)
    s_nomatch.add_constraints(cmpres != 0)

    m_res = strcmp(s_match, inline=True, arguments=[a_addr, b_addr]).ret_expr
    s_match.add_constraints(m_res != 0)
    nm_res = strcmp(s_nomatch, inline=True, arguments=[a_addr, b_addr]).ret_expr
    s_nomatch.add_constraints(nm_res == 0)

    nose.tools.assert_false(s_match.satisfiable())
    nose.tools.assert_false(s_match.satisfiable())

#@nose.tools.timed(10)
def test_inline_strncmp():
    l.info("symbolic left, symbolic right, symbolic len")
    s = SimState(arch="AMD64", mode="symbolic")
    left = s.BV("left", 32)
    left_addr = s.se.BitVecVal(0x1000, 64)
    right = s.BV("right", 32)
    right_addr = s.se.BitVecVal(0x2000, 64)
    maxlen = s.BV("len", 64)

    s.store_mem(left_addr, left)
    s.store_mem(right_addr, right)

    s.add_constraints(strlen(s, inline=True, arguments=[left_addr]).ret_expr == 3)
    s.add_constraints(strlen(s, inline=True, arguments=[right_addr]).ret_expr == 0)

    s.add_constraints(maxlen != 0)
    c = strncmp(s, inline=True, arguments=[left_addr, right_addr, maxlen]).ret_expr

    s_match = s.copy()
    s_match.add_constraints(c == 0)
    nose.tools.assert_false(s_match.satisfiable())
    #nose.tools.assert_equals(s_match.se.min_int(maxlen), 3)

    s_nomatch = s.copy()
    s_nomatch.add_constraints(c != 0)
    nose.tools.assert_true(s_nomatch.satisfiable())
    #nose.tools.assert_equals(s_nomatch.se.max_int(maxlen), 2)

    l.info("zero-length")
    s = SimState(arch="AMD64", mode="symbolic")
    left = s.BV("left", 32)
    left_addr = s.se.BitVecVal(0x1000, 64)
    right = s.BV("right", 32)
    right_addr = s.se.BitVecVal(0x2000, 64)
    maxlen = s.BV("len", 64)
    left_len = strlen(s, inline=True, arguments=[left_addr]).ret_expr
    right_len = strlen(s, inline=True, arguments=[right_addr]).ret_expr
    c = strncmp(s, inline=True, arguments=[left_addr, right_addr, maxlen]).ret_expr

    s.add_constraints(right_len == 0)
    s.add_constraints(left_len == 0)
    #s.add_constraints(c == 0)
    s.add_constraints(maxlen == 0)
    nose.tools.assert_true(s.satisfiable())

#@nose.tools.timed(10)
def test_inline_strstr():
    l.info("concrete haystack and needle")
    s = SimState(arch="AMD64", mode="symbolic")
    str_haystack = s.se.BitVecVal(0x41424300, 32)
    str_needle = s.se.BitVecVal(0x42430000, 32)
    addr_haystack = s.se.BitVecVal(0x10, 64)
    addr_needle = s.se.BitVecVal(0xb0, 64)
    s.store_mem(addr_haystack, str_haystack, endness="Iend_BE")
    s.store_mem(addr_needle, str_needle, endness="Iend_BE")

    ss_res = strstr(s, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
    nose.tools.assert_true(s.se.unique(ss_res))
    nose.tools.assert_equal(s.se.any_int(ss_res), 0x11)

    l.info("concrete haystack, symbolic needle")
    s = SimState(arch="AMD64", mode="symbolic")
    str_haystack = s.se.BitVecVal(0x41424300, 32)
    str_needle = s.BV("wtf", 32)
    addr_haystack = s.se.BitVecVal(0x10, 64)
    addr_needle = s.se.BitVecVal(0xb0, 64)
    s.store_mem(addr_haystack, str_haystack, endness="Iend_BE")
    s.store_mem(addr_needle, str_needle, endness="Iend_BE")

    ss_res = strstr(s, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
    nose.tools.assert_false(s.se.unique(ss_res))
    nose.tools.assert_equal(len(s.se.any_n_int(ss_res, 10)), 4)

    s_match = s.copy()
    s_nomatch = s.copy()
    s_match.add_constraints(ss_res != 0)
    s_nomatch.add_constraints(ss_res == 0)

    match_needle = str_needle[31:16]
    nose.tools.assert_equal(len(s_match.se.any_n_int(match_needle, 300)), 259)
    nose.tools.assert_equal(len(s_match.se.any_n_int(str_needle, 10)), 10)

    l.info("symbolic haystack, symbolic needle")
    s = SimState(arch="AMD64", mode="symbolic")
    s['libc'].buf_symbolic_bytes = 5
    addr_haystack = s.se.BitVecVal(0x10, 64)
    addr_needle = s.se.BitVecVal(0xb0, 64)
    len_needle = strlen(s, inline=True, arguments=[addr_needle])

    ss_res = strstr(s, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
    nose.tools.assert_false(s.se.unique(ss_res))
    nose.tools.assert_equal(len(s.se.any_n_int(ss_res, 100)), s['libc'].buf_symbolic_bytes)

    s_match = s.copy()
    s_nomatch = s.copy()
    s_match.add_constraints(ss_res != 0)
    s_nomatch.add_constraints(ss_res == 0)

    match_cmp = strncmp(s_match, inline=True, arguments=[ss_res, addr_needle, len_needle.ret_expr]).ret_expr
    nose.tools.assert_items_equal(s_match.se.any_n_int(match_cmp, 10), [0])

    r_mm = strstr(s_match, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
    s_match.add_constraints(r_mm == 0)
    nose.tools.assert_false(s_match.satisfiable())

    nose.tools.assert_true(s_nomatch.satisfiable())
    s_nss = s_nomatch.copy()
    nomatch_ss = strstr(s_nss, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
    s_nss.add_constraints(nomatch_ss != 0)
    nose.tools.assert_false(s_nss.satisfiable())

#@nose.tools.timed(10)
def test_strstr_inconsistency(n=2):
    l.info("symbolic haystack, symbolic needle")
    s = SimState(arch="AMD64", mode="symbolic")
    s['libc'].buf_symbolic_bytes = n
    addr_haystack = s.se.BitVecVal(0x10, 64)
    addr_needle = s.se.BitVecVal(0xb0, 64)
    #len_needle = strlen(s, inline=True, arguments=[addr_needle])

    ss_res = strstr(s, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr

    #slh_res = strlen(s, inline=True, arguments=[addr_haystack]).ret_expr
    #sln_res = strlen(s, inline=True, arguments=[addr_needle]).ret_expr
    #print "LENH:", s.se.any_n_int(slh_res, 100)
    #print "LENN:", s.se.any_n_int(sln_res, 100)

    nose.tools.assert_false(s.se.unique(ss_res))
    nose.tools.assert_items_equal(s.se.any_n_int(ss_res, 100), [0] + range(0x10, 0x10 + s['libc'].buf_symbolic_bytes - 1))

    s.add_constraints(ss_res != 0)
    ss2 = strstr(s, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
    s.add_constraints(ss2 == 0)
    print s.se.any_n_int(ss_res, 10)
    print s.se.any_n_int(ss2, 10)
    nose.tools.assert_false(s.satisfiable())

#@nose.tools.timed(10)
def test_memcpy():
    l.info("concrete src, concrete dst, concrete len")
    l.debug("... full copy")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BitVecVal(0x41414141, 32)
    dst_addr = s.se.BitVecVal(0x1000, 64)
    src = s.se.BitVecVal(0x42424242, 32)
    src_addr = s.se.BitVecVal(0x2000, 64)

    s.store_mem(dst_addr, dst)
    s.store_mem(src_addr, src)
    memcpy(s, inline=True, arguments=[dst_addr, src_addr, s.se.BitVecVal(4, 64)])
    new_dst = s.mem_expr(dst_addr, 4, endness='Iend_BE')
    nose.tools.assert_equal(s.se.any_n_str(new_dst, 2), [ "BBBB" ])

    l.debug("... partial copy")
    s = SimState(arch="AMD64", mode="symbolic")
    s.store_mem(dst_addr, dst)
    s.store_mem(src_addr, src)
    memcpy(s, inline=True, arguments=[dst_addr, src_addr, s.se.BitVecVal(2, 64)])
    new_dst = s.mem_expr(dst_addr, 4, endness='Iend_BE')
    nose.tools.assert_equal(s.se.any_n_str(new_dst, 2), [ "BBAA" ])

    l.info("symbolic src, concrete dst, concrete len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BitVecVal(0x41414141, 32)
    dst_addr = s.se.BitVecVal(0x1000, 64)
    src = s.BV("src", 32)
    src_addr = s.se.BitVecVal(0x2000, 64)

    s.store_mem(dst_addr, dst)
    s.store_mem(src_addr, src)

    # make sure it copies it all
    memcpy(s, inline=True, arguments=[dst_addr, src_addr, s.se.BitVecVal(4, 64)])
    nose.tools.assert_true(s.satisfiable())
    s.add_constraints(src != s.mem_expr(dst_addr, 4))
    nose.tools.assert_false(s.satisfiable())

    l.info("symbolic src, concrete dst, symbolic len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BitVecVal(0x41414141, 32)
    dst_addr = s.se.BitVecVal(0x1000, 64)
    src = s.BV("src", 32)
    src_addr = s.se.BitVecVal(0x2000, 64)
    cpylen = s.BV("len", 64)

    s.store_mem(dst_addr, dst)
    s.store_mem(src_addr, src)
    memcpy(s, inline=True, arguments=[dst_addr, src_addr, cpylen])
    result = s.mem_expr(dst_addr, 4, endness='Iend_BE')

    # make sure it copies it all
    s1 = s.copy()
    s1.add_constraints(cpylen == 1)
    nose.tools.assert_true(s1.se.unique(s1.mem_expr(dst_addr+1, 3)))
    nose.tools.assert_equals(len(s1.se.any_n_int(s1.mem_expr(dst_addr, 1), 300)), 256)

    s2 = s.copy()
    s2.add_constraints(cpylen == 2)
    nose.tools.assert_equals(len(s2.se.any_n_int(result[31:24], 300)), 256)
    nose.tools.assert_equals(len(s2.se.any_n_int(result[23:16], 300)), 256)
    nose.tools.assert_equals(s2.se.any_n_str(result[15:0], 300), [ 'AA' ])

    l.info("concrete src, concrete dst, symbolic len")
    dst = s2.se.BitVecVal(0x41414141, 32)
    dst_addr = s2.se.BitVecVal(0x1000, 64)
    src = s2.se.BitVecVal(0x42424242, 32)
    src_addr = s2.se.BitVecVal(0x2000, 64)

    s = SimState(arch="AMD64", mode="symbolic")
    s.store_mem(dst_addr, dst)
    s.store_mem(src_addr, src)
    cpylen = s.BV("len", 64)

    s.add_constraints(s.se.ULE(cpylen, 4))
    memcpy(s, inline=True, arguments=[dst_addr, src_addr, cpylen])
    new_dst = s.mem_expr(dst_addr, 4, endness='Iend_BE')
    nose.tools.assert_items_equal(s.se.any_n_str(new_dst, 300), [ 'AAAA', 'BAAA', 'BBAA', 'BBBA', 'BBBB' ])

#@nose.tools.timed(10)
def test_memcmp():
    l.info("concrete src, concrete dst, concrete len")

    l.debug("... full cmp")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BitVecVal(0x41414141, 32)
    dst_addr = s.se.BitVecVal(0x1000, 64)
    src = s.se.BitVecVal(0x42424242, 32)
    src_addr = s.se.BitVecVal(0x2000, 64)
    s.store_mem(dst_addr, dst)
    s.store_mem(src_addr, src)
    r = memcmp(s, inline=True, arguments=[dst_addr, src_addr, s.BVV(4, 64)]).ret_expr
    nose.tools.assert_true(s.satisfiable())

    s_pos = s.copy()
    s_pos.add_constraints(r >= 0)
    nose.tools.assert_false(s_pos.satisfiable())

    s_neg = s.copy()
    s_neg.add_constraints(r < 0)
    nose.tools.assert_true(s_neg.satisfiable())

    l.debug("... zero cmp")
    s = SimState(arch="AMD64", mode="symbolic")
    s.store_mem(dst_addr, dst)
    s.store_mem(src_addr, src)
    r = memcmp(s, inline=True, arguments=[dst_addr, src_addr, s.se.BitVecVal(0, 64)]).ret_expr
    nose.tools.assert_equals(s.se.any_n_int(r, 2), [ 0 ])

    l.info("symbolic src, concrete dst, concrete len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BitVecVal(0x41414141, 32)
    dst_addr = s.se.BitVecVal(0x1000, 64)
    src = s.BV("src", 32)

    src_addr = s.se.BitVecVal(0x2000, 64)

    s.store_mem(dst_addr, dst)
    s.store_mem(src_addr, src)

    # make sure it copies it all
    r = memcmp(s, inline=True, arguments=[dst_addr, src_addr, s.se.BitVecVal(4, 64)]).ret_expr

    s_match = s.copy()
    s_match.add_constraints(r == 0)
    m = s_match.mem_expr(src_addr, 4)
    nose.tools.assert_equal(s_match.se.any_n_int(m, 2), [0x41414141])

    s_nomatch = s.copy()
    s_nomatch.add_constraints(r != 0)
    m = s_nomatch.mem_expr(src_addr, 4)
    nose.tools.assert_false(s_nomatch.se.solution(m, 0x41414141))

    l.info("symbolic src, concrete dst, symbolic len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BitVecVal(0x41414141, 32)
    dst_addr = s.se.BitVecVal(0x1000, 64)
    src = s.BV("src", 32)
    src_addr = s.se.BitVecVal(0x2000, 64)
    cmplen = s.BV("len", 64)

    s.store_mem(dst_addr, dst)
    s.store_mem(src_addr, src)
    r = memcmp(s, inline=True, arguments=[dst_addr, src_addr, cmplen]).ret_expr

    # look at effects of different lengths
    s1 = s.copy()
    s1.add_constraints(cmplen == 1)
    s1.add_constraints(r == 0)
    l.debug("... simplifying")
    s1.se._solver.simplify()
    l.debug("... solving")
    nose.tools.assert_equals(s1.se.any_n_int(src[31:24], 2), [ 0x41 ])
    nose.tools.assert_false(s1.se.unique(src[31:16]))
    l.debug("... solved")

    s2 = s.copy()
    s2.add_constraints(cmplen == 2)
    s2.add_constraints(r == 0)
    nose.tools.assert_equals(s2.se.any_n_int(s2.mem_expr(src_addr, 2), 2), [ 0x4141 ])
    nose.tools.assert_false(s2.se.unique(s2.mem_expr(src_addr, 3)))

    s2u = s.copy()
    s2u.add_constraints(cmplen == 2)
    s2u.add_constraints(r == 1)
    nose.tools.assert_false(s2u.se.solution(s2u.mem_expr(src_addr, 2), 0x4141))

#@nose.tools.timed(10)
def test_strncpy():
    l.info("concrete src, concrete dst, concrete len")
    l.debug("... full copy")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BitVecVal(0x41414100, 32)
    dst_addr = s.se.BitVecVal(0x1000, 64)
    src = s.se.BitVecVal(0x42420000, 32)
    src_addr = s.se.BitVecVal(0x2000, 64)

    s.store_mem(dst_addr, dst)
    s.store_mem(src_addr, src)
    strncpy(s, inline=True, arguments=[dst_addr, src_addr, s.se.BitVecVal(3, 64)])
    new_dst = s.mem_expr(dst_addr, 4, endness='Iend_BE')
    nose.tools.assert_equal(s.se.any_str(new_dst), "BB\x00\x00")

    l.debug("... partial copy")
    s = SimState(arch="AMD64", mode="symbolic")
    s.store_mem(dst_addr, dst)
    s.store_mem(src_addr, src)
    strncpy(s, inline=True, arguments=[dst_addr, src_addr, s.se.BitVecVal(2, 64)])
    new_dst = s.mem_expr(dst_addr, 4, endness='Iend_BE')
    nose.tools.assert_equal(s.se.any_n_str(new_dst, 2), [ "BBA\x00" ])

    l.info("symbolic src, concrete dst, concrete len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BitVecVal(0x41414100, 32)
    dst_addr = s.se.BitVecVal(0x1000, 64)
    src = s.BV("src", 32)
    src_addr = s.se.BitVecVal(0x2000, 64)

    s.store_mem(dst_addr, dst)
    s.store_mem(src_addr, src)

    # make sure it copies it all
    s.add_constraints(strlen(s, inline=True, arguments=[src_addr]).ret_expr == 2)

    # sanity check
    s_false = s.copy()
    s_false.add_constraints(strlen(s_false, inline=True, arguments=[src_addr]).ret_expr == 3)
    nose.tools.assert_false(s_false.satisfiable())

    strncpy(s, inline=True, arguments=[dst_addr, src_addr, 3])
    nose.tools.assert_true(s.satisfiable())
    c = strcmp(s, inline=True, arguments=[dst_addr, src_addr]).ret_expr

    print s.se.any_n_str(s.mem_expr(dst_addr, 4), 10)
    nose.tools.assert_items_equal(s.se.any_n_int(c, 10), [0])

    l.info("symbolic src, concrete dst, symbolic len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BitVecVal(0x41414100, 32)
    dst_addr = s.se.BitVecVal(0x1000, 64)
    src = s.BV("src", 32)
    src_addr = s.se.BitVecVal(0x2000, 64)
    maxlen = s.BV("len", 64)

    s.store_mem(dst_addr, dst)
    s.store_mem(src_addr, src)

    # make sure it copies it all
    s.add_constraints(strlen(s, inline=True, arguments=[src_addr]).ret_expr == 2)
    strncpy(s, inline=True, arguments=[dst_addr, src_addr, maxlen])
    c = strcmp(s, inline=True, arguments=[dst_addr, src_addr]).ret_expr

    s_match = s.copy()
    s_match.add_constraints(c == 0)
    nose.tools.assert_equals(s_match.se.min_int(maxlen), 3)

    s_nomatch = s.copy()
    s_nomatch.add_constraints(c != 0)
    nose.tools.assert_equals(s_nomatch.se.max_int(maxlen), 2)

    l.info("concrete src, concrete dst, symbolic len")
    l.debug("... full copy")
    s = SimState(arch="AMD64", mode="symbolic")

    dst = s.se.BitVecVal(0x41414100, 32)
    dst_addr = s.se.BitVecVal(0x1000, 64)
    src = s.se.BitVecVal(0x42420000, 32)
    src_addr = s.se.BitVecVal(0x2000, 64)
    maxlen = s.BV("len", 64)

    s.store_mem(dst_addr, dst)
    s.store_mem(src_addr, src)
    strncpy(s, inline=True, arguments=[dst_addr, src_addr, maxlen])
    r = s.mem_expr(dst_addr, 4, endness='Iend_BE')
    #print repr(r.se.any_n_str(10))
    nose.tools.assert_items_equal(s.se.any_n_str(r, 10), [ "AAA\x00", 'BAA\x00', 'BBA\x00', 'BB\x00\x00' ] )


#@nose.tools.timed(10)
def test_strcpy():
    l.info("concrete src, concrete dst")

    l.debug("... full copy")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BitVecVal(0x41414100, 32)
    dst_addr = s.se.BitVecVal(0x1000, 64)
    src = s.se.BitVecVal(0x42420000, 32)
    src_addr = s.se.BitVecVal(0x2000, 64)
    s.store_mem(dst_addr, dst)
    s.store_mem(src_addr, src)
    strcpy(s, inline=True, arguments=[dst_addr, src_addr])
    new_dst = s.mem_expr(dst_addr, 4, endness='Iend_BE')
    nose.tools.assert_equal(s.se.any_str(new_dst), "BB\x00\x00")



    l.info("symbolic src, concrete dst")
    dst = s.se.BitVecVal(0x41414100, 32)
    dst_addr = s.se.BitVecVal(0x1000, 64)
    src = s.BV("src", 32)
    src_addr = s.se.BitVecVal(0x2000, 64)

    s = SimState(arch="AMD64", mode="symbolic")
    s.store_mem(dst_addr, dst)
    s.store_mem(src_addr, src)

    ln = strlen(s, inline=True, arguments=[src_addr]).ret_expr
    print sorted(s.se.any_n_int(ln, 100))

    strcpy(s, inline=True, arguments=[dst_addr, src_addr])
    print sorted(s.se.any_n_int(ln, 100))

    cm = strcmp(s, inline=True, arguments=[dst_addr, src_addr]).ret_expr
    print sorted(s.se.any_n_int(ln, 100))

    s.add_constraints(cm == 0)
    print sorted(s.se.any_n_int(ln, 100))

    s.add_constraints(ln == 15)
    readsize = 16
    both_strs = s.se.Concat(*[ s.mem_expr(dst_addr, readsize, endness='Iend_BE'), s.mem_expr(src_addr, readsize, endness='Iend_BE') ])
    for i in s.se.any_n_str(both_strs, 50):
        print "LINE:", repr(i[:readsize]), repr(i[readsize:])

    #print c.se.any_n_int(10)
    #nose.tools.assert_items_equal(c.se.any_n_int(10), [0])
    #nose.tools.assert_true(s.se.solution(s.mem_expr(dst_addr, 4, endness='Iend_BE'), 0x42434400))
    #nose.tools.assert_true(s.se.solution(s.mem_expr(dst_addr, 4, endness='Iend_BE'), 0x42434445))
    #nose.tools.assert_true(s.se.solution(s.mem_expr(dst_addr, 4, endness='Iend_BE'), 0x00414100))
    #nose.tools.assert_false(s.se.solution(s.mem_expr(dst_addr, 4, endness='Iend_BE'), 0x00010203))

#@nose.tools.timed(10)
def test_sprintf():
    l.info("concrete src, concrete dst, concrete len")
    s = SimState(mode="symbolic", arch="PPC32")
    format_str = s.se.BitVecVal(0x25640000, 32)
    format_addr = s.se.BitVecVal(0x2000, 32)
    #dst = s.se.BitVecVal("destination", 128)
    dst_addr = s.se.BitVecVal(0x1000, 32)
    arg = s.BV("some_number", 32)

    s.store_mem(format_addr, format_str)

    sprintf(s, inline=True, arguments=[dst_addr, format_addr, arg])

    print "CHECKING 2"
    for i in range(9):
        j = random.randint(10**i, 10**(i+1))
        s2 = s.copy()
        s2.add_constraints(arg == j)
        #print s2.se.any_n_str(s2.mem_expr(dst_addr, i+2), 2), repr("%d\x00" % j)
        nose.tools.assert_equal(s2.se.any_n_str(s2.mem_expr(dst_addr, i+2), 2), ["%d\x00" % j])

    s2 = s.copy()
    s2.add_constraints(arg == 0)
    #print s2.se.any_n_str(s2.mem_expr(dst_addr, 2), 2), repr("%d\x00" % 0)
    nose.tools.assert_equal(s2.se.any_n_str(s2.mem_expr(dst_addr, 2), 2), ["%d\x00" % 0])

#@nose.tools.timed(10)
def test_memset():
    l.info("concrete src, concrete dst, concrete len")
    s = SimState(arch="PPC32", mode="symbolic")
    dst = s.se.BitVecVal(0, 128)
    dst_addr = s.se.BitVecVal(0x1000, 32)
    char = s.se.BitVecVal(0x00000041, 32)
    char2 = s.se.BitVecVal(0x50505050, 32)
    length = s.BV("some_length", 32)

    s.store_mem(dst_addr, dst)
    memset(s, inline=True, arguments=[dst_addr, char, s.se.BitVecVal(3, 32)])
    nose.tools.assert_equals(s.se.any_int(s.mem_expr(dst_addr, 4)), 0x41414100)

    l.debug("Symbolic length")
    s = SimState(arch="PPC32", mode="symbolic")
    s.store_mem(dst_addr, dst)
    length = s.BV("some_length", 32)
    memset(s, inline=True, arguments=[dst_addr, char2, length])

    l.debug("Trying 2")
    s_two = s.copy()
    s_two.add_constraints(length == 2)
    nose.tools.assert_equals(s_two.se.any_int(s_two.mem_expr(dst_addr, 4)), 0x50500000)

    l.debug("Trying 0")
    s_zero = s.copy()
    s_zero.add_constraints(length == 0)
    nose.tools.assert_equals(s_zero.se.any_int(s_zero.mem_expr(dst_addr, 4)), 0x00000000)

    l.debug("Trying 5")
    s_five = s.copy()
    s_five.add_constraints(length == 5)
    nose.tools.assert_equals(s_five.se.any_int(s_five.mem_expr(dst_addr, 6)), 0x505050505000)

#def test_concretization():
#    s = SimState(arch="AMD64", mode="symbolic")
#    dst = s.se.BitVecVal(0x41424300, 32)
#    dst_addr = s.se.BitVecVal(0x1000, 64)
#    s.store_mem(dst_addr, dst, 4)
#
#    print "MEM KEYS", s.memory.mem.keys()
#    print "REG KEYS", s.registers.mem.keys()
#
#    print "TO NATIVE..."
#    s.set_native(True)
#    print "... done"
#
#    vv = s.native_env.vexecute(pyvex.IRExpr.Load("Iend_BE", "Ity_I32", pyvex.IRExpr.Const(pyvex.IRConst.U64(0x1000))))
#    nose.tools.assert_equals(vv.str[:4], 'ABC\x00')
#    s.native_env.vexecute(pyvex.IRSB(bytes='\xb8\x41\x42\x43\x44'))
#
#    #import IPython; IPython.embed()
#    print "FROM NATIVE..."
#    s.set_native(False)
#    print "... done"
#
#    nose.tools.assert_equals(s.reg_value(16).se.any_int(), 0x44434241)
#    print "YEAH"

#@nose.tools.timed(10)
def test_inspect():
    class counts: #pylint:disable=no-init
        mem_read = 0
        mem_write = 0
        reg_read = 0
        reg_write = 0
        tmp_read = 0
        tmp_write = 0
        expr = 0
        statement = 0
        instruction = 0
        constraints = 0

    def act_mem_read(state): #pylint:disable=unused-argument
        counts.mem_read += 1
    def act_mem_write(state): #pylint:disable=unused-argument
        counts.mem_write += 1
    def act_reg_read(state): #pylint:disable=unused-argument
        counts.reg_read += 1
    def act_reg_write(state): #pylint:disable=unused-argument
        counts.reg_write += 1
    def act_tmp_read(state): #pylint:disable=unused-argument
        counts.tmp_read += 1
    def act_tmp_write(state): #pylint:disable=unused-argument
        counts.tmp_write += 1
    def act_expr(state): #pylint:disable=unused-argument
        counts.expr += 1
    def act_statement(state): #pylint:disable=unused-argument
        counts.statement += 1
    def act_instruction(state): #pylint:disable=unused-argument
        counts.instruction += 1
#    def act_constraints(state): #pylint:disable=unused-argument
#        counts.constraints += 1


    s = SimState(arch="AMD64", mode="symbolic")

    s.inspect.add_breakpoint('mem_write', simuvex.BP(simuvex.BP_AFTER, action=act_mem_write))
    nose.tools.assert_equals(counts.mem_write, 0)
    s.store_mem(100, s.se.BitVecVal(10, 32))
    nose.tools.assert_equals(counts.mem_write, 1)

    s.inspect.add_breakpoint('mem_read', simuvex.BP(simuvex.BP_AFTER, action=act_mem_read))
    s.inspect.add_breakpoint('mem_read', simuvex.BP(simuvex.BP_AFTER, action=act_mem_read, mem_read_address=100))
    s.inspect.add_breakpoint('mem_read', simuvex.BP(simuvex.BP_AFTER, action=act_mem_read, mem_read_address=123))
    nose.tools.assert_equals(counts.mem_read, 0)
    s.mem_expr(123, 4)
    nose.tools.assert_equals(counts.mem_read, 2)

    s.inspect.add_breakpoint('reg_read', simuvex.BP(simuvex.BP_AFTER, action=act_reg_read))
    nose.tools.assert_equals(counts.reg_read, 0)
    s.reg_expr(16)
    nose.tools.assert_equals(counts.reg_read, 1)

    s.inspect.add_breakpoint('reg_write', simuvex.BP(simuvex.BP_AFTER, action=act_reg_write))
    nose.tools.assert_equals(counts.reg_write, 0)
    s.store_reg(16, s.se.BitVecVal(10, 32))
    nose.tools.assert_equals(counts.mem_write, 1)
    nose.tools.assert_equals(counts.mem_read, 2)
    nose.tools.assert_equals(counts.reg_read, 1)

    s.inspect.add_breakpoint('tmp_read', simuvex.BP(simuvex.BP_AFTER, action=act_tmp_read, tmp_read_num=0))
    s.inspect.add_breakpoint('tmp_write', simuvex.BP(simuvex.BP_AFTER, action=act_tmp_write, tmp_write_num=0))
    s.inspect.add_breakpoint('expr', simuvex.BP(simuvex.BP_AFTER, action=act_expr, expr=1016, expr_unique=False))
    s.inspect.add_breakpoint('statement', simuvex.BP(simuvex.BP_AFTER, action=act_statement))
    s.inspect.add_breakpoint('instruction', simuvex.BP(simuvex.BP_AFTER, action=act_instruction, instruction=1001))
    s.inspect.add_breakpoint('instruction', simuvex.BP(simuvex.BP_AFTER, action=act_instruction, instruction=1000))
    irsb = pyvex.IRSB("\x90\x90\x90\x90\xeb\x0a", mem_addr=1000)
    irsb.pp()
    simuvex.SimIRSB(s, irsb)
    nose.tools.assert_equals(counts.reg_write, 6)
    nose.tools.assert_equals(counts.reg_read, 2)
    nose.tools.assert_equals(counts.tmp_write, 1)
    nose.tools.assert_equals(counts.tmp_read, 1)
    nose.tools.assert_equals(counts.expr, 3) # one for the Put, one for the WrTmp, and one to get the next address to jump to
    nose.tools.assert_equals(counts.statement, 26)
    nose.tools.assert_equals(counts.instruction, 2)
    nose.tools.assert_equals(counts.constraints, 0)

    # final tally
    nose.tools.assert_equals(counts.mem_write, 1)
    nose.tools.assert_equals(counts.mem_read, 2)
    nose.tools.assert_equals(counts.reg_write, 6)
    nose.tools.assert_equals(counts.reg_read, 2)
    nose.tools.assert_equals(counts.tmp_write, 1)
    nose.tools.assert_equals(counts.tmp_read, 1)
    nose.tools.assert_equals(counts.expr, 3)
    nose.tools.assert_equals(counts.statement, 26)
    nose.tools.assert_equals(counts.instruction, 2)
    nose.tools.assert_equals(counts.constraints, 0)

#@nose.tools.timed(10)
def test_symbolic_write():
    s = SimState(arch='AMD64', mode='symbolic')

    addr = s.BV('addr', 64)
    s.add_constraints(s.se.Or(addr == 10, addr == 20, addr == 30))
    nose.tools.assert_equals(len(s.se.any_n_int(addr, 10)), 3)

    s.store_mem(10, s.se.BitVecVal(1, 8))
    s.store_mem(20, s.se.BitVecVal(2, 8))
    s.store_mem(30, s.se.BitVecVal(3, 8))

    nose.tools.assert_true(s.se.unique(s.mem_expr(10, 1)))
    nose.tools.assert_true(s.se.unique(s.mem_expr(20, 1)))
    nose.tools.assert_true(s.se.unique(s.mem_expr(30, 1)))

    #print "CONSTRAINTS BEFORE:", s.constraints._solver.constraints
    s.store_mem(addr, s.se.BitVecVal(255, 8), strategy=['symbolic','any'], limit=100)
    nose.tools.assert_true(s.satisfiable())
    print "GO TIME"
    nose.tools.assert_equals(len(s.se.any_n_int(addr, 10)), 3)
    nose.tools.assert_items_equal(s.se.any_n_int(s.mem_expr(10, 1), 3), [ 1, 255 ])
    nose.tools.assert_items_equal(s.se.any_n_int(s.mem_expr(20, 1), 3), [ 2, 255 ])
    nose.tools.assert_items_equal(s.se.any_n_int(s.mem_expr(30, 1), 3), [ 3, 255 ])
    nose.tools.assert_equals(len(s.se.any_n_int(addr, 10)), 3)

    # see if it works when constraining the write address
    sa = s.copy()
    sa.add_constraints(addr == 20)
    nose.tools.assert_true(sa.satisfiable())
    nose.tools.assert_items_equal(sa.se.any_n_int(sa.mem_expr(10, 1), 3), [ 1 ])
    nose.tools.assert_items_equal(sa.se.any_n_int(sa.mem_expr(20, 1), 3), [ 255 ])
    nose.tools.assert_items_equal(sa.se.any_n_int(sa.mem_expr(30, 1), 3), [ 3 ])
    nose.tools.assert_items_equal(sa.se.any_n_int(addr, 10), [ 20 ])

    # see if it works when constraining a value to the written one
    sv = s.copy()
    sv.add_constraints(sv.mem_expr(30, 1) == 255)
    nose.tools.assert_true(sv.satisfiable())
    nose.tools.assert_items_equal(sv.se.any_n_int(sv.mem_expr(10, 1), 3), [ 1 ])
    nose.tools.assert_items_equal(sv.se.any_n_int(sv.mem_expr(20, 1), 3), [ 2 ])
    nose.tools.assert_items_equal(sv.se.any_n_int(sv.mem_expr(30, 1), 3), [ 255 ])
    nose.tools.assert_items_equal(sv.se.any_n_int(addr, 10), [ 30 ])

    # see if it works when constraining a value to the unwritten one
    sv = s.copy()
    sv.add_constraints(sv.mem_expr(30, 1) == 3)
    nose.tools.assert_true(sv.satisfiable())
    nose.tools.assert_items_equal(sv.se.any_n_int(sv.mem_expr(10, 1), 3), [ 1, 255 ])
    nose.tools.assert_items_equal(sv.se.any_n_int(sv.mem_expr(20, 1), 3), [ 2, 255 ])
    nose.tools.assert_items_equal(sv.se.any_n_int(sv.mem_expr(30, 1), 3), [ 3 ])
    nose.tools.assert_items_equal(sv.se.any_n_int(addr, 10), [ 10, 20 ])

    s = SimState(arch='AMD64', mode='symbolic')
    s.store_mem(0, s.se.BitVecVal(0x4141414141414141, 64))
    length = s.BV("length", 32)
    s.store_mem(0, s.se.BitVecVal(0x4242424242424242, 64), symbolic_length=length)

    for i in range(8):
        ss = s.copy()
        ss.add_constraints(length == i)
        nose.tools.assert_equal(ss.se.any_str(s.mem_expr(0, 8)), "B"*i + "A"*(8-i))

    print "GROOVY"

#@nose.tools.timed(10)
def test_strtok_r():
    l.debug("CONCRETE MODE")
    s = SimState(arch='AMD64', mode='symbolic')
    s.store_mem(100, s.se.BitVecVal(0x4141414241414241424300, 88), endness='Iend_BE')
    s.store_mem(200, s.se.BitVecVal(0x4200, 16), endness='Iend_BE')
    str_ptr = s.se.BitVecVal(100, s.arch.bits)
    delim_ptr = s.se.BitVecVal(200, s.arch.bits)
    state_ptr = s.se.BitVecVal(300, s.arch.bits)

    st1 = strtok_r(s, inline=True, arguments=[str_ptr, delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st1.ret_expr, 10), [104])
    nose.tools.assert_equal(s.se.any_n_int(s.mem_expr(st1.ret_expr-1, 1), 10), [0])
    nose.tools.assert_equal(s.se.any_n_int(s.mem_expr(200, 2), 10), [0x4200])

    st2 = strtok_r(s, inline=True, arguments=[s.se.BitVecVal(0, s.arch.bits), delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st2.ret_expr, 10), [107])
    nose.tools.assert_equal(s.se.any_n_int(s.mem_expr(st2.ret_expr-1, 1), 10), [0])

    st3 = strtok_r(s, inline=True, arguments=[s.se.BitVecVal(0, s.arch.bits), delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st3.ret_expr, 10), [109])
    nose.tools.assert_equal(s.se.any_n_int(s.mem_expr(st3.ret_expr-1, 1), 10), [0])

    st4 = strtok_r(s, inline=True, arguments=[s.se.BitVecVal(0, s.arch.bits), delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st4.ret_expr, 10), [0])
    nose.tools.assert_equal(s.se.any_n_int(s.mem_expr(300, s.arch.bytes, endness=s.arch.memory_endness), 10), [109])

    st5 = strtok_r(s, inline=True, arguments=[s.se.BitVecVal(0, s.arch.bits), delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st5.ret_expr, 10), [0])
    nose.tools.assert_equal(s.se.any_n_int(s.mem_expr(300, s.arch.bytes, endness=s.arch.memory_endness), 10), [109])

    s.store_mem(1000, s.se.BitVecVal(0x4141414241414241424300, 88), endness='Iend_BE')
    s.store_mem(2000, s.se.BitVecVal(0x4200, 16), endness='Iend_BE')
    str_ptr = s.se.BitVecVal(1000, s.arch.bits)
    delim_ptr = s.se.BitVecVal(2000, s.arch.bits)
    state_ptr = s.se.BitVecVal(3000, s.arch.bits)

    st1 = strtok_r(s, inline=True, arguments=[str_ptr, delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st1.ret_expr, 10), [1004])
    nose.tools.assert_equal(s.se.any_n_int(s.mem_expr(st1.ret_expr-1, 1), 10), [0])
    nose.tools.assert_equal(s.se.any_n_int(s.mem_expr(2000, 2), 10), [0x4200])

    st2 = strtok_r(s, inline=True, arguments=[s.se.BitVecVal(0, s.arch.bits), delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st2.ret_expr, 10), [1007])
    nose.tools.assert_equal(s.se.any_n_int(s.mem_expr(st2.ret_expr-1, 1), 10), [0])

    st3 = strtok_r(s, inline=True, arguments=[s.se.BitVecVal(0, s.arch.bits), delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st3.ret_expr, 10), [1009])
    nose.tools.assert_equal(s.se.any_n_int(s.mem_expr(st3.ret_expr-1, 1), 10), [0])

    st4 = strtok_r(s, inline=True, arguments=[s.se.BitVecVal(0, s.arch.bits), delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st4.ret_expr, 10), [0])
    nose.tools.assert_equal(s.se.any_n_int(s.mem_expr(3000, s.arch.bytes, endness=s.arch.memory_endness), 10), [1009])

    st5 = strtok_r(s, inline=True, arguments=[s.se.BitVecVal(0, s.arch.bits), delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st5.ret_expr, 10), [0])
    nose.tools.assert_equal(s.se.any_n_int(s.mem_expr(3000, s.arch.bytes, endness=s.arch.memory_endness), 10), [1009])

    print "LIGHT FULLY SYMBOLIC TEST"
    s = SimState(arch='AMD64', mode='symbolic')
    str_ptr = s.se.BitVecVal(100, s.arch.bits)
    delim_ptr = s.se.BitVecVal(200, s.arch.bits)
    state_ptr = s.se.BitVecVal(300, s.arch.bits)

    s.add_constraints(s.mem_expr(delim_ptr, 1) != 0)

    st1 = strtok_r(s, inline=True, arguments=[str_ptr, delim_ptr, state_ptr])
    s.add_constraints(st1.ret_expr != 0)
    nose.tools.assert_equal(s.se.any_n_int(s.mem_expr(st1.ret_expr-1, 1), 10), [0])

#@nose.tools.timed(10)
def test_strchr():
    l.info("concrete haystack and needle")
    s = SimState(arch="AMD64", mode="symbolic")
    str_haystack = s.se.BitVecVal(0x41424300, 32)
    str_needle = s.se.BitVecVal(0x42, 64)
    addr_haystack = s.se.BitVecVal(0x10, 64)
    s.store_mem(addr_haystack, str_haystack, endness="Iend_BE")

    ss_res = strchr(s, inline=True, arguments=[addr_haystack, str_needle]).ret_expr
    nose.tools.assert_true(s.se.unique(ss_res))
    nose.tools.assert_equal(s.se.any_int(ss_res), 0x11)

    l.info("concrete haystack, symbolic needle")
    s = SimState(arch="AMD64", mode="symbolic")
    str_haystack = s.se.BitVecVal(0x41424300, 32)
    str_needle = s.BV("wtf", 64)
    chr_needle = str_needle[7:0]
    addr_haystack = s.se.BitVecVal(0x10, 64)
    s.store_mem(addr_haystack, str_haystack, endness="Iend_BE")

    ss_res = strchr(s, inline=True, arguments=[addr_haystack, str_needle]).ret_expr
    nose.tools.assert_false(s.se.unique(ss_res))
    nose.tools.assert_equal(len(s.se.any_n_int(ss_res, 10)), 4)

    s_match = s.copy()
    s_nomatch = s.copy()
    s_match.add_constraints(ss_res != 0)
    s_nomatch.add_constraints(ss_res == 0)

    nose.tools.assert_true(s_match.satisfiable())
    nose.tools.assert_true(s_nomatch.satisfiable())
    nose.tools.assert_equal(len(s_match.se.any_n_int(chr_needle, 300)), 3)
    nose.tools.assert_equal(len(s_nomatch.se.any_n_int(chr_needle, 300)), 253)
    nose.tools.assert_items_equal(s_match.se.any_n_int(ss_res, 300), [ 0x10, 0x11, 0x12 ])
    nose.tools.assert_items_equal(s_match.se.any_n_int(chr_needle, 300), [ 0x41, 0x42, 0x43 ])

    print "writing"
    s_match.store_mem(ss_res, s_match.BVV(0x44, 8))
    print "writing"
    nose.tools.assert_items_equal(s_match.se.any_n_int(s_match.mem_expr(0x10, 1), 300), [ 0x41, 0x44 ])
    nose.tools.assert_items_equal(s_match.se.any_n_int(s_match.mem_expr(0x11, 1), 300), [ 0x42, 0x44 ])
    nose.tools.assert_items_equal(s_match.se.any_n_int(s_match.mem_expr(0x12, 1), 300), [ 0x43, 0x44 ])

    print "TUBULAR"
    return

    #l.info("symbolic haystack, symbolic needle")
    #s = SimState(arch="AMD64", mode="symbolic")
    #s['libc'].buf_symbolic_bytes = 5
    #addr_haystack = s.se.BitVecVal(0x10, 64)
    #addr_needle = s.se.BitVecVal(0xb0, 64)
    #len_needle = strlen(s, inline=True, arguments=[addr_needle])

    #ss_res = strstr(s, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
    #ss_val = s.expr_value(ss_res)

    #nose.tools.assert_false(ss_val.is_unique())
    #nose.tools.assert_equal(len(ss_val.se.any_n_int(100)), s['libc'].buf_symbolic_bytes)

    #s_match = s.copy()
    #s_nomatch = s.copy()
    #s_match.add_constraints(ss_res != 0)
    #s_nomatch.add_constraints(ss_res == 0)

    #match_cmp = strncmp(s_match, inline=True, arguments=[ss_res, addr_needle, len_needle.ret_expr]).ret_expr
    #match_cmp_val = s_match.expr_value(match_cmp)
    #nose.tools.assert_items_equal(match_cmp_val.se.any_n_int(10), [0])

    #r_mm = strstr(s_match, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
    #s_match.add_constraints(r_mm == 0)
    #nose.tools.assert_false(s_match.satisfiable())

    #nose.tools.assert_true(s_nomatch.satisfiable())
    #s_nss = s_nomatch.copy()
    #nomatch_ss = strstr(s_nss, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
    #s_nss.add_constraints(nomatch_ss != 0)
    #nose.tools.assert_false(s_nss.satisfiable())

if __name__ == '__main__':
    l.setLevel(logging.DEBUG)
#    print "sprintf"
#    test_sprintf()
#
#    print "state_merge"
#    test_state_merge()
#
#    print "memory"
#    test_memory()
#
##    #test_concretization()
#

    import sys
    if len(sys.argv) > 1:
        globals()['test_' + sys.argv[1]]()
    else:
        print 'memory'
        test_memory()

        print 'registers'
        test_registers()

        print 'state'
        test_state()

        print "memcmp"
        test_memcmp()

        print "memset"
        test_memset()

        print "memcpy"
        test_memcpy()

        print "strlen"
        test_inline_strlen()

        print "strncmp"
        test_inline_strncmp()

        print "strcmp"
        test_inline_strcmp()

        print "strncpy"
        test_strncpy()

        print "strcpy"
        test_strcpy()

        ##print "strstr_inconsistency(2)"
        ##test_strstr_inconsistency(2)

        ##print "strstr_inconsistency(3)"
        ##test_strstr_inconsistency(3)

        ##print "inline_strstr"
        ##test_inline_strstr()

        print "inspect"
        #test_inspect()

        print "symbolic_write"
        test_symbolic_write()

        print "strchr"
        test_strchr()

        import claripy.backends.backend_z3
        print 'solve_count', claripy.backends.backend_z3.solve_count
        print 'cache_count', claripy.backends.backend_z3.cache_count
        print 'cached_evals', claripy.solvers.solver.cached_evals
        print 'cached_min', claripy.solvers.solver.cached_min
        print 'cached_max', claripy.solvers.solver.cached_max
        print 'cached_solve', claripy.solvers.solver.cached_solve
        print 'filter_true', claripy.solvers.solver.filter_true
        print 'filter_false', claripy.solvers.solver.filter_false


        #print "strtok_r"
        #test_strtok_r()
