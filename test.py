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

import symexec as se
#from simuvex import SimMemory
from simuvex import SimState
from simuvex import s_ccall, SimProcedures
import pyvex

strstr = SimProcedures['libc.so.6']['strstr']
strcmp = SimProcedures['libc.so.6']['strcmp']
strncmp = SimProcedures['libc.so.6']['strncmp']
strlen = SimProcedures['libc.so.6']['strlen']
strncpy = SimProcedures['libc.so.6']['strncpy']
strcpy = SimProcedures['libc.so.6']['strcpy']
sprintf = SimProcedures['libc.so.6']['sprintf']
memset = SimProcedures['libc.so.6']['memset']

## pylint: disable=R0904
#def test_memory():
#	initial_memory = { 0: 'A', 1: 'A', 2: 'A', 3: 'A', 10: 'B' }
#	vectorized_memory = Vectorizer(initial_memory)
#	mem = SimMemory(backer=vectorized_memory)
#
#	# concrete address and concrete result
#	loaded_val = SimValue(mem.load(0, 4)[0]) # Returns: a z3 BitVec representing 0x41414141
#	nose.tools.assert_false(loaded_val.is_symbolic())
#	nose.tools.assert_equal(loaded_val.any(), 0x41414141)
#
#	# concrete address and partially symbolic result
#	loaded_val = SimValue(mem.load(2, 4)[0])
#	nose.tools.assert_true(loaded_val.is_symbolic())
#	nose.tools.assert_false(loaded_val.is_unique())
#	nose.tools.assert_greater_equal(loaded_val.any(), 0x41410000)
#	nose.tools.assert_less_equal(loaded_val.any(), 0x41420000)
#	nose.tools.assert_equal(loaded_val.min(), 0x41410000)
#	nose.tools.assert_equal(loaded_val.max(), 0x4141ffff)
#
#	# symbolic (but fixed) address and concrete result
#	x = se.BitVec('x', 64)
#	addr = SimValue(x, constraints = [ x == 10 ])
#	loaded_val = SimValue(mem.load(addr, 1)[0])
#	nose.tools.assert_false(loaded_val.is_symbolic())
#	nose.tools.assert_equal(loaded_val.any(), 0x42)

#def test_symvalue():
#	# concrete symvalue
#	zero = SimValue(se.BitVecVal(0, 64))
#	nose.tools.assert_false(zero.is_symbolic())
#	nose.tools.assert_equal(zero.any(), 0)
#	nose.tools.assert_raises(ConcretizingException, zero.exactly_n, 2)
#
#	# symbolic symvalue
#	x = se.BitVec('x', 64)
#	sym = SimValue(x, constraints = [ x > 100, x < 200 ])
#	nose.tools.assert_true(sym.is_symbolic())
#	nose.tools.assert_equal(sym.min(), 101)
#	nose.tools.assert_equal(sym.max(), 199)
#	nose.tools.assert_items_equal(sym.any_n(99), range(101, 200))
#	nose.tools.assert_raises(ConcretizingException, zero.exactly_n, 102)

def test_state_merge():
	a = SimState(mode='symbolic')
	a.store_mem(1, se.BitVecVal(42, 8))

	b = a.copy()
	c = b.copy()
	a.store_mem(2, a.mem_expr(1, 1)+1)
	b.store_mem(2, b.mem_expr(1, 1)*2)
	c.store_mem(2, c.mem_expr(1, 1)/2)

	# make sure the byte at 1 is right
	nose.tools.assert_equal(a.mem_value(1, 1).any(), 42)
	nose.tools.assert_equal(b.mem_value(1, 1).any(), 42)
	nose.tools.assert_equal(c.mem_value(1, 1).any(), 42)

	# make sure the byte at 2 is right
	nose.tools.assert_equal(a.mem_value(2, 1).any(), 43)
	nose.tools.assert_equal(b.mem_value(2, 1).any(), 84)
	nose.tools.assert_equal(c.mem_value(2, 1).any(), 21)

	# the byte at 2 should be unique for all before the merge
	nose.tools.assert_true(a.mem_value(2, 1).is_unique())
	nose.tools.assert_true(b.mem_value(2, 1).is_unique())
	nose.tools.assert_true(c.mem_value(2, 1).is_unique())

	merge_val = a.merge(b, c)

	# the byte at 2 should now *not* be unique for a
	nose.tools.assert_false(a.mem_value(2, 1).is_unique())
	nose.tools.assert_true(b.mem_value(2, 1).is_unique())
	nose.tools.assert_true(c.mem_value(2, 1).is_unique())

	# the byte at 2 should have the three values
	nose.tools.assert_items_equal(a.mem_value(2, 1).any_n(10), (43, 84, 21))

	# we should be able to select them by adding constraints
	a_a = a.copy()
	a_a.add_constraints(merge_val == 0)
	nose.tools.assert_true(a_a.mem_value(2, 1).is_unique())
	nose.tools.assert_equal(a_a.mem_value(2, 1).any(), 43)

	a_b = a.copy()
	a_b.add_constraints(merge_val == 1)
	nose.tools.assert_true(a_b.mem_value(2, 1).is_unique())
	nose.tools.assert_equal(a_b.mem_value(2, 1).any(), 84)

	a_c = a.copy()
	a_c.add_constraints(merge_val == 2)
	nose.tools.assert_true(a_c.mem_value(2, 1).is_unique())
	nose.tools.assert_equal(a_c.mem_value(2, 1).any(), 21)

def test_ccall():
	s = SimState(arch="AMD64")

	l.debug("Testing amd64_actions_ADD")
	l.debug("(8-bit) 1 + 1...")
	arg_l = se.BitVecVal(1, 8)
	arg_r = se.BitVecVal(1, 8)
	ret = s_ccall.pc_actions_ADD(s, 8, arg_l, arg_r, 0)
	nose.tools.assert_equal(ret, 0)

	l.debug("(32-bit) (-1) + (-2)...")
	arg_l = se.BitVecVal(-1, 32)
	arg_r = se.BitVecVal(-1, 32)
	ret = s_ccall.pc_actions_ADD(s, 32, arg_l, arg_r, 0)
	nose.tools.assert_equal(ret, 0b101010)

	l.debug("Testing pc_actions_SUB")
	l.debug("(8-bit) 1 - 1...",)
	arg_l = se.BitVecVal(1, 8)
	arg_r = se.BitVecVal(1, 8)
	ret = s_ccall.pc_actions_SUB(s, 8, arg_l, arg_r, 0)
	nose.tools.assert_equal(ret, 0b010100)

	l.debug("(32-bit) (-1) - (-2)...")
	arg_l = se.BitVecVal(-1, 32)
	arg_r = se.BitVecVal(-1, 32)
	ret = s_ccall.pc_actions_SUB(s, 32, arg_l, arg_r, 0)
	nose.tools.assert_equal(ret, 0)

def test_inline_strlen():
	s = SimState(arch="AMD64", mode="symbolic")

	l.info("fully concrete string")
	a_str = se.BitVecVal(0x41414100, 32)
	a_addr = se.BitVecVal(0x10, 64)
	s.store_mem(a_addr, a_str, endness="Iend_BE")
	a_len = SimProcedures['libc.so.6']['strlen'](s, inline=True, arguments=[a_addr]).ret_expr
	nose.tools.assert_true(s.expr_value(a_len).is_unique())
	nose.tools.assert_equal(s.expr_value(a_len).any(), 3)

	l.info("concrete-terminated string")
	b_str = se.Concat(s.new_symbolic("mystring", 24), se.BitVecVal(0, 8))
	b_addr = se.BitVecVal(0x20, 64)
	s.store_mem(b_addr, b_str, endness="Iend_BE")
	b_len = SimProcedures['libc.so.6']['strlen'](s, inline=True, arguments=[b_addr]).ret_expr
	nose.tools.assert_equal(s.expr_value(b_len).max(), 3)
	nose.tools.assert_items_equal(s.expr_value(b_len).any_n(10), (0,1,2,3))

	l.info("fully unconstrained")
	u_addr = se.BitVecVal(0x50, 64)
	u_len = SimProcedures['libc.so.6']['strlen'](s, inline=True, arguments=[u_addr]).ret_expr
	nose.tools.assert_equal(len(s.expr_value(u_len).any_n(100)), 16)
	nose.tools.assert_equal(s.expr_value(u_len).max(), 15)

	#
	# This tests if a strlen can influence a symbolic str.
	#
	l.info("Trying to influence length.")
	s = SimState(arch="AMD64", mode="symbolic")
	str_c = s.new_symbolic("some_string", 8*16)
	c_addr = se.BitVecVal(0x10, 64)
	s.store_mem(c_addr, str_c, endness='Iend_BE')
	c_len = SimProcedures['libc.so.6']['strlen'](s, inline=True, arguments=[c_addr]).ret_expr
	nose.tools.assert_equal(len(s.expr_value(c_len).any_n(100)), 16)
	nose.tools.assert_equal(s.expr_value(c_len).max(), 15)

	one_s = s.copy()
	one_s.add_constraints(c_len == 1)
	nose.tools.assert_equal(one_s.expr_value(str_c).any_str().index('\x00'), 1)
	str_test = one_s.mem_value(c_addr, 2, endness='Iend_BE')
	nose.tools.assert_equal(len(str_test.any_n_str(300)), 255)

	for i in range(2):
		test_s = s.copy()
		test_s.add_constraints(c_len == i)
		str_test = test_s.mem_value(c_addr, i + 1, endness='Iend_BE')
		nose.tools.assert_equal(str_test.any_str().index('\x00'), i)
		nose.tools.assert_equal(len(str_test.any_n_str(2 ** (i*8) + 1)), 2 ** (i*8) - i)

def test_inline_strcmp():
	s = SimState(arch="AMD64", mode="symbolic")
	str_a = se.BitVecVal(0x41414100, 32)
	str_b = s.new_symbolic("mystring", 32)

	a_addr = se.BitVecVal(0x10, 64)
	b_addr = se.BitVecVal(0xb0, 64)

	s.store_mem(a_addr, str_a, endness="Iend_BE")
	s.store_mem(b_addr, str_b, endness="Iend_BE")

	s_cmp = s.copy()
	cmpres = SimProcedures['libc.so.6']['strcmp'](s_cmp, inline=True, arguments=[a_addr, b_addr]).ret_expr
	s_match = s_cmp.copy()
	s_nomatch = s_cmp.copy()
	s_match.add_constraints(cmpres == 0)
	s_nomatch.add_constraints(cmpres != 0)

	nose.tools.assert_true(s_match.expr_value(str_b).is_unique())
	nose.tools.assert_false(s_nomatch.expr_value(str_b).is_unique())
	nose.tools.assert_equal(s_match.expr_value(str_b).any_str(), "AAA\x00")

	s_ncmp = s.copy()
	ncmpres = SimProcedures['libc.so.6']['strncmp'](s_ncmp, inline=True, arguments=[a_addr, b_addr, se.BitVecVal(2, s.arch.bits)]).ret_expr
	s_match = s_ncmp.copy()
	s_nomatch = s_ncmp.copy()
	s_match.add_constraints(ncmpres == 0)
	s_nomatch.add_constraints(ncmpres != 0)

	nose.tools.assert_false(s_match.expr_value(str_b).is_unique())
	nose.tools.assert_true(s_match.mem_value(b_addr, 2).is_unique())
	nose.tools.assert_equal(len(s_match.mem_value(b_addr, 3).any_n(300)), 256)
	nose.tools.assert_false(s_nomatch.expr_value(str_b).is_unique())

	l.info("concrete a, symbolic b")
	s = SimState(arch="AMD64", mode="symbolic")
	str_a = se.BitVecVal(0x41424300, 32)
	str_b = s.new_symbolic("mystring", 32)
	a_addr = se.BitVecVal(0x10, 64)
	b_addr = se.BitVecVal(0xb0, 64)
	s.store_mem(a_addr, str_a, endness="Iend_BE")
	s.store_mem(b_addr, str_b, endness="Iend_BE")

	s_cmp = s.copy()
	cmpres = strncmp(s_cmp, inline=True, arguments=[a_addr, b_addr, se.BitVecVal(2, s_cmp.arch.bits)]).ret_expr
	s_match = s_cmp.copy()
	s_nomatch = s_cmp.copy()
	s_match.add_constraints(cmpres == 0)
	s_nomatch.add_constraints(cmpres != 0)

	b_match = s_match.expr_value(str_b)
	b_nomatch = s_nomatch.expr_value(str_b)

	nose.tools.assert_true(b_match.is_solution(0x41420000))
	nose.tools.assert_true(b_match.is_solution(0x41421234))
	nose.tools.assert_true(b_match.is_solution(0x41424300))
	nose.tools.assert_false(b_nomatch.is_solution(0x41420000))
	nose.tools.assert_false(b_nomatch.is_solution(0x41421234))
	nose.tools.assert_false(b_nomatch.is_solution(0x41424300))

	l.info("symbolic a, symbolic b")
	s = SimState(arch="AMD64", mode="symbolic")
	a_addr = se.BitVecVal(0x10, 64)
	b_addr = se.BitVecVal(0xb0, 64)

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

def test_inline_strncmp():
	l.info("symbolic left, symbolic right, symbolic len")
	s = SimState(arch="AMD64", mode="symbolic")

	left = s.new_symbolic("left", 32)
	left_addr = se.BitVecVal(0x1000, 64)
	right = s.new_symbolic("right", 32)
	right_addr = se.BitVecVal(0x2000, 64)
	maxlen = s.new_symbolic("len", 64)

	s.store_mem(left_addr, left, 4)
	s.store_mem(right_addr, right, 4)

	s.add_constraints(strlen(s, inline=True, arguments=[left_addr]).ret_expr == 3)
	s.add_constraints(strlen(s, inline=True, arguments=[right_addr]).ret_expr == 0)
	s.add_constraints(maxlen != 0)
	c = strncmp(s, inline=True, arguments=[left_addr, right_addr, maxlen]).ret_expr

	s_match = s.copy()
	s_match.add_constraints(c == 0)
	nose.tools.assert_false(s_match.satisfiable())
	#nose.tools.assert_equals(s_match.expr_value(maxlen).min(), 3)

	s_nomatch = s.copy()
	s_nomatch.add_constraints(c != 0)
	nose.tools.assert_true(s_nomatch.satisfiable())
	#nose.tools.assert_equals(s_nomatch.expr_value(maxlen).max(), 2)

def test_inline_strstr():
	l.info("concrete haystack and needle")
	s = SimState(arch="AMD64", mode="symbolic")
	str_haystack = se.BitVecVal(0x41424300, 32)
	str_needle = se.BitVecVal(0x42430000, 32)
	addr_haystack = se.BitVecVal(0x10, 64)
	addr_needle = se.BitVecVal(0xb0, 64)
	s.store_mem(addr_haystack, str_haystack, endness="Iend_BE")
	s.store_mem(addr_needle, str_needle, endness="Iend_BE")

	ss_res = strstr(s, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
	ss_val = s.expr_value(ss_res)

	nose.tools.assert_true(ss_val.is_unique())
	nose.tools.assert_equal(ss_val.any(), 0x11)

	l.info("concrete haystack, symbolic needle")
	s = SimState(arch="AMD64", mode="symbolic")
	str_haystack = se.BitVecVal(0x41424300, 32)
	str_needle = s.new_symbolic("wtf", 32)
	addr_haystack = se.BitVecVal(0x10, 64)
	addr_needle = se.BitVecVal(0xb0, 64)
	s.store_mem(addr_haystack, str_haystack, endness="Iend_BE")
	s.store_mem(addr_needle, str_needle, endness="Iend_BE")

	ss_res = strstr(s, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
	ss_val = s.expr_value(ss_res)

	nose.tools.assert_false(ss_val.is_unique())
	nose.tools.assert_equal(len(ss_val.any_n(10)), 4)

	s_match = s.copy()
	s_nomatch = s.copy()
	s_match.add_constraints(ss_res != 0)
	s_nomatch.add_constraints(ss_res != 0)

	match_needle = s_match.expr_value(se.Extract(31, 16, str_needle))
	nose.tools.assert_equal(len(match_needle.any_n(300)), 259)
	nomatch_needle = s_match.expr_value(str_needle)
	nose.tools.assert_equal(len(nomatch_needle.any_n(10)), 10)

	l.info("symbolic haystack, symbolic needle")
	s = SimState(arch="AMD64", mode="symbolic")
	s['libc'].max_str_symbolic_bytes = 5
	addr_haystack = se.BitVecVal(0x10, 64)
	addr_needle = se.BitVecVal(0xb0, 64)
	len_needle = strlen(s, inline=True, arguments=[addr_needle])

	ss_res = strstr(s, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
	ss_val = s.expr_value(ss_res)

	nose.tools.assert_false(ss_val.is_unique())
	nose.tools.assert_equal(len(ss_val.any_n(100)), s['libc'].max_str_symbolic_bytes)

	s_match = s.copy()
	s_nomatch = s.copy()
	s_match.add_constraints(ss_res != 0)
	s_nomatch.add_constraints(ss_res == 0)

	match_cmp = strncmp(s_match, inline=True, arguments=[ss_res, addr_needle, len_needle.ret_expr]).ret_expr
	match_cmp_val = s_match.expr_value(match_cmp)
	nose.tools.assert_items_equal(match_cmp_val.any_n(10), [0])

	r_mm = strstr(s_match, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
	s_match.add_constraints(r_mm == 0)
	nose.tools.assert_false(s_match.satisfiable())

	nose.tools.assert_true(s_nomatch.satisfiable())
	s_nss = s_nomatch.copy()
	nomatch_ss = strstr(s_nss, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
	s_nss.add_constraints(nomatch_ss != 0)
	nose.tools.assert_false(s_nss.satisfiable())

def test_strstr_inconsistency(n=2):
	l.info("symbolic haystack, symbolic needle")
	s = SimState(arch="AMD64", mode="symbolic")
	s['libc'].max_str_symbolic_bytes = n
	addr_haystack = se.BitVecVal(0x10, 64)
	addr_needle = se.BitVecVal(0xb0, 64)
	#len_needle = strlen(s, inline=True, arguments=[addr_needle])

	ss_res = strstr(s, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
	ss_val = s.expr_value(ss_res)

	nose.tools.assert_false(ss_val.is_unique())
	nose.tools.assert_equal(len(ss_val.any_n(100)), s['libc'].max_str_symbolic_bytes)

	s.add_constraints(ss_res != 0)
	ss2 = strstr(s, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
	s.add_constraints(ss2 == 0)
	print s.expr_value(ss_res).any_n(10)
	print s.expr_value(ss2).any_n(10)
	nose.tools.assert_false(s.satisfiable())

def test_strncpy():
	l.info("concrete src, concrete dst, concrete len")
	dst = se.BitVecVal(0x41414100, 32)
	dst_addr = se.BitVecVal(0x1000, 64)
	src = se.BitVecVal(0x42420000, 32)
	src_addr = se.BitVecVal(0x2000, 64)

	l.debug("... full copy")
	s = SimState(arch="AMD64", mode="symbolic")
	s.store_mem(dst_addr, dst, 4)
	s.store_mem(src_addr, src, 4)
	strncpy(s, inline=True, arguments=[dst_addr, src_addr, se.BitVecVal(3, 64)])
	new_dst = s.mem_value(dst_addr, 4, endness='Iend_BE')
	nose.tools.assert_equal(new_dst.any_str(), "BB\x00\x00")

	l.debug("... partial copy")
	s = SimState(arch="AMD64", mode="symbolic")
	s.store_mem(dst_addr, dst, 4)
	s.store_mem(src_addr, src, 4)
	strncpy(s, inline=True, arguments=[dst_addr, src_addr, se.BitVecVal(2, 64)])
	new_dst = s.mem_value(dst_addr, 4, endness='Iend_BE')
	nose.tools.assert_equal(new_dst.any_str(), "BBA\x00")

	l.info("symbolic src, concrete dst, concrete len")
	s = SimState(arch="AMD64", mode="symbolic")
	dst = se.BitVecVal(0x41414100, 32)
	dst_addr = se.BitVecVal(0x1000, 64)
	src = s.new_symbolic("src", 32)
	src_addr = se.BitVecVal(0x2000, 64)

	s.store_mem(dst_addr, dst, 4)
	s.store_mem(src_addr, src, 4)

	# make sure it copies it all
	s.add_constraints(strlen(s, inline=True, arguments=[src_addr]).ret_expr == 2)
	strncpy(s, inline=True, arguments=[dst_addr, src_addr, se.BitVecVal(3, 64)])
	c = s.expr_value(strcmp(s, inline=True, arguments=[dst_addr, src_addr]).ret_expr)
	nose.tools.assert_items_equal(c.any_n(10), [0])

	l.info("symbolic src, concrete dst, symbolic len")
	s = SimState(arch="AMD64", mode="symbolic")
	dst = se.BitVecVal(0x41414100, 32)
	dst_addr = se.BitVecVal(0x1000, 64)
	src = s.new_symbolic("src", 32)
	src_addr = se.BitVecVal(0x2000, 64)
	maxlen = s.new_symbolic("len", 32)

	s.store_mem(dst_addr, dst, 4)
	s.store_mem(src_addr, src, 4)

	# make sure it copies it all
	s.add_constraints(strlen(s, inline=True, arguments=[src_addr]).ret_expr == 2)
	strncpy(s, inline=True, arguments=[dst_addr, src_addr, maxlen])
	c = strcmp(s, inline=True, arguments=[dst_addr, src_addr]).ret_expr

	s_match = s.copy()
	s_match.add_constraints(c == 0)
	nose.tools.assert_equals(s_match.expr_value(maxlen).min(), 3)

	s_nomatch = s.copy()
	s_nomatch.add_constraints(c != 0)
	nose.tools.assert_equals(s_nomatch.expr_value(maxlen).max(), 2)

def test_strcpy():
	l.info("concrete src, concrete dst, concrete len")
	dst = se.BitVecVal(0x41414100, 32)
	dst_addr = se.BitVecVal(0x1000, 64)
	src = se.BitVecVal(0x42420000, 32)
	src_addr = se.BitVecVal(0x2000, 64)

	l.debug("... full copy")
	s = SimState(arch="AMD64", mode="symbolic")
	s.store_mem(dst_addr, dst, 4)
	s.store_mem(src_addr, src, 4)
	strcpy(s, inline=True, arguments=[dst_addr, src_addr])
	new_dst = s.mem_value(dst_addr, 4, endness='Iend_BE')
	nose.tools.assert_equal(new_dst.any_str(), "BB\x00\x00")

	l.info("symbolic src, concrete dst, concrete len")
	dst = se.BitVecVal(0x41414100, 32)
	dst_addr = se.BitVecVal(0x1000, 64)
	src = s.new_symbolic("src", 32)
	src_addr = se.BitVecVal(0x2000, 64)

	s = SimState(arch="AMD64", mode="symbolic")
	s.store_mem(dst_addr, dst, 4)
	s.store_mem(src_addr, src, 4)

	strcpy(s, inline=True, arguments=[dst_addr, src_addr])
	c = s.expr_value(strcmp(s, inline=True, arguments=[dst_addr, src_addr]).ret_expr)
	nose.tools.assert_items_equal(c.any_n(10), [0])
	nose.tools.assert_true(s.mem_value(dst_addr, 4, endness='Iend_BE').is_solution(0x42434400))
	nose.tools.assert_true(s.mem_value(dst_addr, 4, endness='Iend_BE').is_solution(0x42434445))
	nose.tools.assert_true(s.mem_value(dst_addr, 4, endness='Iend_BE').is_solution(0x00414100))
	nose.tools.assert_false(s.mem_value(dst_addr, 4, endness='Iend_BE').is_solution(0x00010203))

def test_sprintf():
	l.info("concrete src, concrete dst, concrete len")
	s = SimState(mode="symbolic", arch="PPC32")
	format_str = se.BitVecVal(0x25640000, 32)
	format_addr = se.BitVecVal(0x2000, 32)
	#dst = se.BitVecVal("destination", 128)
	dst_addr = se.BitVecVal(0x1000, 32)
	arg = s.new_symbolic("some_number", 32)

	s.store_mem(format_addr, format_str)

	sprintf(s, inline=True, arguments=[dst_addr, format_addr, arg])

	print "CHECKING 2"
	for i in range(9):
		j = random.randint(10**i, 10**(i+1))
		s2 = s.copy()
		s2.add_constraints(arg == j)
		#print s2.mem_value(dst_addr, i+2).any_n_str(2), repr("%d\x00" % j)
		nose.tools.assert_equal(s2.mem_value(dst_addr, i+2).any_n_str(2), ["%d\x00" % j])

	s2 = s.copy()
	s2.add_constraints(arg == 0)
	#print s2.mem_value(dst_addr, 2).any_n_str(2), repr("%d\x00" % 0)
	nose.tools.assert_equal(s2.mem_value(dst_addr, 2).any_n_str(2), ["%d\x00" % 0])

def test_memset():
	l.info("concrete src, concrete dst, concrete len")
	s = SimState(arch="PPC32", mode="symbolic")
	dst = se.BitVecVal(0, 128)
	dst_addr = se.BitVecVal(0x1000, 32)
	char = se.BitVecVal(0x00000041, 32)
	char2 = se.BitVecVal(0x50505050, 32)
	length = s.new_symbolic("some_length", 32)

	s.store_mem(dst_addr, dst, 4, )
	memset(s, inline=True, arguments=[dst_addr, char, se.BitVecVal(3, 32)])
	nose.tools.assert_equals(s.mem_value(dst_addr, 4).any(), 0x41414100)

	l.debug("Symbolic length")
	s = SimState(arch="PPC32", mode="symbolic")
	s.store_mem(dst_addr, dst, 4, )
	memset(s, inline=True, arguments=[dst_addr, char2, length])

	l.debug("Trying 2")
	s_two = s.copy()
	s_two.add_constraints(length == 2)
	nose.tools.assert_equals(s_two.mem_value(dst_addr, 4).any(), 0x50500000)

	l.debug("Trying 0")
	s_zero = s.copy()
	s_zero.add_constraints(length == 0)
	nose.tools.assert_equals(s_zero.mem_value(dst_addr, 4).any(), 0x00000000)

	l.debug("Trying 5")
	s_five = s.copy()
	s_five.add_constraints(length == 5)
	nose.tools.assert_equals(s_five.mem_value(dst_addr, 6).any(), 0x505050505000)

def test_concretization():
	s = SimState(arch="AMD64", mode="symbolic")
	dst = se.BitVecVal(0x41424300, 32)
	dst_addr = se.BitVecVal(0x1000, 64)
	s.store_mem(dst_addr, dst, 4)

	print "MEM KEYS", s.memory.mem.keys()
	print "REG KEYS", s.registers.mem.keys()

	print "TO NATIVE..."
	s.set_native(True)
	print "... done"

	vv = s.native_env.vexecute(pyvex.IRExpr.Load("Iend_BE", "Ity_I32", pyvex.IRExpr.Const(pyvex.IRConst.U64(0x1000))))
	nose.tools.assert_equals(vv.str[:4], 'ABC\x00')
	s.native_env.vexecute(pyvex.IRSB(bytes='\xb8\x41\x42\x43\x44'))

	#import IPython; IPython.embed()
	print "FROM NATIVE..."
	s.set_native(False)
	print "... done"

	nose.tools.assert_equals(s.reg_value(16).any(), 0x44434241)
	print "YEAH"


if __name__ == '__main__':
	#test_memset()
	#test_sprintf()
	#test_state_merge()
	#test_inline_strncmp()
	#test_memory()
	#test_inline_strlen()
	#test_inline_strcmp()
	#test_strcpy()
	#test_strncpy()
	#test_strstr_inconsistency(2)
	#test_strstr_inconsistency(3)
	#test_inline_strstr()
	test_concretization()
