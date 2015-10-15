import nose
import random

from simuvex import SimState, SimProcedures

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
getc = SimProcedures['libc.so.6']['_IO_getc']
fgetc = SimProcedures['libc.so.6']['fgetc']
getchar = SimProcedures['libc.so.6']['getchar']


import logging
l = logging.getLogger('simuvex.test.string')

#@nose.tools.timed(10)
def test_inline_strlen():
    s = SimState(arch="AMD64", mode="symbolic")

    l.info("fully concrete string")
    a_str = s.se.BVV(0x41414100, 32)
    a_addr = s.se.BVV(0x10, 64)
    s.memory.store(a_addr, a_str, endness="Iend_BE")
    a_len = SimProcedures['libc.so.6']['strlen'](s, inline=True, arguments=[a_addr]).ret_expr
    nose.tools.assert_true(s.se.unique(a_len))
    nose.tools.assert_equal(s.se.any_int(a_len), 3)

    l.info("concrete-terminated string")
    b_str = s.se.Concat(s.se.BVS("mystring", 24), s.se.BVV(0, 8))
    b_addr = s.se.BVV(0x20, 64)
    s.memory.store(b_addr, b_str, endness="Iend_BE")
    b_len = SimProcedures['libc.so.6']['strlen'](s, inline=True, arguments=[b_addr]).ret_expr
    nose.tools.assert_equal(s.se.max_int(b_len), 3)
    nose.tools.assert_items_equal(s.se.any_n_int(b_len, 10), (0,1,2,3))

    l.info("fully unconstrained")
    u_addr = s.se.BVV(0x50, 64)
    u_len_sp = SimProcedures['libc.so.6']['strlen'](s, inline=True, arguments=[u_addr])
    u_len = u_len_sp.ret_expr
    nose.tools.assert_equal(len(s.se.any_n_int(u_len, 100)), s.libc.buf_symbolic_bytes)
    nose.tools.assert_equal(s.se.max_int(u_len), s.libc.buf_symbolic_bytes-1)

    #print u_len_sp.se.maximum_null

    #s.add_constraints(u_len < 16)

    nose.tools.assert_equal(s.se.any_n_int(s.memory.load(0x50 + u_len, 1), 300), [0])

    #
    # This tests if a strlen can influence a symbolic str.
    #
    l.info("Trying to influence length.")
    s = SimState(arch="AMD64", mode="symbolic")
    str_c = s.se.BVS("some_string", 8*16)
    c_addr = s.se.BVV(0x10, 64)
    s.memory.store(c_addr, str_c, endness='Iend_BE')
    c_len = SimProcedures['libc.so.6']['strlen'](s, inline=True, arguments=[c_addr]).ret_expr
    nose.tools.assert_equal(len(s.se.any_n_int(c_len, 100)), s.libc.buf_symbolic_bytes)
    nose.tools.assert_equal(s.se.max_int(c_len), s.libc.buf_symbolic_bytes-1)

    one_s = s.copy()
    one_s.add_constraints(c_len == 1)
    nose.tools.assert_equal(one_s.se.any_str(str_c).index('\x00'), 1)
    str_test = one_s.memory.load(c_addr, 2, endness='Iend_BE')
    nose.tools.assert_equal(len(one_s.se.any_n_str(str_test, 300)), 255)

    for i in range(16):
        test_s = s.copy()
        test_s.add_constraints(c_len == i)
        str_test = test_s.memory.load(c_addr, i + 1, endness='Iend_BE')
        nose.tools.assert_equal(test_s.se.any_str(str_test).index('\x00'), i)
        for j in range(i):
            nose.tools.assert_false(test_s.se.unique(test_s.memory.load(c_addr+j, 1)))

#@nose.tools.timed(10)
def test_inline_strcmp():
    s = SimState(arch="AMD64", mode="symbolic")
    str_a = s.se.BVV(0x41414100, 32)
    str_b = s.se.BVS("mystring", 32)

    a_addr = s.se.BVV(0x10, 64)
    b_addr = s.se.BVV(0xb0, 64)

    s.memory.store(a_addr, str_a, endness="Iend_BE")
    s.memory.store(b_addr, str_b, endness="Iend_BE")

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
    ncmpres = SimProcedures['libc.so.6']['strncmp'](s_ncmp, inline=True, arguments=[a_addr, b_addr, s.se.BVV(2, s.arch.bits)]).ret_expr
    s_match = s_ncmp.copy()
    s_nomatch = s_ncmp.copy()
    s_match.add_constraints(ncmpres == 0)
    s_nomatch.add_constraints(ncmpres != 0)

    nose.tools.assert_false(s_match.se.unique(str_b))
    nose.tools.assert_true(s_match.se.unique(s_match.memory.load(b_addr, 2)))
    nose.tools.assert_equal(len(s_match.se.any_n_int(s_match.memory.load(b_addr, 3), 300)), 256)
    nose.tools.assert_false(s_nomatch.se.unique(str_b))

    l.info("concrete a, symbolic b")
    s = SimState(arch="AMD64", mode="symbolic")
    str_a = s.se.BVV(0x41424300, 32)
    str_b = s.se.BVS("mystring", 32)
    a_addr = s.se.BVV(0x10, 64)
    b_addr = s.se.BVV(0xb0, 64)
    s.memory.store(a_addr, str_a, endness="Iend_BE")
    s.memory.store(b_addr, str_b, endness="Iend_BE")

    s_cmp = s.copy()
    cmpres = strncmp(s_cmp, inline=True, arguments=[a_addr, b_addr, s.se.BVV(2, s_cmp.arch.bits)]).ret_expr
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
    a_addr = s.se.BVV(0x10, 64)
    b_addr = s.se.BVV(0xb0, 64)

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
    left = s.se.BVS("left", 32)
    left_addr = s.se.BVV(0x1000, 64)
    right = s.se.BVS("right", 32)
    right_addr = s.se.BVV(0x2000, 64)
    maxlen = s.se.BVS("len", 64)

    s.memory.store(left_addr, left)
    s.memory.store(right_addr, right)

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
    left = s.se.BVS("left", 32)
    left_addr = s.se.BVV(0x1000, 64)
    right = s.se.BVS("right", 32)
    right_addr = s.se.BVV(0x2000, 64)
    maxlen = s.se.BVS("len", 64)
    left_len = strlen(s, inline=True, arguments=[left_addr]).ret_expr
    right_len = strlen(s, inline=True, arguments=[right_addr]).ret_expr
    c = strncmp(s, inline=True, arguments=[left_addr, right_addr, maxlen]).ret_expr

    s.add_constraints(right_len == 0)
    s.add_constraints(left_len == 0)
    #s.add_constraints(c == 0)
    s.add_constraints(maxlen == 0)
    nose.tools.assert_true(s.satisfiable())

#@nose.tools.timed(10)
def broken_inline_strstr():
    l.info("concrete haystack and needle")
    s = SimState(arch="AMD64", mode="symbolic")
    str_haystack = s.se.BVV(0x41424300, 32)
    str_needle = s.se.BVV(0x42430000, 32)
    addr_haystack = s.se.BVV(0x10, 64)
    addr_needle = s.se.BVV(0xb0, 64)
    s.memory.store(addr_haystack, str_haystack, endness="Iend_BE")
    s.memory.store(addr_needle, str_needle, endness="Iend_BE")

    ss_res = strstr(s, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
    nose.tools.assert_true(s.se.unique(ss_res))
    nose.tools.assert_equal(s.se.any_int(ss_res), 0x11)

    l.info("concrete haystack, symbolic needle")
    s = SimState(arch="AMD64", mode="symbolic")
    str_haystack = s.se.BVV(0x41424300, 32)
    str_needle = s.se.BVS("wtf", 32)
    addr_haystack = s.se.BVV(0x10, 64)
    addr_needle = s.se.BVV(0xb0, 64)
    s.memory.store(addr_haystack, str_haystack, endness="Iend_BE")
    s.memory.store(addr_needle, str_needle, endness="Iend_BE")

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
    s.libc.buf_symbolic_bytes = 5
    addr_haystack = s.se.BVV(0x10, 64)
    addr_needle = s.se.BVV(0xb0, 64)
    len_needle = strlen(s, inline=True, arguments=[addr_needle])

    ss_res = strstr(s, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
    nose.tools.assert_false(s.se.unique(ss_res))
    nose.tools.assert_equal(len(s.se.any_n_int(ss_res, 100)), s.libc.buf_symbolic_bytes)

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
    s.libc.buf_symbolic_bytes = n
    addr_haystack = s.se.BVV(0x10, 64)
    addr_needle = s.se.BVV(0xb0, 64)
    #len_needle = strlen(s, inline=True, arguments=[addr_needle])

    ss_res = strstr(s, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr

    #slh_res = strlen(s, inline=True, arguments=[addr_haystack]).ret_expr
    #sln_res = strlen(s, inline=True, arguments=[addr_needle]).ret_expr
    #print "LENH:", s.se.any_n_int(slh_res, 100)
    #print "LENN:", s.se.any_n_int(sln_res, 100)

    nose.tools.assert_false(s.se.unique(ss_res))
    nose.tools.assert_items_equal(s.se.any_n_int(ss_res, 100), [0] + range(0x10, 0x10 + s.libc.buf_symbolic_bytes - 1))

    s.add_constraints(ss_res != 0)
    ss2 = strstr(s, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
    s.add_constraints(ss2 == 0)
    nose.tools.assert_false(s.satisfiable())

#@nose.tools.timed(10)
def test_memcpy():
    l.info("concrete src, concrete dst, concrete len")
    l.debug("... full copy")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BVV(0x41414141, 32)
    dst_addr = s.se.BVV(0x1000, 64)
    src = s.se.BVV(0x42424242, 32)
    src_addr = s.se.BVV(0x2000, 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    memcpy(s, inline=True, arguments=[dst_addr, src_addr, s.se.BVV(4, 64)])
    new_dst = s.memory.load(dst_addr, 4, endness='Iend_BE')
    nose.tools.assert_equal(s.se.any_n_str(new_dst, 2), [ "BBBB" ])

    l.debug("... partial copy")
    s = SimState(arch="AMD64", mode="symbolic")
    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    memcpy(s, inline=True, arguments=[dst_addr, src_addr, s.se.BVV(2, 64)])
    new_dst = s.memory.load(dst_addr, 4, endness='Iend_BE')
    nose.tools.assert_equal(s.se.any_n_str(new_dst, 2), [ "BBAA" ])

    l.info("symbolic src, concrete dst, concrete len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BVV(0x41414141, 32)
    dst_addr = s.se.BVV(0x1000, 64)
    src = s.se.BVS("src", 32)
    src_addr = s.se.BVV(0x2000, 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)

    # make sure it copies it all
    memcpy(s, inline=True, arguments=[dst_addr, src_addr, s.se.BVV(4, 64)])
    nose.tools.assert_true(s.satisfiable())
    s.add_constraints(src != s.memory.load(dst_addr, 4))
    nose.tools.assert_false(s.satisfiable())

    l.info("symbolic src, concrete dst, symbolic len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BVV(0x41414141, 32)
    dst_addr = s.se.BVV(0x1000, 64)
    src = s.se.BVS("src", 32)
    src_addr = s.se.BVV(0x2000, 64)
    cpylen = s.se.BVS("len", 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    memcpy(s, inline=True, arguments=[dst_addr, src_addr, cpylen])
    result = s.memory.load(dst_addr, 4, endness='Iend_BE')

    # make sure it copies it all
    s1 = s.copy()
    s1.add_constraints(cpylen == 1)
    nose.tools.assert_true(s1.se.unique(s1.memory.load(dst_addr+1, 3)))
    nose.tools.assert_equals(len(s1.se.any_n_int(s1.memory.load(dst_addr, 1), 300)), 256)

    s2 = s.copy()
    s2.add_constraints(cpylen == 2)
    nose.tools.assert_equals(len(s2.se.any_n_int(result[31:24], 300)), 256)
    nose.tools.assert_equals(len(s2.se.any_n_int(result[23:16], 300)), 256)
    nose.tools.assert_equals(s2.se.any_n_str(result[15:0], 300), [ 'AA' ])

    l.info("concrete src, concrete dst, symbolic len")
    dst = s2.se.BVV(0x41414141, 32)
    dst_addr = s2.se.BVV(0x1000, 64)
    src = s2.se.BVV(0x42424242, 32)
    src_addr = s2.se.BVV(0x2000, 64)

    s = SimState(arch="AMD64", mode="symbolic")
    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    cpylen = s.se.BVS("len", 64)

    s.add_constraints(s.se.ULE(cpylen, 4))
    memcpy(s, inline=True, arguments=[dst_addr, src_addr, cpylen])
    new_dst = s.memory.load(dst_addr, 4, endness='Iend_BE')
    nose.tools.assert_items_equal(s.se.any_n_str(new_dst, 300), [ 'AAAA', 'BAAA', 'BBAA', 'BBBA', 'BBBB' ])

#@nose.tools.timed(10)
def test_memcmp():
    l.info("concrete src, concrete dst, concrete len")

    l.debug("... full cmp")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BVV(0x41414141, 32)
    dst_addr = s.se.BVV(0x1000, 64)
    src = s.se.BVV(0x42424242, 32)
    src_addr = s.se.BVV(0x2000, 64)
    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    r = memcmp(s, inline=True, arguments=[dst_addr, src_addr, s.se.BVV(4, 64)]).ret_expr
    nose.tools.assert_true(s.satisfiable())

    s_pos = s.copy()
    s_pos.add_constraints(r.SGE(0))
    nose.tools.assert_false(s_pos.satisfiable())

    s_neg = s.copy()
    s_neg.add_constraints(r.SLT(0))
    nose.tools.assert_true(s_neg.satisfiable())

    l.debug("... zero cmp")
    s = SimState(arch="AMD64", mode="symbolic")
    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    r = memcmp(s, inline=True, arguments=[dst_addr, src_addr, s.se.BVV(0, 64)]).ret_expr
    nose.tools.assert_equals(s.se.any_n_int(r, 2), [ 0 ])

    l.info("symbolic src, concrete dst, concrete len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BVV(0x41414141, 32)
    dst_addr = s.se.BVV(0x1000, 64)
    src = s.se.BVS("src", 32)

    src_addr = s.se.BVV(0x2000, 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)

    # make sure it copies it all
    r = memcmp(s, inline=True, arguments=[dst_addr, src_addr, s.se.BVV(4, 64)]).ret_expr

    s_match = s.copy()
    s_match.add_constraints(r == 0)
    m = s_match.memory.load(src_addr, 4)
    nose.tools.assert_equal(s_match.se.any_n_int(m, 2), [0x41414141])

    s_nomatch = s.copy()
    s_nomatch.add_constraints(r != 0)
    m = s_nomatch.memory.load(src_addr, 4)
    nose.tools.assert_false(s_nomatch.se.solution(m, 0x41414141))

    l.info("symbolic src, concrete dst, symbolic len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BVV(0x41414141, 32)
    dst_addr = s.se.BVV(0x1000, 64)
    src = s.se.BVS("src", 32)
    src_addr = s.se.BVV(0x2000, 64)
    cmplen = s.se.BVS("len", 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
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
    nose.tools.assert_equals(s2.se.any_n_int(s2.memory.load(src_addr, 2), 2), [ 0x4141 ])
    nose.tools.assert_false(s2.se.unique(s2.memory.load(src_addr, 3)))

    s2u = s.copy()
    s2u.add_constraints(cmplen == 2)
    s2u.add_constraints(r == 1)
    nose.tools.assert_false(s2u.se.solution(s2u.memory.load(src_addr, 2), 0x4141))

#@nose.tools.timed(10)
def test_strncpy():
    l.info("concrete src, concrete dst, concrete len")
    l.debug("... full copy")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BVV(0x41414100, 32)
    dst_addr = s.se.BVV(0x1000, 64)
    src = s.se.BVV(0x42420000, 32)
    src_addr = s.se.BVV(0x2000, 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    strncpy(s, inline=True, arguments=[dst_addr, src_addr, s.se.BVV(3, 64)])
    new_dst = s.memory.load(dst_addr, 4, endness='Iend_BE')
    nose.tools.assert_equal(s.se.any_str(new_dst), "BB\x00\x00")

    l.debug("... partial copy")
    s = SimState(arch="AMD64", mode="symbolic")
    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    strncpy(s, inline=True, arguments=[dst_addr, src_addr, s.se.BVV(2, 64)])
    new_dst = s.memory.load(dst_addr, 4, endness='Iend_BE')
    nose.tools.assert_equal(s.se.any_n_str(new_dst, 2), [ "BBA\x00" ])

    l.info("symbolic src, concrete dst, concrete len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BVV(0x41414100, 32)
    dst_addr = s.se.BVV(0x1000, 64)
    src = s.se.BVS("src", 32)
    src_addr = s.se.BVV(0x2000, 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)

    # make sure it copies it all
    s.add_constraints(strlen(s, inline=True, arguments=[src_addr]).ret_expr == 2)

    # sanity check
    s_false = s.copy()
    s_false.add_constraints(strlen(s_false, inline=True, arguments=[src_addr]).ret_expr == 3)
    nose.tools.assert_false(s_false.satisfiable())

    strncpy(s, inline=True, arguments=[dst_addr, src_addr, 3])
    nose.tools.assert_true(s.satisfiable())
    c = strcmp(s, inline=True, arguments=[dst_addr, src_addr]).ret_expr

    nose.tools.assert_items_equal(s.se.any_n_int(c, 10), [0])

    l.info("symbolic src, concrete dst, symbolic len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BVV(0x41414100, 32)
    dst_addr = s.se.BVV(0x1000, 64)
    src = s.se.BVS("src", 32)
    src_addr = s.se.BVV(0x2000, 64)
    maxlen = s.se.BVS("len", 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)

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

    dst = s.se.BVV(0x41414100, 32)
    dst_addr = s.se.BVV(0x1000, 64)
    src = s.se.BVV(0x42420000, 32)
    src_addr = s.se.BVV(0x2000, 64)
    maxlen = s.se.BVS("len", 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    strncpy(s, inline=True, arguments=[dst_addr, src_addr, maxlen])
    r = s.memory.load(dst_addr, 4, endness='Iend_BE')
    #print repr(r.se.any_n_str(10))
    nose.tools.assert_items_equal(s.se.any_n_str(r, 10), [ "AAA\x00", 'BAA\x00', 'BBA\x00', 'BB\x00\x00' ] )


#@nose.tools.timed(10)
def test_strcpy():
    l.info("concrete src, concrete dst")

    l.debug("... full copy")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.se.BVV(0x41414100, 32)
    dst_addr = s.se.BVV(0x1000, 64)
    src = s.se.BVV(0x42420000, 32)
    src_addr = s.se.BVV(0x2000, 64)
    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    strcpy(s, inline=True, arguments=[dst_addr, src_addr])
    new_dst = s.memory.load(dst_addr, 4, endness='Iend_BE')
    nose.tools.assert_equal(s.se.any_str(new_dst), "BB\x00\x00")



    l.info("symbolic src, concrete dst")
    dst = s.se.BVV(0x41414100, 32)
    dst_addr = s.se.BVV(0x1000, 64)
    src = s.se.BVS("src", 32)
    src_addr = s.se.BVV(0x2000, 64)

    s = SimState(arch="AMD64", mode="symbolic")
    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)

    ln = strlen(s, inline=True, arguments=[src_addr]).ret_expr

    strcpy(s, inline=True, arguments=[dst_addr, src_addr])

    cm = strcmp(s, inline=True, arguments=[dst_addr, src_addr]).ret_expr

    s.add_constraints(cm == 0)

    s.add_constraints(ln == 15)
    #readsize = 16
    #both_strs = s.se.Concat(*[ s.memory.load(dst_addr, readsize, endness='Iend_BE'), s.memory.load(src_addr, readsize, endness='Iend_BE') ])
    #for i in s.se.any_n_str(both_strs, 50):

    #print c.se.any_n_int(10)
    #nose.tools.assert_items_equal(c.se.any_n_int(10), [0])
    #nose.tools.assert_true(s.se.solution(s.memory.load(dst_addr, 4, endness='Iend_BE'), 0x42434400))
    #nose.tools.assert_true(s.se.solution(s.memory.load(dst_addr, 4, endness='Iend_BE'), 0x42434445))
    #nose.tools.assert_true(s.se.solution(s.memory.load(dst_addr, 4, endness='Iend_BE'), 0x00414100))
    #nose.tools.assert_false(s.se.solution(s.memory.load(dst_addr, 4, endness='Iend_BE'), 0x00010203))

#@nose.tools.timed(10)
def broken_sprintf():
    l.info("concrete src, concrete dst, concrete len")
    s = SimState(mode="symbolic", arch="PPC32")
    format_str = s.se.BVV(0x25640000, 32)
    format_addr = s.se.BVV(0x2000, 32)
    #dst = s.se.BVV("destination", 128)
    dst_addr = s.se.BVV(0x1000, 32)
    arg = s.se.BVS("some_number", 32)

    s.memory.store(format_addr, format_str)

    sprintf(s, inline=True, arguments=[dst_addr, format_addr, arg])

    for i in range(9):
        j = random.randint(10**i, 10**(i+1))
        s2 = s.copy()
        s2.add_constraints(arg == j)
        #print s2.se.any_n_str(s2.memory.load(dst_addr, i+2), 2), repr("%d\x00" % j)
        nose.tools.assert_equal(s2.se.any_n_str(s2.memory.load(dst_addr, i+2), 2), ["%d\x00" % j])

    s2 = s.copy()
    s2.add_constraints(arg == 0)
    #print s2.se.any_n_str(s2.memory.load(dst_addr, 2), 2), repr("%d\x00" % 0)
    nose.tools.assert_equal(s2.se.any_n_str(s2.memory.load(dst_addr, 2), 2), ["%d\x00" % 0])

#@nose.tools.timed(10)
def test_memset():
    l.info("concrete src, concrete dst, concrete len")
    s = SimState(arch="PPC32", mode="symbolic")
    dst = s.se.BVV(0, 128)
    dst_addr = s.se.BVV(0x1000, 32)
    char = s.se.BVV(0x00000041, 32)
    char2 = s.se.BVV(0x50505050, 32)
    length = s.se.BVS("some_length", 32)

    s.memory.store(dst_addr, dst)
    memset(s, inline=True, arguments=[dst_addr, char, s.se.BVV(3, 32)])
    nose.tools.assert_equals(s.se.any_int(s.memory.load(dst_addr, 4)), 0x41414100)

    l.debug("Symbolic length")
    s = SimState(arch="PPC32", mode="symbolic")
    s.memory.store(dst_addr, dst)
    length = s.se.BVS("some_length", 32)
    memset(s, inline=True, arguments=[dst_addr, char2, length])

    l.debug("Trying 2")
    s_two = s.copy()
    s_two.add_constraints(length == 2)
    nose.tools.assert_equals(s_two.se.any_int(s_two.memory.load(dst_addr, 4)), 0x50500000)

    l.debug("Trying 0")
    s_zero = s.copy()
    s_zero.add_constraints(length == 0)
    nose.tools.assert_equals(s_zero.se.any_int(s_zero.memory.load(dst_addr, 4)), 0x00000000)

    l.debug("Trying 5")
    s_five = s.copy()
    s_five.add_constraints(length == 5)
    nose.tools.assert_equals(s_five.se.any_int(s_five.memory.load(dst_addr, 6)), 0x505050505000)

#@nose.tools.timed(10)
def test_strchr():
    l.info("concrete haystack and needle")
    s = SimState(arch="AMD64", mode="symbolic")
    str_haystack = s.se.BVV(0x41424300, 32)
    str_needle = s.se.BVV(0x42, 64)
    addr_haystack = s.se.BVV(0x10, 64)
    s.memory.store(addr_haystack, str_haystack, endness="Iend_BE")

    ss_res = strchr(s, inline=True, arguments=[addr_haystack, str_needle]).ret_expr
    nose.tools.assert_true(s.se.unique(ss_res))
    nose.tools.assert_equal(s.se.any_int(ss_res), 0x11)

    l.info("concrete haystack, symbolic needle")
    s = SimState(arch="AMD64", mode="symbolic")
    str_haystack = s.se.BVV(0x41424300, 32)
    str_needle = s.se.BVS("wtf", 64)
    chr_needle = str_needle[7:0]
    addr_haystack = s.se.BVV(0x10, 64)
    s.memory.store(addr_haystack, str_haystack, endness="Iend_BE")

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

    s_match.memory.store(ss_res, s_match.se.BVV(0x44, 8))
    nose.tools.assert_items_equal(s_match.se.any_n_int(s_match.memory.load(0x10, 1), 300), [ 0x41, 0x44 ])
    nose.tools.assert_items_equal(s_match.se.any_n_int(s_match.memory.load(0x11, 1), 300), [ 0x42, 0x44 ])
    nose.tools.assert_items_equal(s_match.se.any_n_int(s_match.memory.load(0x12, 1), 300), [ 0x43, 0x44 ])

    return

    #l.info("symbolic haystack, symbolic needle")
    #s = SimState(arch="AMD64", mode="symbolic")
    #s.libc.buf_symbolic_bytes = 5
    #addr_haystack = s.se.BVV(0x10, 64)
    #addr_needle = s.se.BVV(0xb0, 64)
    #len_needle = strlen(s, inline=True, arguments=[addr_needle])

    #ss_res = strstr(s, inline=True, arguments=[addr_haystack, addr_needle]).ret_expr
    #ss_val = s.expr_value(ss_res)

    #nose.tools.assert_false(ss_val.is_unique())
    #nose.tools.assert_equal(len(ss_val.se.any_n_int(100)), s.libc.buf_symbolic_bytes)

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

#@nose.tools.timed(10)
def broken_strtok_r():
    l.debug("CONCRETE MODE")
    s = SimState(arch='AMD64', mode='symbolic')
    s.memory.store(100, s.se.BVV(0x4141414241414241424300, 88), endness='Iend_BE')
    s.memory.store(200, s.se.BVV(0x4200, 16), endness='Iend_BE')
    str_ptr = s.se.BVV(100, s.arch.bits)
    delim_ptr = s.se.BVV(200, s.arch.bits)
    state_ptr = s.se.BVV(300, s.arch.bits)

    st1 = strtok_r(s, inline=True, arguments=[str_ptr, delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st1.ret_expr, 10), [104])
    nose.tools.assert_equal(s.se.any_n_int(s.memory.load(st1.ret_expr-1, 1), 10), [0])
    nose.tools.assert_equal(s.se.any_n_int(s.memory.load(200, 2), 10), [0x4200])

    st2 = strtok_r(s, inline=True, arguments=[s.se.BVV(0, s.arch.bits), delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st2.ret_expr, 10), [107])
    nose.tools.assert_equal(s.se.any_n_int(s.memory.load(st2.ret_expr-1, 1), 10), [0])

    st3 = strtok_r(s, inline=True, arguments=[s.se.BVV(0, s.arch.bits), delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st3.ret_expr, 10), [109])
    nose.tools.assert_equal(s.se.any_n_int(s.memory.load(st3.ret_expr-1, 1), 10), [0])

    st4 = strtok_r(s, inline=True, arguments=[s.se.BVV(0, s.arch.bits), delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st4.ret_expr, 10), [0])
    nose.tools.assert_equal(s.se.any_n_int(s.memory.load(300, s.arch.bytes, endness=s.arch.memory_endness), 10), [109])

    st5 = strtok_r(s, inline=True, arguments=[s.se.BVV(0, s.arch.bits), delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st5.ret_expr, 10), [0])
    nose.tools.assert_equal(s.se.any_n_int(s.memory.load(300, s.arch.bytes, endness=s.arch.memory_endness), 10), [109])

    s.memory.store(1000, s.se.BVV(0x4141414241414241424300, 88), endness='Iend_BE')
    s.memory.store(2000, s.se.BVV(0x4200, 16), endness='Iend_BE')
    str_ptr = s.se.BVV(1000, s.arch.bits)
    delim_ptr = s.se.BVV(2000, s.arch.bits)
    state_ptr = s.se.BVV(3000, s.arch.bits)

    st1 = strtok_r(s, inline=True, arguments=[str_ptr, delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st1.ret_expr, 10), [1004])
    nose.tools.assert_equal(s.se.any_n_int(s.memory.load(st1.ret_expr-1, 1), 10), [0])
    nose.tools.assert_equal(s.se.any_n_int(s.memory.load(2000, 2), 10), [0x4200])

    st2 = strtok_r(s, inline=True, arguments=[s.se.BVV(0, s.arch.bits), delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st2.ret_expr, 10), [1007])
    nose.tools.assert_equal(s.se.any_n_int(s.memory.load(st2.ret_expr-1, 1), 10), [0])

    st3 = strtok_r(s, inline=True, arguments=[s.se.BVV(0, s.arch.bits), delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st3.ret_expr, 10), [1009])
    nose.tools.assert_equal(s.se.any_n_int(s.memory.load(st3.ret_expr-1, 1), 10), [0])

    st4 = strtok_r(s, inline=True, arguments=[s.se.BVV(0, s.arch.bits), delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st4.ret_expr, 10), [0])
    nose.tools.assert_equal(s.se.any_n_int(s.memory.load(3000, s.arch.bytes, endness=s.arch.memory_endness), 10), [1009])

    st5 = strtok_r(s, inline=True, arguments=[s.se.BVV(0, s.arch.bits), delim_ptr, state_ptr])
    nose.tools.assert_equal(s.se.any_n_int(st5.ret_expr, 10), [0])
    nose.tools.assert_equal(s.se.any_n_int(s.memory.load(3000, s.arch.bytes, endness=s.arch.memory_endness), 10), [1009])

    print "LIGHT FULLY SYMBOLIC TEST"
    s = SimState(arch='AMD64', mode='symbolic')
    str_ptr = s.se.BVV(100, s.arch.bits)
    delim_ptr = s.se.BVV(200, s.arch.bits)
    state_ptr = s.se.BVV(300, s.arch.bits)

    s.add_constraints(s.memory.load(delim_ptr, 1) != 0)

    st1 = strtok_r(s, inline=True, arguments=[str_ptr, delim_ptr, state_ptr])
    s.add_constraints(st1.ret_expr != 0)
    nose.tools.assert_equal(s.se.any_n_int(s.memory.load(st1.ret_expr-1, 1), 10), [0])


def test_getc():
    s = SimState(mode='symbolic')
    stdin = s.posix.files[0]
    stdin.content.store(0, "1234")
    nose.tools.assert_items_equal(s.se.any_n_int(stdin.pos, 300), [0])
    # The argument of getc should be a FILE *
    c = getc(s, inline=True, arguments=[0]).ret_expr
    nose.tools.assert_items_equal(s.se.any_n_int(c, 300), [0x31])
    nose.tools.assert_items_equal(s.se.any_n_int(stdin.pos, 300), [1])

    c = getc(s, inline=True, arguments=[0]).ret_expr
    nose.tools.assert_items_equal(s.se.any_n_int(c, 300), [0x32])
    nose.tools.assert_items_equal(s.se.any_n_int(stdin.pos, 300), [2])

    c = getc(s, inline=True, arguments=[0]).ret_expr
    nose.tools.assert_items_equal(s.se.any_n_int(c, 300), [0x33])
    nose.tools.assert_items_equal(s.se.any_n_int(stdin.pos, 300), [3])

    c = getc(s, inline=True, arguments=[0]).ret_expr
    nose.tools.assert_items_equal(s.se.any_n_int(c, 300), [0x34])
    nose.tools.assert_items_equal(s.se.any_n_int(stdin.pos, 300), [4])


def test_fgetc():
    s = SimState(mode='symbolic')
    stdin = s.posix.files[0]
    stdin.content.store(0, "1234")
    nose.tools.assert_items_equal(s.se.any_n_int(stdin.pos, 300), [0])
    c = fgetc(s, inline=True, arguments=[0]).ret_expr
    nose.tools.assert_items_equal(s.se.any_n_int(c, 300), [0x31])
    nose.tools.assert_items_equal(s.se.any_n_int(stdin.pos, 300), [1])

    c = fgetc(s, inline=True, arguments=[0]).ret_expr
    nose.tools.assert_items_equal(s.se.any_n_int(c, 300), [0x32])
    nose.tools.assert_items_equal(s.se.any_n_int(stdin.pos, 300), [2])

    c = fgetc(s, inline=True, arguments=[0]).ret_expr
    nose.tools.assert_items_equal(s.se.any_n_int(c, 300), [0x33])
    nose.tools.assert_items_equal(s.se.any_n_int(stdin.pos, 300), [3])

    c = fgetc(s, inline=True, arguments=[0]).ret_expr
    nose.tools.assert_items_equal(s.se.any_n_int(c, 300), [0x34])
    nose.tools.assert_items_equal(s.se.any_n_int(stdin.pos, 300), [4])


def test_getchar():
    s = SimState(mode='symbolic')
    stdin = s.posix.files[0]
    stdin.content.store(0, "1234")
    nose.tools.assert_items_equal(s.se.any_n_int(stdin.pos, 300), [0])
    c = getchar(s, inline=True, arguments=[]).ret_expr
    nose.tools.assert_items_equal(s.se.any_n_int(c, 300), [0x31])
    nose.tools.assert_items_equal(s.se.any_n_int(stdin.pos, 300), [1])

    c = getchar(s, inline=True, arguments=[]).ret_expr
    nose.tools.assert_items_equal(s.se.any_n_int(c, 300), [0x32])
    nose.tools.assert_items_equal(s.se.any_n_int(stdin.pos, 300), [2])

    c = getchar(s, inline=True, arguments=[]).ret_expr
    nose.tools.assert_items_equal(s.se.any_n_int(c, 300), [0x33])
    nose.tools.assert_items_equal(s.se.any_n_int(stdin.pos, 300), [3])

    c = getchar(s, inline=True, arguments=[]).ret_expr
    nose.tools.assert_items_equal(s.se.any_n_int(c, 300), [0x34])
    nose.tools.assert_items_equal(s.se.any_n_int(stdin.pos, 300), [4])



if __name__ == '__main__':
    test_getc()
    test_fgetc()
    test_getchar()
    test_inline_strcmp()
    test_inline_strlen()
    test_inline_strncmp()
    test_memcmp()
    test_memcpy()
    test_memset()
    test_strchr()
    test_strcpy()
    test_strncpy()
    test_strstr_inconsistency()
