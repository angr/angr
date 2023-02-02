import sys
import random
import angr

from angr import SimState, SIM_LIBRARIES

FAKE_ADDR = 0x100000


def make_func(name):
    return (
        lambda state, arguments: SIM_LIBRARIES["libc.so.6"]
        .get(name, "AMD64")
        .execute(state, arguments=arguments)
        .ret_expr
    )


strstr = make_func("strstr")
strtok_r = make_func("strtok_r")
strcmp = make_func("strcmp")
strchr = make_func("strchr")
strncmp = make_func("strncmp")
strlen = make_func("strlen")
strncpy = make_func("strncpy")
strcpy = make_func("strcpy")
memset = make_func("memset")
memcpy = make_func("memcpy")
memcmp = make_func("memcmp")
sprintf = make_func("sprintf")
getc = make_func("_IO_getc")
fgetc = make_func("fgetc")
getchar = make_func("getchar")
scanf = make_func("scanf")
wcscmp = make_func("wcscmp")

import logging

l = logging.getLogger("angr.tests.string")


def make_state_with_stdin(content):
    s = SimState(arch="AMD64", mode="symbolic")
    stdin_storage = angr.storage.file.SimFile("stdin", content=content)
    stdin = angr.storage.file.SimFileDescriptor(stdin_storage)
    s.register_plugin("posix", angr.state_plugins.SimSystemPosix(stdin=stdin_storage, fd={0: stdin}))
    return s


def test_inline_strlen():
    s = SimState(arch="AMD64", mode="symbolic")

    l.info("fully concrete string")
    a_str = s.solver.BVV(0x41414100, 32)
    a_addr = s.solver.BVV(0x10, 64)
    s.memory.store(a_addr, a_str, endness="Iend_BE")
    a_len = strlen(s, arguments=[a_addr])
    assert s.solver.unique(a_len)
    assert s.solver.eval(a_len) == 3

    l.info("concrete-terminated string")
    b_str = s.solver.Concat(s.solver.BVS("mystring", 24), s.solver.BVV(0, 8))
    b_addr = s.solver.BVV(0x20, 64)
    s.memory.store(b_addr, b_str, endness="Iend_BE")
    b_len = strlen(s, arguments=[b_addr])
    assert s.solver.max_int(b_len) == 3
    assert tuple(sorted(s.solver.eval_upto(b_len, 10))) == (0, 1, 2, 3)

    l.info("fully unconstrained")
    u_addr = s.solver.BVV(0x50, 64)
    u_len_sp = strlen(s, arguments=[u_addr])
    u_len = u_len_sp
    assert len(s.solver.eval_upto(u_len, 100)) == s.libc.buf_symbolic_bytes
    assert s.solver.max_int(u_len) == s.libc.buf_symbolic_bytes - 1
    # print u_len_sp.solver.maximum_null

    # s.add_constraints(u_len < 16)

    assert s.solver.eval_upto(s.memory.load(0x50 + u_len, 1), 300) == [0]
    #
    # This tests if a strlen can influence a symbolic str.
    #
    l.info("Trying to influence length.")
    s = SimState(arch="AMD64", mode="symbolic")
    str_c = s.solver.BVS("some_string", 8 * 16)
    c_addr = s.solver.BVV(0x10, 64)
    s.memory.store(c_addr, str_c, endness="Iend_BE")
    c_len = strlen(s, arguments=[c_addr])
    assert len(s.solver.eval_upto(c_len, 100)) == s.libc.buf_symbolic_bytes
    assert s.solver.max_int(c_len) == s.libc.buf_symbolic_bytes - 1

    one_s = s.copy()
    one_s.add_constraints(c_len == 1)
    assert one_s.solver.eval(str_c, cast_to=bytes).index(b"\x00") == 1
    str_test = one_s.memory.load(c_addr, 2, endness="Iend_BE")
    assert len(one_s.solver.eval_upto(str_test, 300, cast_to=bytes)) == 255

    for i in range(16):
        test_s = s.copy()
        test_s.add_constraints(c_len == i)
        str_test = test_s.memory.load(c_addr, i + 1, endness="Iend_BE")
        assert test_s.solver.eval(str_test, cast_to=bytes).index(b"\x00") == i
        for j in range(i):
            assert not test_s.solver.unique(test_s.memory.load(c_addr + j, 1))


def test_inline_strcmp():
    s = SimState(arch="AMD64", mode="symbolic")
    str_a = s.solver.BVV(0x41414100, 32)
    str_b = s.solver.BVS("mystring", 32)

    a_addr = s.solver.BVV(0x10, 64)
    b_addr = s.solver.BVV(0xB0, 64)

    s.memory.store(a_addr, str_a, endness="Iend_BE")
    s.memory.store(b_addr, str_b, endness="Iend_BE")

    s_cmp = s.copy()
    cmpres = strcmp(s_cmp, arguments=[a_addr, b_addr])
    s_match = s_cmp.copy()
    s_nomatch = s_cmp.copy()
    s_match.add_constraints(cmpres == 0)
    s_nomatch.add_constraints(cmpres != 0)

    assert s_match.solver.unique(str_b)
    assert not s_nomatch.solver.unique(str_b)
    assert s_match.solver.eval(str_b, cast_to=bytes) == b"AAA\x00"

    s_ncmp = s.copy()
    ncmpres = strncmp(s_ncmp, arguments=[a_addr, b_addr, s.solver.BVV(2, s.arch.bits)])
    s_match = s_ncmp.copy()
    s_nomatch = s_ncmp.copy()
    s_match.add_constraints(ncmpres == 0)
    s_nomatch.add_constraints(ncmpres != 0)

    assert not s_match.solver.unique(str_b)
    assert s_match.solver.unique(s_match.memory.load(b_addr, 2))
    assert len(s_match.solver.eval_upto(s_match.memory.load(b_addr, 3), 300)) == 256
    assert not s_nomatch.solver.unique(str_b)

    l.info("concrete a, symbolic b")
    s = SimState(arch="AMD64", mode="symbolic")
    str_a = s.solver.BVV(0x41424300, 32)
    str_b = s.solver.BVS("mystring", 32)
    a_addr = s.solver.BVV(0x10, 64)
    b_addr = s.solver.BVV(0xB0, 64)
    s.memory.store(a_addr, str_a, endness="Iend_BE")
    s.memory.store(b_addr, str_b, endness="Iend_BE")

    s_cmp = s.copy()
    cmpres = strncmp(s_cmp, arguments=[a_addr, b_addr, s.solver.BVV(2, s_cmp.arch.bits)])
    s_match = s_cmp.copy()
    s_nomatch = s_cmp.copy()
    s_match.add_constraints(cmpres == 0)
    s_nomatch.add_constraints(cmpres != 0)

    assert s_match.solver.solution(str_b, 0x41420000)
    assert s_match.solver.solution(str_b, 0x41421234)
    assert s_match.solver.solution(str_b, 0x41424300)
    assert not s_nomatch.solver.solution(str_b, 0x41420000)
    assert not s_nomatch.solver.solution(str_b, 0x41421234)
    assert not s_nomatch.solver.solution(str_b, 0x41424300)

    l.info("symbolic a, symbolic b")
    s = SimState(arch="AMD64", mode="symbolic")
    a_addr = s.solver.BVV(0x10, 64)
    b_addr = s.solver.BVV(0xB0, 64)

    s_cmp = s.copy()
    cmpres = strcmp(s_cmp, arguments=[a_addr, b_addr])
    s_match = s_cmp.copy()
    s_nomatch = s_cmp.copy()
    s_match.add_constraints(cmpres == 0)
    s_nomatch.add_constraints(cmpres != 0)

    m_res = strcmp(s_match, arguments=[a_addr, b_addr])
    s_match.add_constraints(m_res != 0)
    nm_res = strcmp(s_nomatch, arguments=[a_addr, b_addr])
    s_nomatch.add_constraints(nm_res == 0)

    assert not s_match.satisfiable()
    assert not s_match.satisfiable()


def test_inline_strncmp():
    l.info("symbolic left, symbolic right, symbolic len")
    s = SimState(arch="AMD64", mode="symbolic")
    left = s.solver.BVS("left", 32)
    left_addr = s.solver.BVV(0x1000, 64)
    right = s.solver.BVS("right", 32)
    right_addr = s.solver.BVV(0x2000, 64)
    maxlen = s.solver.BVS("len", 64)

    s.memory.store(left_addr, left)
    s.memory.store(right_addr, right)

    s.add_constraints(strlen(s, arguments=[left_addr]) == 3)
    s.add_constraints(strlen(s, arguments=[right_addr]) == 0)

    s.add_constraints(maxlen != 0)
    c = strncmp(s, arguments=[left_addr, right_addr, maxlen])

    s_match = s.copy()
    s_match.add_constraints(c == 0)
    assert not s_match.satisfiable()
    # assert s_match.solver.min_int(maxlen) == 3

    s_nomatch = s.copy()
    s_nomatch.add_constraints(c != 0)
    assert s_nomatch.satisfiable()
    # assert s_nomatch.solver.max_int(maxlen) == 2

    l.info("zero-length")
    s = SimState(arch="AMD64", mode="symbolic")
    left = s.solver.BVS("left", 32)
    left_addr = s.solver.BVV(0x1000, 64)
    right = s.solver.BVS("right", 32)
    right_addr = s.solver.BVV(0x2000, 64)
    maxlen = s.solver.BVS("len", 64)
    left_len = strlen(s, arguments=[left_addr])
    right_len = strlen(s, arguments=[right_addr])
    c = strncmp(s, arguments=[left_addr, right_addr, maxlen])

    s.add_constraints(right_len == 0)
    s.add_constraints(left_len == 0)
    # s.add_constraints(c == 0)
    s.add_constraints(maxlen == 0)
    assert s.satisfiable()


def broken_inline_strstr():
    l.info("concrete haystack and needle")
    s = SimState(arch="AMD64", mode="symbolic")
    str_haystack = s.solver.BVV(0x41424300, 32)
    str_needle = s.solver.BVV(0x42430000, 32)
    addr_haystack = s.solver.BVV(0x10, 64)
    addr_needle = s.solver.BVV(0xB0, 64)
    s.memory.store(addr_haystack, str_haystack, endness="Iend_BE")
    s.memory.store(addr_needle, str_needle, endness="Iend_BE")

    ss_res = strstr(s, arguments=[addr_haystack, addr_needle])
    assert s.solver.unique(ss_res)
    assert s.solver.eval(ss_res) == 0x11

    l.info("concrete haystack, symbolic needle")
    s = SimState(arch="AMD64", mode="symbolic")
    str_haystack = s.solver.BVV(0x41424300, 32)
    str_needle = s.solver.BVS("wtf", 32)
    addr_haystack = s.solver.BVV(0x10, 64)
    addr_needle = s.solver.BVV(0xB0, 64)
    s.memory.store(addr_haystack, str_haystack, endness="Iend_BE")
    s.memory.store(addr_needle, str_needle, endness="Iend_BE")

    ss_res = strstr(s, arguments=[addr_haystack, addr_needle])
    assert not s.solver.unique(ss_res)
    assert len(s.solver.eval_upto(ss_res, 10)) == 4

    s_match = s.copy()
    s_nomatch = s.copy()
    s_match.add_constraints(ss_res != 0)
    s_nomatch.add_constraints(ss_res == 0)

    match_needle = str_needle[31:16]
    assert len(s_match.solver.eval_upto(match_needle, 300)) == 259
    assert len(s_match.solver.eval_upto(str_needle, 10)) == 10

    l.info("symbolic haystack, symbolic needle")
    s = SimState(arch="AMD64", mode="symbolic")
    s.libc.buf_symbolic_bytes = 5
    addr_haystack = s.solver.BVV(0x10, 64)
    addr_needle = s.solver.BVV(0xB0, 64)
    len_needle = strlen(s, arguments=[addr_needle])

    ss_res = strstr(s, arguments=[addr_haystack, addr_needle])
    assert not s.solver.unique(ss_res)
    assert len(s.solver.eval_upto(ss_res, 100)) == s.libc.buf_symbolic_bytes

    s_match = s.copy()
    s_nomatch = s.copy()
    s_match.add_constraints(ss_res != 0)
    s_nomatch.add_constraints(ss_res == 0)

    match_cmp = strncmp(s_match, arguments=[ss_res, addr_needle, len_needle])
    assert s_match.solver.eval_upto(match_cmp, 10) == [0]

    r_mm = strstr(s_match, arguments=[addr_haystack, addr_needle])
    s_match.add_constraints(r_mm == 0)
    assert not s_match.satisfiable()

    assert s_nomatch.satisfiable()
    s_nss = s_nomatch.copy()
    nomatch_ss = strstr(s_nss, arguments=[addr_haystack, addr_needle])
    s_nss.add_constraints(nomatch_ss != 0)
    assert not s_nss.satisfiable()


def test_strstr_inconsistency():
    l.info("symbolic haystack, symbolic needle")
    s = SimState(arch="AMD64", mode="symbolic")
    s.libc.buf_symbolic_bytes = 2
    addr_haystack = s.solver.BVV(0x10, 64)
    addr_needle = s.solver.BVV(0xB0, 64)
    # len_needle = strlen(s, inline=True, arguments=[addr_needle])

    ss_res = strstr(s, arguments=[addr_haystack, addr_needle])

    # slh_res = strlen(s, inline=True, arguments=[addr_haystack])
    # sln_res = strlen(s, inline=True, arguments=[addr_needle])
    # print "LENH:", s.solver.eval_upto(slh_res, 100)
    # print "LENN:", s.solver.eval_upto(sln_res, 100)

    assert not s.solver.unique(ss_res)
    assert sorted(s.solver.eval_upto(ss_res, 100)) == [0] + list(range(0x10, 0x10 + s.libc.buf_symbolic_bytes - 1))

    s.add_constraints(ss_res != 0)
    ss2 = strstr(s, arguments=[addr_haystack, addr_needle])
    s.add_constraints(ss2 == 0)
    assert not s.satisfiable()


def test_memcpy():
    l.info("concrete src, concrete dst, concrete len")
    l.debug("... full copy")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.solver.BVV(0x41414141, 32)
    dst_addr = s.solver.BVV(0x1000, 64)
    src = s.solver.BVV(0x42424242, 32)
    src_addr = s.solver.BVV(0x2000, 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    memcpy(s, arguments=[dst_addr, src_addr, s.solver.BVV(4, 64)])
    new_dst = s.memory.load(dst_addr, 4, endness="Iend_BE")
    assert s.solver.eval_upto(new_dst, 2, cast_to=bytes) == [b"BBBB"]

    l.info("giant copy")
    s = SimState(arch="AMD64", mode="symbolic", remove_options=angr.options.simplification)
    s.memory._maximum_symbolic_size = 0x2000000
    size = s.solver.BVV(0x1000000, 64)
    data = s.solver.BVS("giant", 8 * 0x1_000_000)
    dst_addr = s.solver.BVV(0x2000000, 64)
    src_addr = s.solver.BVV(0x4000000, 64)
    s.memory.store(src_addr, data)

    memcpy(s, arguments=[dst_addr, src_addr, size])
    assert s.memory.load(dst_addr, size) is s.memory.load(src_addr, size)

    l.debug("... partial copy")
    s = SimState(arch="AMD64", mode="symbolic")
    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    memcpy(s, arguments=[dst_addr, src_addr, s.solver.BVV(2, 64)])
    new_dst = s.memory.load(dst_addr, 4, endness="Iend_BE")
    assert s.solver.eval_upto(new_dst, 2, cast_to=bytes) == [b"BBAA"]

    l.info("symbolic src, concrete dst, concrete len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.solver.BVV(0x41414141, 32)
    dst_addr = s.solver.BVV(0x1000, 64)
    src = s.solver.BVS("src", 32)
    src_addr = s.solver.BVV(0x2000, 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)

    # make sure it copies it all
    memcpy(s, arguments=[dst_addr, src_addr, s.solver.BVV(4, 64)])
    assert s.satisfiable()
    s.add_constraints(src != s.memory.load(dst_addr, 4))
    assert not s.satisfiable()

    l.info("symbolic src, concrete dst, symbolic len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.solver.BVV(0x41414141, 32)
    dst_addr = s.solver.BVV(0x1000, 64)
    src = s.solver.BVS("src", 32)
    src_addr = s.solver.BVV(0x2000, 64)
    cpylen = s.solver.BVS("len", 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    s.add_constraints(cpylen < 10)
    memcpy(s, arguments=[dst_addr, src_addr, cpylen])
    result = s.memory.load(dst_addr, 4, endness="Iend_BE")

    # make sure it copies it all
    s1 = s.copy()
    s1.add_constraints(cpylen == 1)
    assert s1.solver.unique(s1.memory.load(dst_addr + 1, 3))
    assert len(s1.solver.eval_upto(s1.memory.load(dst_addr, 1), 300)) == 256

    s2 = s.copy()
    s2.add_constraints(cpylen == 2)
    assert len(s2.solver.eval_upto(result[31:24], 300)) == 256
    assert len(s2.solver.eval_upto(result[23:16], 300)) == 256
    assert s2.solver.eval_upto(result[15:0], 300, cast_to=bytes) == [b"AA"]

    l.info("concrete src, concrete dst, symbolic len")
    dst = s2.solver.BVV(0x41414141, 32)
    dst_addr = s2.solver.BVV(0x1000, 64)
    src = s2.solver.BVV(0x42424242, 32)
    src_addr = s2.solver.BVV(0x2000, 64)

    s = SimState(arch="AMD64", mode="symbolic")
    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    cpylen = s.solver.BVS("len", 64)

    s.add_constraints(s.solver.ULE(cpylen, 4))
    memcpy(s, arguments=[dst_addr, src_addr, cpylen])
    new_dst = s.memory.load(dst_addr, 4, endness="Iend_BE")
    assert sorted(s.solver.eval_upto(new_dst, 300, cast_to=bytes)) == [b"AAAA", b"BAAA", b"BBAA", b"BBBA", b"BBBB"]


def test_memcmp():
    l.info("concrete src, concrete dst, concrete len")

    l.debug("... full cmp")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.solver.BVV(0x41414141, 32)
    dst_addr = s.solver.BVV(0x1000, 64)
    src = s.solver.BVV(0x42424242, 32)
    src_addr = s.solver.BVV(0x2000, 64)
    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    r = memcmp(s, arguments=[dst_addr, src_addr, s.solver.BVV(4, 64)])
    assert s.satisfiable()

    s_pos = s.copy()
    s_pos.add_constraints(r.SGE(0))
    assert not s_pos.satisfiable()

    s_neg = s.copy()
    s_neg.add_constraints(r.SLT(0))
    assert s_neg.satisfiable()

    l.debug("... zero cmp")
    s = SimState(arch="AMD64", mode="symbolic")
    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    r = memcmp(s, arguments=[dst_addr, src_addr, s.solver.BVV(0, 64)])
    assert s.solver.eval_upto(r, 2) == [0]

    l.info("symbolic src, concrete dst, concrete len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.solver.BVV(0x41414141, 32)
    dst_addr = s.solver.BVV(0x1000, 64)
    src = s.solver.BVS("src", 32)

    src_addr = s.solver.BVV(0x2000, 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)

    # make sure it copies it all
    r = memcmp(s, arguments=[dst_addr, src_addr, s.solver.BVV(4, 64)])

    s_match = s.copy()
    s_match.add_constraints(r == 0)
    m = s_match.memory.load(src_addr, 4)
    assert s_match.solver.eval_upto(m, 2) == [0x41414141]

    s_nomatch = s.copy()
    s_nomatch.add_constraints(r != 0)
    m = s_nomatch.memory.load(src_addr, 4)
    assert not s_nomatch.solver.solution(m, 0x41414141)

    l.info("symbolic src, concrete dst, symbolic len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.solver.BVV(0x41414141, 32)
    dst_addr = s.solver.BVV(0x1000, 64)
    src = s.solver.BVS("src", 32)
    src_addr = s.solver.BVV(0x2000, 64)
    cmplen = s.solver.BVS("len", 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    r = memcmp(s, arguments=[dst_addr, src_addr, cmplen])

    # look at effects of different lengths
    s1 = s.copy()
    s1.add_constraints(cmplen == 1)
    s1.add_constraints(r == 0)
    l.debug("... simplifying")
    s1.solver._solver.simplify()
    l.debug("... solving")
    assert s1.solver.eval_upto(src[31:24], 2) == [0x41]
    assert not s1.solver.unique(src[31:16])
    l.debug("... solved")

    s2 = s.copy()
    s2.add_constraints(cmplen == 2)
    s2.add_constraints(r == 0)
    assert s2.solver.eval_upto(s2.memory.load(src_addr, 2), 2) == [0x4141]
    assert not s2.solver.unique(s2.memory.load(src_addr, 3))

    s2u = s.copy()
    s2u.add_constraints(cmplen == 2)
    s2u.add_constraints(r == 1)
    assert not s2u.solver.solution(s2u.memory.load(src_addr, 2), 0x4141)


def test_strncpy():
    l.info("concrete src, concrete dst, concrete len")
    l.debug("... full copy")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.solver.BVV(0x41414100, 32)
    dst_addr = s.solver.BVV(0x1000, 64)
    src = s.solver.BVV(0x42420000, 32)
    src_addr = s.solver.BVV(0x2000, 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    strncpy(s, arguments=[dst_addr, src_addr, s.solver.BVV(3, 64)])
    new_dst = s.memory.load(dst_addr, 4, endness="Iend_BE")
    assert s.solver.eval(new_dst, cast_to=bytes) == b"BB\x00\x00"

    l.debug("... partial copy")
    s = SimState(arch="AMD64", mode="symbolic")
    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    strncpy(s, arguments=[dst_addr, src_addr, s.solver.BVV(2, 64)])
    new_dst = s.memory.load(dst_addr, 4, endness="Iend_BE")
    assert s.solver.eval_upto(new_dst, 2, cast_to=bytes) == [b"BBA\x00"]

    l.info("symbolic src, concrete dst, concrete len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.solver.BVV(0x41414100, 32)
    dst_addr = s.solver.BVV(0x1000, 64)
    src = s.solver.BVS("src", 32)
    src_addr = s.solver.BVV(0x2000, 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)

    # make sure it copies it all
    s.add_constraints(strlen(s, arguments=[src_addr]) == 2)

    # sanity check
    s_false = s.copy()
    s_false.add_constraints(strlen(s_false, arguments=[src_addr]) == 3)
    assert not s_false.satisfiable()

    strncpy(s, arguments=[dst_addr, src_addr, 3])
    assert s.satisfiable()
    c = strcmp(s, arguments=[dst_addr, src_addr])

    assert s.solver.eval_upto(c, 10) == [0]

    l.info("symbolic src, concrete dst, symbolic len")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.solver.BVV(0x41414100, 32)
    dst_addr = s.solver.BVV(0x1000, 64)
    src = s.solver.BVS("src", 32)
    src_addr = s.solver.BVV(0x2000, 64)
    maxlen = s.solver.BVS("len", 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)

    # make sure it copies it all
    s.add_constraints(strlen(s, arguments=[src_addr]) == 2)
    strncpy(s, arguments=[dst_addr, src_addr, maxlen])
    c = strcmp(s, arguments=[dst_addr, src_addr])

    s_match = s.copy()
    s_match.add_constraints(c == 0)
    assert s_match.solver.min_int(maxlen) == 3

    s_nomatch = s.copy()
    s_nomatch.add_constraints(c != 0)
    assert s_nomatch.solver.max_int(maxlen) == 2

    l.info("concrete src, concrete dst, symbolic len")
    l.debug("... full copy")
    s = SimState(arch="AMD64", mode="symbolic")

    dst = s.solver.BVV(0x41414100, 32)
    dst_addr = s.solver.BVV(0x1000, 64)
    src = s.solver.BVV(0x42420000, 32)
    src_addr = s.solver.BVV(0x2000, 64)
    maxlen = s.solver.BVS("len", 64)

    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    strncpy(s, arguments=[dst_addr, src_addr, maxlen])
    r = s.memory.load(dst_addr, 4, endness="Iend_BE")
    # print repr(r.solver.eval_upto(r, 10, cast_to=bytes))
    assert sorted(s.solver.eval_upto(r, 10, cast_to=bytes)) == [b"AAA\x00", b"BAA\x00", b"BB\x00\x00", b"BBA\x00"]


def test_strcpy():
    l.info("concrete src, concrete dst")

    l.debug("... full copy")
    s = SimState(arch="AMD64", mode="symbolic")
    dst = s.solver.BVV(0x41414100, 32)
    dst_addr = s.solver.BVV(0x1000, 64)
    src = s.solver.BVV(0x42420000, 32)
    src_addr = s.solver.BVV(0x2000, 64)
    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)
    strcpy(s, arguments=[dst_addr, src_addr])
    new_dst = s.memory.load(dst_addr, 4, endness="Iend_BE")
    assert s.solver.eval(new_dst, cast_to=bytes) == b"BB\x00\x00"

    l.info("symbolic src, concrete dst")
    dst = s.solver.BVV(0x41414100, 32)
    dst_addr = s.solver.BVV(0x1000, 64)
    src = s.solver.BVS("src", 32)
    src_addr = s.solver.BVV(0x2000, 64)

    s = SimState(arch="AMD64", mode="symbolic")
    s.memory.store(dst_addr, dst)
    s.memory.store(src_addr, src)

    ln = strlen(s, arguments=[src_addr])

    strcpy(s, arguments=[dst_addr, src_addr])

    cm = strcmp(s, arguments=[dst_addr, src_addr])

    s.add_constraints(cm == 0)

    s.add_constraints(ln == 15)
    # readsize = 16
    # both_strs = s.solver.Concat(
    #     *[s.memory.load(dst_addr, readsize, endness="Iend_BE"), s.memory.load(src_addr, readsize, endness="Iend_BE")]
    # )
    # for i in s.solver.eval_upto(both_strs, 50, cast_to=bytes):
    #     assert s.solver.eval_upto(10) == [0]
    #     assert s.solver.solution(s.memory.load(dst_addr, 4, endness="Iend_BE"), 0x42434400)
    #     assert s.solver.solution(s.memory.load(dst_addr, 4, endness="Iend_BE"), 0x42434445)
    #     assert s.solver.solution(s.memory.load(dst_addr, 4, endness="Iend_BE"), 0x00414100)
    #     assert not s.solver.solution(s.memory.load(dst_addr, 4, endness="Iend_BE"), 0x00010203)


def broken_sprintf():
    l.info("concrete src, concrete dst, concrete len")
    s = SimState(mode="symbolic", arch="PPC32")
    format_str = s.solver.BVV(0x25640000, 32)
    format_addr = s.solver.BVV(0x2000, 32)
    # dst = s.solver.BVV("destination", 128)
    dst_addr = s.solver.BVV(0x1000, 32)
    arg = s.solver.BVS("some_number", 32)

    s.memory.store(format_addr, format_str)

    sprintf(s, arguments=[dst_addr, format_addr, arg])

    for i in range(9):
        j = random.randint(10**i, 10 ** (i + 1))
        s2 = s.copy()
        s2.add_constraints(arg == j)
        # print s2.solver.eval_upto(s2.memory.load(dst_addr, i+2), 2, cast_to=bytes), repr(b"%d\x00" % j)
        assert s2.solver.eval_upto(s2.memory.load(dst_addr, i + 2), 2, cast_to=bytes) == [b"%d\x00" % j]

    s2 = s.copy()
    s2.add_constraints(arg == 0)
    # print s2.solver.eval_upto(s2.memory.load(dst_addr, 2), 2, cast_to=bytes), repr(b"%d\x00" % 0)
    assert s2.solver.eval_upto(s2.memory.load(dst_addr, 2), 2, cast_to=bytes) == [b"%d\x00" % 0]


def test_memset():
    l.info("concrete src, concrete dst, concrete len")
    s = SimState(arch="PPC32", mode="symbolic")
    dst = s.solver.BVV(0, 128)
    dst_addr = s.solver.BVV(0x1000, 32)
    char = s.solver.BVV(0x00000041, 32)
    char2 = s.solver.BVV(0x50505050, 32)
    length = s.solver.BVS("some_length", 32)

    s.memory.store(dst_addr, dst)
    memset(s, arguments=[dst_addr, char, s.solver.BVV(3, 32)])
    assert s.solver.eval(s.memory.load(dst_addr, 4)) == 0x41414100

    l.debug("Symbolic length")
    s = SimState(arch="PPC32", mode="symbolic")
    s.memory.store(dst_addr, dst)
    length = s.solver.BVS("some_length", 32)
    s.add_constraints(length < 10)
    memset(s, arguments=[dst_addr, char2, length])

    l.debug("Trying 2")
    s_two = s.copy()
    s_two.add_constraints(length == 2)
    assert s_two.solver.eval(s_two.memory.load(dst_addr, 4)) == 0x50500000

    l.debug("Trying 0")
    s_zero = s.copy()
    s_zero.add_constraints(length == 0)
    assert s_zero.solver.eval(s_zero.memory.load(dst_addr, 4)) == 0x00000000

    l.debug("Trying 5")
    s_five = s.copy()
    s_five.add_constraints(length == 5)
    assert s_five.solver.eval(s_five.memory.load(dst_addr, 6)) == 0x505050505000


def test_strchr():
    l.info("concrete haystack and needle")
    s = SimState(arch="AMD64", mode="symbolic")
    str_haystack = s.solver.BVV(0x41424300, 32)
    str_needle = s.solver.BVV(0x42, 64)
    addr_haystack = s.solver.BVV(0x10, 64)
    s.memory.store(addr_haystack, str_haystack, endness="Iend_BE")

    ss_res = strchr(s, arguments=[addr_haystack, str_needle])
    assert s.solver.unique(ss_res)
    assert s.solver.eval(ss_res) == 0x11

    l.info("concrete haystack, symbolic needle")
    s = SimState(arch="AMD64", mode="symbolic")
    str_haystack = s.solver.BVV(0x41424300, 32)
    str_needle = s.solver.BVS("wtf", 64)
    chr_needle = str_needle[7:0]
    addr_haystack = s.solver.BVV(0x10, 64)
    s.memory.store(addr_haystack, str_haystack, endness="Iend_BE")

    ss_res = strchr(s, arguments=[addr_haystack, str_needle])
    assert not s.solver.unique(ss_res)
    assert len(s.solver.eval_upto(ss_res, 10)) == 5

    s_match = s.copy()
    s_nomatch = s.copy()
    s_match.add_constraints(ss_res != 0)
    s_nomatch.add_constraints(ss_res == 0)

    assert s_match.satisfiable()
    assert s_nomatch.satisfiable()
    assert len(s_match.solver.eval_upto(chr_needle, 300)) == 4
    assert len(s_nomatch.solver.eval_upto(chr_needle, 300)) == 252
    assert sorted(s_match.solver.eval_upto(ss_res, 300)) == [0x10, 0x11, 0x12, 0x13]
    assert sorted(s_match.solver.eval_upto(chr_needle, 300)) == [0x00, 0x41, 0x42, 0x43]

    s_match.memory.store(ss_res, s_match.solver.BVV(0x44, 8))
    assert sorted(s_match.solver.eval_upto(s_match.memory.load(0x10, 1), 300)) == [0x41, 0x44]
    assert sorted(s_match.solver.eval_upto(s_match.memory.load(0x11, 1), 300)) == [0x42, 0x44]
    assert sorted(s_match.solver.eval_upto(s_match.memory.load(0x12, 1), 300)) == [0x43, 0x44]
    assert sorted(s_match.solver.eval_upto(s_match.memory.load(0x13, 1), 300)) == [0x00, 0x44]

    # l.info("symbolic haystack, symbolic needle")
    # s = SimState(arch="AMD64", mode="symbolic")
    # s.libc.buf_symbolic_bytes = 5
    # addr_haystack = s.solver.BVV(0x10, 64)
    # addr_needle = s.solver.BVV(0xb0, 64)
    # len_needle = strlen(s, inline=True, arguments=[addr_needle])

    # ss_res = strstr(s, inline=True, arguments=[addr_haystack, addr_needle])
    # ss_val = s.expr_value(ss_res)

    # assert not ss_val.is_unique()
    # assert len(ss_val.solver.eval_upto(100)) == s.libc.buf_symbolic_bytes

    # s_match = s.copy()
    # s_nomatch = s.copy()
    # s_match.add_constraints(ss_res != 0)
    # s_nomatch.add_constraints(ss_res == 0)

    # match_cmp = strncmp(s_match, inline=True, arguments=[ss_res, addr_needle, len_needle])
    # match_cmp_val = s_match.expr_value(match_cmp)
    # assert match_cmp_val.solver.eval_upto(10) == [0]

    # r_mm = strstr(s_match, inline=True, arguments=[addr_haystack, addr_needle])
    # s_match.add_constraints(r_mm == 0)
    # assert not s_match.satisfiable()

    # assert s_nomatch.satisfiable()
    # s_nss = s_nomatch.copy()
    # nomatch_ss = strstr(s_nss, inline=True, arguments=[addr_haystack, addr_needle])
    # s_nss.add_constraints(nomatch_ss != 0)
    # assert not s_nss.satisfiable()


def broken_strtok_r():
    l.debug("CONCRETE MODE")
    s = SimState(arch="AMD64", mode="symbolic")
    s.memory.store(100, s.solver.BVV(0x4141414241414241424300, 88), endness="Iend_BE")
    s.memory.store(200, s.solver.BVV(0x4200, 16), endness="Iend_BE")
    str_ptr = s.solver.BVV(100, s.arch.bits)
    delim_ptr = s.solver.BVV(200, s.arch.bits)
    state_ptr = s.solver.BVV(300, s.arch.bits)

    st1 = strtok_r(s, arguments=[str_ptr, delim_ptr, state_ptr])
    assert s.solver.eval_upto(st1, 10) == [104]
    assert s.solver.eval_upto(s.memory.load(st1 - 1, 1), 10) == [0]
    assert s.solver.eval_upto(s.memory.load(200, 2), 10) == [0x4200]

    st2 = strtok_r(s, arguments=[s.solver.BVV(0, s.arch.bits), delim_ptr, state_ptr])
    assert s.solver.eval_upto(st2, 10) == [107]
    assert s.solver.eval_upto(s.memory.load(st2 - 1, 1), 10) == [0]

    st3 = strtok_r(s, arguments=[s.solver.BVV(0, s.arch.bits), delim_ptr, state_ptr])
    assert s.solver.eval_upto(st3, 10) == [109]
    assert s.solver.eval_upto(s.memory.load(st3 - 1, 1), 10) == [0]

    st4 = strtok_r(s, arguments=[s.solver.BVV(0, s.arch.bits), delim_ptr, state_ptr])
    assert s.solver.eval_upto(st4, 10) == [0]
    assert s.solver.eval_upto(s.memory.load(300, s.arch.bytes, endness=s.arch.memory_endness), 10) == [109]

    st5 = strtok_r(s, arguments=[s.solver.BVV(0, s.arch.bits), delim_ptr, state_ptr])
    assert s.solver.eval_upto(st5, 10) == [0]
    assert s.solver.eval_upto(s.memory.load(300, s.arch.bytes, endness=s.arch.memory_endness), 10) == [109]

    s.memory.store(1000, s.solver.BVV(0x4141414241414241424300, 88), endness="Iend_BE")
    s.memory.store(2000, s.solver.BVV(0x4200, 16), endness="Iend_BE")
    str_ptr = s.solver.BVV(1000, s.arch.bits)
    delim_ptr = s.solver.BVV(2000, s.arch.bits)
    state_ptr = s.solver.BVV(3000, s.arch.bits)

    st1 = strtok_r(s, arguments=[str_ptr, delim_ptr, state_ptr])
    assert s.solver.eval_upto(st1, 10) == [1004]
    assert s.solver.eval_upto(s.memory.load(st1 - 1, 1), 10) == [0]
    assert s.solver.eval_upto(s.memory.load(2000, 2), 10) == [0x4200]

    st2 = strtok_r(s, arguments=[s.solver.BVV(0, s.arch.bits), delim_ptr, state_ptr])
    assert s.solver.eval_upto(st2, 10) == [1007]
    assert s.solver.eval_upto(s.memory.load(st2 - 1, 1), 10) == [0]

    st3 = strtok_r(s, arguments=[s.solver.BVV(0, s.arch.bits), delim_ptr, state_ptr])
    assert s.solver.eval_upto(st3, 10) == [1009]
    assert s.solver.eval_upto(s.memory.load(st3 - 1, 1), 10) == [0]

    st4 = strtok_r(s, arguments=[s.solver.BVV(0, s.arch.bits), delim_ptr, state_ptr])
    assert s.solver.eval_upto(st4, 10) == [0]
    assert s.solver.eval_upto(s.memory.load(3000, s.arch.bytes, endness=s.arch.memory_endness), 10) == [1009]

    st5 = strtok_r(s, arguments=[s.solver.BVV(0, s.arch.bits), delim_ptr, state_ptr])
    assert s.solver.eval_upto(st5, 10) == [0]
    assert s.solver.eval_upto(s.memory.load(3000, s.arch.bytes, endness=s.arch.memory_endness), 10) == [1009]

    s = SimState(arch="AMD64", mode="symbolic")
    str_ptr = s.solver.BVV(100, s.arch.bits)
    delim_ptr = s.solver.BVV(200, s.arch.bits)
    state_ptr = s.solver.BVV(300, s.arch.bits)

    s.add_constraints(s.memory.load(delim_ptr, 1) != 0)

    st1 = strtok_r(s, arguments=[str_ptr, delim_ptr, state_ptr])
    s.add_constraints(st1 != 0)
    assert s.solver.eval_upto(s.memory.load(st1 - 1, 1), 10) == [0]


def test_getc():
    s = make_state_with_stdin(b"1234")
    stdin = s.posix.get_fd(0)
    s.mem[0x1000 + 0x70].int = 0

    assert s.solver.eval_one(stdin.tell()) == 0

    # The argument of getc should be a FILE *
    c = getc(s, [0x1000])
    assert s.solver.eval_upto(c, 300) == [0x31]
    assert s.solver.eval_upto(stdin.tell(), 300) == [1]

    c = getc(s, [0x1000])
    assert s.solver.eval_upto(c, 300) == [0x32]
    assert s.solver.eval_upto(stdin.tell(), 300) == [2]

    c = getc(s, [0x1000])
    assert s.solver.eval_upto(c, 300) == [0x33]
    assert s.solver.eval_upto(stdin.tell(), 300) == [3]

    c = getc(s, [0x1000])
    assert s.solver.eval_upto(c, 300) == [0x34]
    assert s.solver.eval_upto(stdin.tell(), 300) == [4]


def test_getchar():
    s = make_state_with_stdin(b"1234")
    stdin = s.posix.get_fd(0)

    assert s.solver.eval_upto(stdin.tell(), 300) == [0]
    c = getchar(s, arguments=[])
    assert s.solver.eval_upto(c, 300) == [0x31]
    assert s.solver.eval_upto(stdin.tell(), 300) == [1]

    c = getchar(s, arguments=[])
    assert s.solver.eval_upto(c, 300) == [0x32]
    assert s.solver.eval_upto(stdin.tell(), 300) == [2]

    c = getchar(s, arguments=[])
    assert s.solver.eval_upto(c, 300) == [0x33]
    assert s.solver.eval_upto(stdin.tell(), 300) == [3]

    c = getchar(s, arguments=[])
    assert s.solver.eval_upto(c, 300) == [0x34]
    assert s.solver.eval_upto(stdin.tell(), 300) == [4]


def test_scanf():
    s = make_state_with_stdin(b"Hello\n")
    s.memory.store(0x2000, b"%1s\0")
    scanf(s, [0x2000, 0x1000])
    assert s.solver.eval_upto(s.memory.load(0x1000, 2), 2, cast_to=bytes) == [b"H\x00"]


def test_strcmp():
    l.info("concrete a, concrete b")
    s = SimState(arch="AMD64", mode="symbolic")
    a_addr = s.solver.BVV(0x10, 64)
    b_addr = s.solver.BVV(0xB0, 64)

    s.memory.store(a_addr, b"heck\x00")
    s.memory.store(b_addr, b"heck\x00")

    r = strcmp(s, arguments=[a_addr, b_addr])
    assert s.solver.eval_upto(r, 2) == [0]

    l.info("concrete a, empty b")
    s = SimState(arch="AMD64", mode="symbolic")
    a_addr = s.solver.BVV(0x10, 64)
    b_addr = s.solver.BVV(0xB0, 64)

    s.memory.store(a_addr, b"heck\x00")
    s.memory.store(b_addr, b"\x00")

    r = strcmp(s, arguments=[a_addr, b_addr])
    assert s.solver.eval_upto(r, 2) == [1]

    l.info("empty a, concrete b")
    s = SimState(arch="AMD64", mode="symbolic")
    a_addr = s.solver.BVV(0x10, 64)
    b_addr = s.solver.BVV(0xB0, 64)

    s.memory.store(a_addr, b"\x00")
    s.memory.store(b_addr, b"heck\x00")

    r = strcmp(s, arguments=[a_addr, b_addr])
    assert s.solver.eval_upto(r, 2) == [0xFFFFFFFF]

    l.info("empty a, empty b")
    s = SimState(arch="AMD64", mode="symbolic")
    a_addr = s.solver.BVV(0x10, 64)
    b_addr = s.solver.BVV(0xB0, 64)

    s.memory.store(a_addr, b"\x00")
    s.memory.store(b_addr, b"\x00")

    r = strcmp(s, arguments=[a_addr, b_addr])
    assert s.solver.eval_upto(r, 2) == [0]


def test_wcscmp():
    # concrete cases for the wide char version sufficiently overlap with strcmp and friends
    l.info("concrete a, symbolic b")
    s = SimState(arch="AMD64", mode="symbolic")
    heck = "heck\x00".encode("utf-16")[2:]  # remove encoding prefix
    a_addr = s.solver.BVV(0x10, 64)
    b_addr = s.solver.BVV(0xB0, 64)
    b_bvs = s.solver.BVS("b", len(heck) * 8)

    s.memory.store(a_addr, heck)
    s.memory.store(b_addr, b_bvs)

    r = wcscmp(s, arguments=[a_addr, b_addr])

    solutions = s.solver.eval_upto(b_bvs, 2, cast_to=bytes, extra_constraints=(r == 0,))
    assert solutions == [heck]


def test_string_without_null():
    s = SimState(arch="AMD64", mode="symbolic")
    str_ = b"abcd"
    str_addr = s.solver.BVV(0x10, 64)
    s.memory.store(str_addr, str_)
    assert s.solver.eval(s.mem[str_addr].string.resolved, cast_to=bytes) == b"abcd"


def run_all():
    def print_test_name(name):
        print("#" * (len(name) + 8))
        print("###", name, "###")
        print("#" * (len(name) + 8))

    functions = globals()
    all_functions = dict(filter((lambda kv: kv[0].startswith("test_")), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], "__call__"):
            print_test_name(f)
            all_functions[f]()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        globals()["test_" + sys.argv[1]]()
    else:
        run_all()
