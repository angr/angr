# pylint:disable=line-too-long,missing-class-docstring
import time

import claripy

from angr.storage.memory_mixins import (
    DataNormalizationMixin,
    SizeNormalizationMixin,
    AddressConcretizationMixin,
    UltraPagesMixin,
    ListPagesMixin,
    PagedMemoryMixin,
    MultiValuedMemory,
    MVListPagesMixin,
)
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr import SimState, SIM_PROCEDURES
from angr import options as o
from angr.state_plugins import SimSystemPosix, SimLightRegisters
from angr.storage.file import SimFile


class UltraPageMemory(
    DataNormalizationMixin,
    SizeNormalizationMixin,
    AddressConcretizationMixin,
    UltraPagesMixin,
    PagedMemoryMixin,
):
    pass


class ListPageMemory(
    DataNormalizationMixin,
    SizeNormalizationMixin,
    AddressConcretizationMixin,
    ListPagesMixin,
    PagedMemoryMixin,
):
    pass


class MVPageMemory(
    SizeNormalizationMixin,
    AddressConcretizationMixin,
    MVListPagesMixin,
    PagedMemoryMixin,
):
    pass


def test_copy():
    s = SimState(arch="AMD64", mode="symbolic")
    s.memory.store(0x100, b"ABCDEFGHIJKLMNOP")
    s.memory.store(0x200, b"XXXXXXXXXXXXXXXX")
    x = s.solver.BVS("size", s.arch.bits)
    s.add_constraints(s.solver.ULT(x, 10))
    s.memory.copy_contents(0x200, 0x100, x)

    assert sorted(s.solver.eval_upto(x, 100)) == list(range(10))
    result = s.memory.load(0x200, 5)
    assert sorted(s.solver.eval_upto(result, 100, cast_to=bytes)) == [
        b"ABCDE",
        b"ABCDX",
        b"ABCXX",
        b"ABXXX",
        b"AXXXX",
        b"XXXXX",
    ]
    assert sorted(s.solver.eval_upto(result, 100, cast_to=bytes, extra_constraints=[x == 3])) == [b"ABCXX"]

    s = SimState(arch="AMD64", mode="symbolic")
    s.register_plugin("posix", SimSystemPosix(stdin=SimFile(name="stdin", content=b"ABCDEFGHIJKLMNOP", has_end=True)))
    s.memory.store(0x200, b"XXXXXXXXXXXXXXXX")
    x = s.solver.BVS("size", s.arch.bits)
    s.add_constraints(s.solver.ULT(x, 10))

    s.posix.get_fd(0).read(0x200, x)
    assert sorted(s.solver.eval_upto(x, 100)) == list(range(10))
    result = s.memory.load(0x200, 5)
    assert sorted(s.solver.eval_upto(result, 100, cast_to=bytes)) == [
        b"ABCDE",
        b"ABCDX",
        b"ABCXX",
        b"ABXXX",
        b"AXXXX",
        b"XXXXX",
    ]
    assert sorted(s.solver.eval_upto(result, 100, cast_to=bytes, extra_constraints=[x == 3])) == [b"ABCXX"]

    s = SimState(arch="AMD64", mode="symbolic")
    s.register_plugin("posix", SimSystemPosix(stdin=SimFile(name="stdin", content=b"ABCDEFGHIJKLMNOP")))
    s.memory.store(0x200, b"XXXXXXXXXXXXXXXX")
    x = s.solver.BVS("size", s.arch.bits)
    s.add_constraints(s.solver.ULT(x, 10))

    read_proc = SIM_PROCEDURES["posix"]["read"]()
    ret_x = read_proc.execute(s, arguments=(0, 0x200, x)).ret_expr
    assert sorted(s.solver.eval_upto(x, 100)) == list(range(10))
    result = s.memory.load(0x200, 5)
    assert sorted(s.solver.eval_upto(result, 100, cast_to=bytes)) == [
        b"ABCDE",
        b"ABCDX",
        b"ABCXX",
        b"ABXXX",
        b"AXXXX",
        b"XXXXX",
    ]
    assert sorted(s.solver.eval_upto(result, 100, cast_to=bytes, extra_constraints=[x == 3])) == [b"ABCXX"]

    assert sorted(s.solver.eval_upto(ret_x, 100)) == list(range(10))
    assert sorted(s.solver.eval_upto(result, 100, cast_to=bytes, extra_constraints=[ret_x == 3])) == [b"ABCXX"]


def _concrete_memory_tests(s):
    # Store a 4-byte variable to memory directly...
    s.memory.store(100, s.solver.BVV(0x1337, 32))
    # ... then load it

    expr = s.memory.load(100, 4)
    assert expr is s.solver.BVV(0x1337, 32)
    expr = s.memory.load(100, 2)
    assert expr is s.solver.BVV(0, 16)
    expr = s.memory.load(102, 2)
    assert expr is s.solver.BVV(0x1337, 16)

    # partially symbolic
    expr = s.memory.load(102, 4)
    assert expr.length == 32
    assert s.solver.min(expr) == 0x13370000
    assert s.solver.max(expr) == 0x1337FFFF

    # partial overwrite
    s.memory.store(101, s.solver.BVV(0x1415, 16))
    expr = s.memory.load(101, 3)
    assert expr is s.solver.BVV(0x141537, 24)
    expr = s.memory.load(100, 2)
    assert s.solver.min(expr) == 0x14
    expr = s.memory.load(102, 2)
    assert expr is s.solver.BVV(0x1537, 16)
    expr = s.memory.load(102, 2, endness="Iend_LE")
    assert expr is s.solver.BVV(0x3715, 16)

    s.memory.store(0x100, s.solver.BVV(b"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"), endness="Iend_LE")
    expr = s.memory.load(0x104, 13)
    assert expr is s.solver.BVV(b"GGGGFFFFEEEED")

    # branching
    s2 = s.copy()
    s2a = s2.copy()
    s2b = s2.copy()

    s2a.memory.store(0x100, s.solver.BVV(b"A"))
    s2b.memory.store(0x100, s.solver.BVV(b"B"))
    assert s2b.memory.load(0x100, 1) is s.solver.BVV(b"B")
    assert s2a.memory.load(0x100, 1) is s.solver.BVV(b"A")


## pylint: disable=R0904
def test_memory():
    initial_memory = {0: b"A", 1: b"A", 2: b"A", 3: b"A", 10: b"B"}
    s = SimState(
        arch="AMD64",
        dict_memory_backer=initial_memory,
        add_options={o.REVERSE_MEMORY_NAME_MAP, o.REVERSE_MEMORY_HASH_MAP},
    )

    _concrete_memory_tests(s)
    # concrete address and partially symbolic result
    expr = s.memory.load(2, 4)
    expr = s.memory.load(2, 4)
    expr = s.memory.load(2, 4)
    expr = s.memory.load(2, 4)
    assert s.solver.symbolic(expr)
    assert not s.solver.unique(expr)
    assert s.solver.eval(expr) >= 0x41410000
    assert s.solver.eval(expr) <= 0x41420000
    assert s.solver.min_int(expr) == 0x41410000
    assert s.solver.max_int(expr) == 0x4141FFFF

    # concrete address and concrete result
    expr = s.memory.load(0, 4)  # Returns: a z3 BVS representing 0x41414141
    assert not s.solver.symbolic(expr)
    assert s.solver.eval(expr) == 0x41414141

    c = s.solver.BVS("condition", 8)
    expr = s.memory.load(10, 1, condition=c == 1, fallback=s.solver.BVV(b"X"))
    assert s.solver.eval_upto(expr, 10, cast_to=bytes, extra_constraints=[c == 1]) == [b"B"]
    assert s.solver.eval_upto(expr, 10, cast_to=bytes, extra_constraints=[c != 1]) == [b"X"]

    x = s.solver.BVS("ref_test", 16, explicit_name=True)
    s.memory.store(0x1000, x)
    s.memory.store(0x2000, x)
    assert set(s.memory.addrs_for_name("ref_test")) == {0x1000, 0x1001, 0x2000, 0x2001}
    assert set(s.memory.addrs_for_hash(x.cache_key)) == {0x1000, 0x1001, 0x2000, 0x2001}

    s2 = s.copy()
    y = s2.solver.BVS("ref_test2", 16, explicit_name=True)
    s2.memory.store(0x2000, y)
    assert s2.memory.load(0x2000, 2) is y
    assert s.memory.load(0x2000, 2) is x
    assert set(s.memory.addrs_for_name("ref_test")) == {0x1000, 0x1001, 0x2000, 0x2001}
    assert set(s.memory.addrs_for_hash(x.cache_key)) == {0x1000, 0x1001, 0x2000, 0x2001}
    assert set(s2.memory.addrs_for_name("ref_test")) == {0x1000, 0x1001}
    assert set(s2.memory.addrs_for_hash(x.cache_key)) == {0x1000, 0x1001}
    assert set(s2.memory.addrs_for_name("ref_test2")) == {0x2000, 0x2001}
    assert set(s2.memory.addrs_for_hash(y.cache_key)) == {0x2000, 0x2001}

    s.memory.store(0x3000, s.solver.BVS("replace_old", 32, explicit_name=True))
    s.memory.store(0x3001, s.solver.BVV(b"AB"))
    assert set(s.memory.addrs_for_name("replace_old")) == {0x3000, 0x3003}
    assert s.solver.eval_upto(s.memory.load(0x3001, 2), 10, cast_to=bytes) == [b"AB"]

    # n = s.solver.BVS('replace_new', 32, explicit_name=True)
    # c = s.solver.BVS('replace_cool', 32, explicit_name=True)

    # mo = s.memory.memory_objects_for_name('replace_old')
    # assert len(mo) == 1
    # s.memory.replace_memory_object(next(iter(mo)), n)
    # assert set(s.memory.addrs_for_name('replace_old')) == set()
    # assert set(s.memory.addrs_for_name('replace_new')) == {0x3000, 0x3003}
    # assert s.solver.eval_upto(s.memory.load(0x3001, 2), 10, cast_to=bytes) == [b"AB"]

    # s.memory.store(0x4000, s.solver.If(n == 0, n+10, n+20))

    # assert set(s.memory.addrs_for_name('replace_new')) == {0x3000, 0x3003, 0x4000, 0x4001, 0x4002, 0x4003}
    # s.memory.replace_all(n, c)
    # assert set(s.memory.addrs_for_name('replace_old')) == set()
    # assert set(s.memory.addrs_for_name('replace_new')) == set()
    # assert set(s.memory.addrs_for_name('replace_cool')) == {0x3000, 0x3003, 0x4000, 0x4001, 0x4002, 0x4003}
    # assert s.solver.eval_upto(s.memory.load(0x3001, 2), 10, cast_to=bytes) == [b"AB"]

    # z = s.solver.BVV(0, 32)
    # s.memory.replace_all(c, z)
    # assert set(s.memory.addrs_for_name('replace_old')) == set()
    # assert set(s.memory.addrs_for_name('replace_new')) == set()
    # assert set(s.memory.addrs_for_name('replace_cool')) == set()
    # assert s.solver.eval_upto(s.memory.load(0x3001, 2), 10, cast_to=bytes) == [b"AB"]
    # assert s.solver.eval_upto(s.memory.load(0x3000, 4), 10) == [0x00414200]
    # assert s.solver.eval_upto(s.memory.load(0x4000, 4), 10) == [0x0000000a]

    # symbolic length
    x = s.solver.BVV(0x11223344, 32)
    y = s.solver.BVV(0xAABBCCDD, 32)
    n = s.solver.BVS("size", 32)
    s.add_constraints(n <= 4)
    s.memory.store(0x5000, x)
    s.memory.store(0x5000, y, size=n)
    assert set(s.solver.eval_upto(s.memory.load(0x5000, 4), 10)) == {
        0x11223344,
        0xAA223344,
        0xAABB3344,
        0xAABBCC44,
        0xAABBCCDD,
    }

    s1 = s.copy()
    s1.add_constraints(n == 1)
    assert set(s1.solver.eval_upto(s1.memory.load(0x5000, 4), 10)) == {0xAA223344}

    s4 = s.copy()
    s4.add_constraints(n == 4)
    assert set(s4.solver.eval_upto(s4.memory.load(0x5000, 4), 10)) == {0xAABBCCDD}

    # condition without fallback
    x = s.solver.BVV(0x11223344, 32)
    y = s.solver.BVV(0xAABBCCDD, 32)
    c = s.solver.BVS("condition", 32)
    s.memory.store(0x6000, x)
    s.memory.store(0x6000, y, condition=c == 1)
    assert set(s.solver.eval_upto(s.memory.load(0x6000, 4), 10)) == {0x11223344, 0xAABBCCDD}

    s0 = s.copy()
    s0.add_constraints(c == 0)
    assert set(s0.solver.eval_upto(s0.memory.load(0x6000, 4), 10)) == {0x11223344}

    s1 = s.copy()
    s1.add_constraints(c == 1)
    assert set(s1.solver.eval_upto(s1.memory.load(0x6000, 4), 10)) == {0xAABBCCDD}

    # condition with symbolic size
    x = s.solver.BVV(0x11223344, 32)
    y = s.solver.BVV(0xAABBCCDD, 32)
    c = s.solver.BVS("condition", 32)
    n = s.solver.BVS("size", 32)
    s.add_constraints(n <= 4)
    s.memory.store(0x8000, x)
    s.memory.store(0x8000, y, condition=c == 1, size=n)

    s0 = s.copy()
    s0.add_constraints(c == 0)
    assert set(s0.solver.eval_upto(s0.memory.load(0x8000, 4), 10)) == {0x11223344}

    s1 = s.copy()
    s1.add_constraints(c == 1)
    assert set(s1.solver.eval_upto(s1.memory.load(0x8000, 4), 10)) == {
        0x11223344,
        0xAA223344,
        0xAABB3344,
        0xAABBCC44,
        0xAABBCCDD,
    }


def test_abstract_memory():
    initial_memory = {0: b"A", 1: b"B", 2: b"C", 3: b"D"}

    s = SimState(
        mode="static",
        arch="AMD64",
        dict_memory_backer=initial_memory,
        add_options={o.ABSTRACT_SOLVER, o.ABSTRACT_MEMORY},
    )
    se = s.solver

    def to_vs(region, offset):
        return s.solver.VS(s.arch.bits, region, 0, offset)

    # Load a single-byte constant from global region
    expr = s.memory.load(to_vs("global", 2), 1)
    assert s.solver.eval(expr) == 0x43
    assert s.solver.max_int(expr) == 0x43
    assert s.solver.min_int(expr) == 0x43

    # Store a single-byte constant to global region
    s.memory.store(to_vs("global", 1), s.solver.BVV(b"D"), 1)
    expr = s.memory.load(to_vs("global", 1), 1)
    assert s.solver.eval(expr) == 0x44

    # Store a single-byte StridedInterval to global region
    si_0 = s.solver.BVS("unnamed", 8, 10, 20, 2)
    s.memory.store(to_vs("global", 4), si_0)

    # Load the single-byte StridedInterval from global region
    expr = s.memory.load(to_vs("global", 4), 1)
    assert s.solver.min_int(expr) == 10
    assert s.solver.max_int(expr) == 20
    assert s.solver.eval_upto(expr, 100) == [10, 12, 14, 16, 18, 20]

    # Store a two-byte StridedInterval object to global region
    si_1 = s.solver.BVS("unnamed", 16, 10, 20, 2)
    s.memory.store(to_vs("global", 5), si_1)

    # Load the two-byte StridedInterval object from global region
    expr = s.memory.load(to_vs("global", 5), 2)
    assert claripy.backends.vsa.identical(expr, si_1)

    # Store a four-byte StridedInterval object to global region
    si_2 = s.solver.BVS("unnamed", 32, 8000, 9000, 2)
    s.memory.store(to_vs("global", 7), si_2)

    # Load the four-byte StridedInterval object from global region
    expr = s.memory.load(to_vs("global", 7), 4)
    assert claripy.backends.vsa.identical(expr, s.solver.BVS("unnamed", 32, 8000, 9000, 2))

    # Test default values
    s.options.remove(o.SYMBOLIC_INITIAL_VALUES)
    expr = s.memory.load(to_vs("global", 100), 4)
    assert claripy.backends.vsa.identical(expr, s.solver.BVS("unnamed", 32, 0, 0, 0))

    # Test default values (symbolic)
    s.options.add(o.SYMBOLIC_INITIAL_VALUES)
    expr = s.memory.load(to_vs("global", 104), 4)
    assert claripy.backends.vsa.identical(expr, s.solver.BVS("unnamed", 32, 0, 0xFFFFFFFF, 1))
    assert claripy.backends.vsa.identical(expr, s.solver.BVS("unnamed", 32, -0x80000000, 0x7FFFFFFF, 1))

    #
    # Merging
    #

    # Merging two one-byte values
    s.memory.store(to_vs("function_merge", 0), s.solver.BVS("unnamed", 8, 0x10, 0x10, 0))
    a = s.copy()
    a.memory.store(to_vs("function_merge", 0), s.solver.BVS("unnamed", 8, 0x20, 0x20, 0))

    b = s.merge(a)[0]
    expr = b.memory.load(to_vs("function_merge", 0), 1)
    assert claripy.backends.vsa.identical(expr, s.solver.BVS("unnamed", 8, 0x10, 0x20, 0x10))

    #  |  MO(value_0)  |
    #  |  MO(value_1)  |
    # 0x20          0x24
    # Merge one byte in value_0/1 means merging the entire MemoryObject
    a = s.copy()
    a.memory.store(to_vs("function_merge", 0x20), se.SI(bits=32, stride=0, lower_bound=0x100000, upper_bound=0x100000))
    b = s.copy()
    b.memory.store(to_vs("function_merge", 0x20), se.SI(bits=32, stride=0, lower_bound=0x100001, upper_bound=0x100001))
    c = a.merge(b)[0]
    expr = c.memory.load(to_vs("function_merge", 0x20), 4)
    assert claripy.backends.vsa.identical(expr, se.SI(bits=32, stride=1, lower_bound=0x100000, upper_bound=0x100001))
    c_page = c.memory._regions["function_merge"]._pages[0]
    object_set = {
        c_page._get_object(0x20, 0),
        c_page._get_object(0x21, 0),
        c_page._get_object(0x22, 0),
        c_page._get_object(0x23, 0),
    }
    assert len(object_set) == 1

    a = s.copy()
    a.memory.store(
        to_vs("function_merge", 0x20), se.SI(bits=32, stride=0x100000, lower_bound=0x100000, upper_bound=0x200000)
    )
    b = s.copy()
    b.memory.store(to_vs("function_merge", 0x20), se.SI(bits=32, stride=0, lower_bound=0x300000, upper_bound=0x300000))
    c = a.merge(b)[0]
    expr = c.memory.load(to_vs("function_merge", 0x20), 4)
    assert claripy.backends.vsa.identical(
        expr, se.SI(bits=32, stride=0x100000, lower_bound=0x100000, upper_bound=0x300000)
    )
    object_set = {
        c_page._get_object(0x20, 0),
        c_page._get_object(0x21, 0),
        c_page._get_object(0x22, 0),
        c_page._get_object(0x23, 0),
    }
    assert len(object_set) == 1

    #
    # Widening
    #

    a = s.solver.SI(bits=32, stride=1, lower_bound=1, upper_bound=2)
    b = s.solver.SI(bits=32, stride=1, lower_bound=1, upper_bound=3)
    a = a.reversed
    b = b.reversed
    # widened = a.widen(b)
    # TODO: Added a proper test case
    # print widened.reversed

    # We are done!
    # Restore the old claripy standalone object
    # claripy.set_claripy(old_claripy_standalone)


def test_abstract_memory_find():
    initial_memory = {1: b"A", 2: b"B", 3: b"\x00"}

    s = SimState(
        mode="static",
        arch="AMD64",
        dict_memory_backer=initial_memory,
        add_options={o.ABSTRACT_SOLVER, o.ABSTRACT_MEMORY},
    )

    se = s.solver
    BVV = se.BVV
    VS = se.VS
    SI = se.SI

    s.memory.store(4, se.TSI(bits=64))

    def to_vs(region, offset):
        return VS(s.arch.bits, region, 0, offset)

    r, _, _ = s.memory.find(to_vs("global", 1), BVV(b"A"), 8)

    r_model = claripy.backends.vsa.convert(r)
    s_expected = claripy.backends.vsa.convert(SI(bits=64, to_conv=1))
    assert isinstance(r_model, claripy.vsa.ValueSet)
    assert list(r_model.regions.keys()) == ["global"]
    assert claripy.backends.vsa.identical(r_model.regions["global"], s_expected)

    r, _, _ = s.memory.find(to_vs("global", 1), BVV(b"B"), 8)
    r_model = claripy.backends.vsa.convert(r)
    s_expected = claripy.backends.vsa.convert(SI(bits=64, to_conv=2))
    assert isinstance(r_model, claripy.vsa.ValueSet)
    assert list(r_model.regions.keys()) == ["global"]
    assert claripy.backends.vsa.identical(r_model.regions["global"], s_expected)

    r, _, _ = s.memory.find(to_vs("global", 1), BVV(b"\0"), 8)
    r_model = claripy.backends.vsa.convert(r)
    s_expected = claripy.backends.vsa.convert(SI(bits=64, to_conv=3))
    assert isinstance(r_model, claripy.vsa.ValueSet)
    assert list(r_model.regions.keys()) == ["global"]
    assert claripy.backends.vsa.identical(r_model.regions["global"], s_expected)

    # Find in StridedIntervals
    r, _, _ = s.memory.find(to_vs("global", 4), BVV(b"\0"), 8)
    r_model = claripy.backends.vsa.convert(r)
    s_expected = claripy.backends.vsa.convert(SI(bits=64, stride=1, lower_bound=4, upper_bound=11))
    assert isinstance(r_model, claripy.vsa.ValueSet)
    assert list(r_model.regions.keys()) == ["global"]
    assert claripy.backends.vsa.identical(r_model.regions["global"], s_expected)


def test_registers():
    s = SimState(arch="AMD64")
    expr = s.registers.load("rax")
    assert s.solver.symbolic(expr)

    s.registers.store("rax", 0x31)
    expr = s.registers.load("rax")
    assert not s.solver.symbolic(expr)
    assert s.solver.eval(expr) == 0x00000031


def test_fullpage_write():
    s = SimState(arch="AMD64")
    a = s.solver.BVV(b"A" * 0x2000)
    s.memory.store(0, a)
    # assert len(s.memory.mem._pages) == 2
    # assert len(s.memory.mem._pages[0].keys()) == 0
    # assert len(s.memory.mem._pages[1].keys()) == 0
    assert s.memory.load(0, 0x2000) is a
    assert a.variables != s.memory.load(0x2000, 1).variables

    s = SimState(arch="AMD64")
    a = s.solver.BVV(b"A" * 2)
    s.memory.store(0x1000, a)
    s.memory.store(0x2000, a)
    assert a.variables == s.memory.load(0x2000, 1).variables
    assert a.variables == s.memory.load(0x2001, 1).variables
    assert a.variables != s.memory.load(0x2002, 1).variables

    s = SimState(arch="AMD64")
    x = s.solver.BVV(b"X")
    a = s.solver.BVV(b"A" * 0x1000)
    s.memory.store(1, x)
    s2 = s.copy()
    s2.memory.store(0, a)
    assert len(s.memory.changed_bytes(s2.memory)) == 0x1000

    s = SimState(arch="AMD64")
    s.memory._maximum_symbolic_size = 0x2000000
    a = s.solver.BVS("A", 0x1000000 * 8)
    s.memory.store(0, a)
    b = s.memory.load(0, 0x1000000)
    assert b is a


def test_symbolic_write():
    s = SimState(arch="AMD64", add_options={o.SYMBOLIC_WRITE_ADDRESSES})
    x = s.solver.BVS("x", 64)
    y = s.solver.BVS("y", 64)
    a = s.solver.BVV(b"A" * 0x10)
    b = s.solver.BVV(b"B")
    c = s.solver.BVV(b"C")
    d = s.solver.BVV(b"D")

    s.memory.store(0x10, a)
    s.add_constraints(x >= 0x10, x < 0x20)
    s.memory.store(x, b)

    for i in range(0x10, 0x20):
        assert len(s.solver.eval_upto(s.memory.load(i, 1), 10)) == 2

    s.memory.store(x, c)
    for i in range(0x10, 0x20):
        assert len(s.solver.eval_upto(s.memory.load(i, 1), 10)) == 2

    s2 = s.copy()
    s2.add_constraints(y >= 0x10, y < 0x20)
    s2.memory.store(y, d)
    for i in range(0x10, 0x20):
        assert len(s2.solver.eval_upto(s2.memory.load(i, 1), 10)) == 3


def test_concrete_memset():
    def _individual_test(state, base, val, size):
        # time it
        start = time.time()
        memset = SIM_PROCEDURES["libc"]["memset"]().execute(state, arguments=[base, state.solver.BVV(val, 8), size])
        elapsed = time.time() - start

        # should be done within 1 second
        assert elapsed <= 5
        # the result should be good
        byt_0 = memset.state.memory.load(base, 1)
        assert s.solver.eval_upto(byt_0, 10) == [val]
        byt_1 = memset.state.memory.load(base + 1, 1)
        assert s.solver.eval_upto(byt_1, 10) == [val]
        byt_2 = memset.state.memory.load(base + size - 1, 1)
        assert s.solver.eval_upto(byt_2, 10) == [val]

    BASE = 0x800000
    SIZE = 0x200000

    # Writes many zeros
    VAL = 0
    s = SimState(arch="AMD64")
    _individual_test(s, BASE, VAL, SIZE)

    # Writes many ones
    VAL = 1
    s = SimState(arch="AMD64")
    _individual_test(s, BASE, VAL, SIZE)


def test_false_condition():
    s = SimState(arch="AMD64")

    asdf = s.solver.BVV(b"asdf")
    fdsa = s.solver.BVV(b"fdsa")
    s.memory.store(0x1000, asdf)
    s.memory.store(0x1000, fdsa, condition=s.solver.false)
    s.memory.store(0, fdsa, condition=s.solver.false)

    assert s.memory.load(0x1000, 4) is asdf
    assert 0 not in s.memory._pages


def test_fast_memory():
    s = SimState(arch="AMD64", add_options={o.FAST_REGISTERS, o.FAST_MEMORY})

    s.regs.rax = 0x4142434445464748
    s.regs.rbx = 0x5555555544444444
    assert (s.regs.rax == 0x4142434445464748).is_true()
    assert (s.regs.rbx == 0x5555555544444444).is_true()

    _concrete_memory_tests(s)


def test_light_memory():
    s = SimState(arch="AMD64", plugins={"registers": SimLightRegisters()})
    assert type(s.registers) is SimLightRegisters

    assert s.regs.rax.symbolic
    s.regs.rax = 0x4142434445464748
    assert (s.regs.rax == 0x4142434445464748).is_true()

    assert s.regs.rbx.symbolic
    s.regs.rbx = 0x5555555544444444
    assert (s.regs.rbx == 0x5555555544444444).is_true()

    assert s.regs.rcx.symbolic

    s.regs.ah = 0
    assert (s.regs.rax == 0x4142434445460048).is_true()

    s.regs.cl = 0
    assert s.regs.rcx.symbolic


def test_crosspage_store():
    for memcls in [
        UltraPageMemory,
        ListPageMemory,
    ]:
        state = SimState(arch="x86", mode="symbolic", plugins={"memory": memcls()})

        state.regs.sp = 0xBAAAFFFC
        state.memory.store(state.regs.sp, b"\x01\x02\x03\x04" + b"\x05\x06\x07\x08")
        assert state.solver.eval(state.memory.load(state.regs.sp, 8)) == 0x0102030405060708

        state.memory.store(state.regs.sp, b"\x01\x02\x03\x04" + b"\x05\x06\x07\x08", endness="Iend_LE")
        assert state.solver.eval(state.memory.load(state.regs.sp, 8)) == 0x0807060504030201

        symbol = claripy.BVS("symbol", 64)
        state.memory.store(state.regs.sp, symbol)
        assert state.memory.load(state.regs.sp, 8) is symbol

        state.memory.store(state.regs.sp, symbol, endness="Iend_LE")
        assert state.memory.load(state.regs.sp, 8) is symbol.reversed


def test_mv_crosspage_store():
    for memcls in [
        MVPageMemory,
    ]:
        state = SimState(arch="x86", mode="symbolic", plugins={"memory": memcls()})

        mv = MultiValues(offset_to_values={0: {claripy.BVV(1337, 32)}, 4: {claripy.BVV(13371337, 8 * 5)}})
        state.memory.store(4096 - 3, mv)

        first_three_bytes = state.memory.load(4096 - 3, size=3)
        assert state.solver.eval_one(first_three_bytes.one_value()) == 1337 >> 8

        next_one_byte = state.memory.load(4096, size=1)
        assert state.solver.eval_one(next_one_byte.one_value()) == 1337 & 0xFF

        first_four_bytes = state.memory.load(4096 - 3, size=4)
        assert state.solver.eval_one(first_four_bytes.one_value()) == 1337

        all_bytes = state.memory.load(4096 - 3, size=9)
        assert state.solver.eval_one(all_bytes.one_value()) == (1337 << 40) | 13371337

        data = {
            0: {claripy.BVS("TOP", 32), claripy.BVV(0x56495254, 32)},
            4: {claripy.BVV(47, 8), claripy.BVV(85, 8)},
            5: {claripy.BVS("TOP", 32), claripy.BVV(0x414C5F53, 32)},
            9: {claripy.BVV(69, 8), claripy.BVV(47, 8)},
            10: {
                claripy.BVV(0x52564552, 32),
                claripy.BVV(0x56495254, 32),
                claripy.BVS("TOP", 32),
                claripy.BVV(0x63757272, 32),
            },
            14: {claripy.BVV(101, 8), claripy.BVV(47, 8), claripy.BVV(46, 8), claripy.BVV(85, 8)},
            15: {
                claripy.BVV(0x656E74, 24),
                claripy.BVV(0x6E7400, 24),
                claripy.BVV(0x414C5F, 24),
                claripy.BVS("TOP", 24),
            },
            18: {claripy.BVV(114, 8), claripy.BVS("TOP", 8), claripy.BVV(83, 8), claripy.BVV(47, 8)},
            19: {
                claripy.BVV(0x45525645, 32),
                claripy.BVS("TOP", 32),
                claripy.BVV(0x2E747278, 32),
                claripy.BVV(0x795B2564, 32),
            },
            23: {claripy.BVV(46, 8), claripy.BVV(82, 8), claripy.BVV(0, 8), claripy.BVV(93, 8)},
            24: {claripy.BVV(0x74727800, 32), claripy.BVV(0x2E69705B, 32), claripy.BVV(0x2E656E74, 32)},
            28: {
                claripy.BVV(0x72795B25645D2E69705B25645D2E636F75, 136),
                claripy.BVV(0x25645D2E636F756E74203D2025643B0A00, 136),
            },
            45: {claripy.BVV(110, 8), claripy.BVV(47, 8)},
            46: {claripy.BVV(0x74203D20, 32), claripy.BVS("TOP", 32)},
            50: {claripy.BVV(37, 8), claripy.BVV(47, 8)},
            51: {
                claripy.BVS("TOP", 32),
                claripy.BVV(0x56495254, 32),
                claripy.BVV(0x63757272, 32),
                claripy.BVV(0x643B0A00, 32),
            },
            55: {claripy.BVV(101, 8), claripy.BVV(85, 8), claripy.BVV(47, 8)},
            56: {claripy.BVV(0x6E7400, 24), claripy.BVV(0x414C5F, 24), claripy.BVS("TOP", 24)},
            59: {claripy.BVS("TOP", 8)},
            60: {claripy.BVV(0x45525645, 32), claripy.BVS("TOP", 32), claripy.BVV(0x2E747278, 32)},
            64: {claripy.BVV(46, 8), claripy.BVV(82, 8), claripy.BVV(0, 8)},
            65: {claripy.BVV(0x74727800, 32), claripy.BVV(0x2E656E74, 32)},
            69: {claripy.BVV(0x72795B25645D2E69705B25645D2E636F756E74203D2025643B0A00, 216)},
            96: {claripy.BVV(47, 8)},
            97: {claripy.BVS("TOP", 32)},
            101: {claripy.BVV(0x2E74727800, 40)},
        }
        mv = MultiValues(offset_to_values=data)
        state.memory.store(0x7FFEFF9C, mv)  # should not crash


def test_crosspage_read():
    state = SimState(arch="ARM")
    state.regs.sp = 0x7FFF0008
    state.stack_push(0x44556677)
    state.stack_push(0x1)
    state.stack_push(0x2)
    state.stack_push(0x3)
    state.stack_push(0x4)
    state.stack_push(0x99887766)
    state.stack_push(0x5)
    state.stack_push(0x105C8)
    state.stack_push(0x11223344)

    r1 = state.memory.load(state.regs.sp, 36)
    assert bytes.fromhex("77665544") in state.solver.eval(r1, cast_to=bytes)

    state.stack_push(0x10564)

    r2 = state.memory.load(state.regs.sp, 40)
    assert bytes.fromhex("77665544") in state.solver.eval(r2, cast_to=bytes)
    # assert s.solver.eval(r, 2) == ( 0xffeeddccbbaa998877665544, )


def test_address_wrap():
    for memcls in [UltraPageMemory, ListPageMemory]:
        state = SimState(arch="x86", mode="symbolic", plugins={"memory": memcls()})
        symbol = claripy.BVS("symbol", 64)

        state.memory.store(0xFFFFFFFF, symbol.get_byte(0))
        state.memory.store(0, b"\0" * 8)
        assert len(state.memory.load(0xFFFFFFFF, 8)) == 64

        state.memory.store(0xFFFFFFFF, b"ABCD")
        assert state.solver.eval(state.memory.load(0, 3)) == 0x424344

        state.memory.store(0xFFFFFFFF, symbol)
        assert state.memory.load(0, 1) is symbol[64 - 8 - 1 : 64 - 16]


def test_underconstrained():
    state = SimState(arch="AMD64", add_options={o.UNDER_CONSTRAINED_SYMEXEC})

    # test that under-constrained load is constrained
    ptr1 = state.memory.load(0x4141414141414000, size=8, endness="Iend_LE")
    assert ptr1.uc_alloc_depth == 0
    assert ptr1.uninitialized
    state.memory.load(ptr1, size=1)
    # ptr1 should have been constrained
    assert state.solver.min_int(ptr1) == state.solver.max_int(ptr1)

    # test that under-constrained store is constrained
    ptr2 = state.memory.load(0x4141414141414008, size=8, endness="Iend_LE")
    assert ptr2.uc_alloc_depth == 0
    assert ptr2.uninitialized
    state.memory.store(ptr2, b"\x41", size=1)
    # ptr2 should have been constrained
    assert state.solver.min_int(ptr2) == state.solver.max_int(ptr2)

    # ptr1 and ptr2 should not point to the same region
    assert state.solver.eval(ptr1) != state.solver.eval(ptr2)

    # uninitialized load and stores w/o uc_alloc_depth should not crash
    ptr3 = claripy.Concat(
        state.memory.load(0x4141414141414010, size=4, endness="Iend_LE"),
        state.memory.load(0x4141414141414014, size=4, endness="Iend_LE"),
    )
    assert ptr3.uninitialized
    assert ptr3.uc_alloc_depth is None  # because uc_alloc_depth doesn't carry across Concat
    # we don't care what these do, as long as they don't crash
    state.memory.store(ptr3, b"\x41", size=1)
    state.memory.load(ptr3, size=1)


def test_concrete_load_non_adjacent_pages():
    s = SimState(arch="AMD64", mode="symbolic", plugins={"memory": UltraPageMemory()})

    s.memory.store(0x100000, b"\x01" * 4096)
    s.memory.store(0x100000 + 4096, b"\x02" * 4096)
    mv = s.memory.concrete_load(0x100000 + 0xFFA, 400)
    assert len(mv) == 400, "Loading data across non-physically adjacent pages failed for ultra pages."
    assert mv == (b"\x01" * 6) + (b"\x02" * 394)


def test_hex_dump():
    s = SimState(arch="AMD64")
    addr = s.heap.allocate(0x20)
    s.memory.store(addr, claripy.Concat(claripy.BVV("ABCDEFGH"), claripy.BVS("symbolic_part", 24 * s.arch.bits)))
    dump = s.memory.hex_dump(addr, 0x20)
    assert (
        dump == "c0000000: 41424344 45464748 ???????? ???????? ABCDEFGH????????\n"
        "c0000010: ???????? ???????? ???????? ???????? ????????????????\n"
    )

    dump = s.memory.hex_dump(
        addr, 0x20, extra_constraints=(s.memory.load(addr + 0x10, 4) == 0xDEADBEEF,), solve=True, endianness="Iend_LE"
    )
    assert (
        dump == "c0000000: 44434241 48474645 ???????? ???????? ABCDEFGH????????\n"
        "c0000010: efbeadde ???????? ???????? ???????? ....????????????\n"
    )


def test_concrete_load():
    for memcls in [UltraPageMemory, ListPageMemory]:
        state = SimState(arch="AMD64", mode="symbolic", plugins={"memory": memcls()})
        state.memory.store(0x20000, b"aaaabbbbccccdddd")

        data, bitmap = state.memory.concrete_load(0x20000, 4, with_bitmap=True)
        data_bytes = bytes(d if b == 0 else 0 for d, b in zip(data, bitmap))
        assert data_bytes == b"aaaa"
        assert bitmap.tobytes() == b"\x00\x00\x00\x00"

        data, bitmap = state.memory.concrete_load(0x20004, 8, with_bitmap=True)
        data_bytes = bytes(d if b == 0 else 0 for d, b in zip(data, bitmap))
        assert data_bytes == b"bbbbcccc"
        assert bitmap.tobytes() == b"\x00\x00\x00\x00\x00\x00\x00\x00"

        state.memory.store(0x20001, claripy.BVS("flag", 8))
        data, bitmap = state.memory.concrete_load(0x20000, 4, with_bitmap=True)
        data_bytes = bytes(d if b == 0 else 0 for d, b in zip(data, bitmap))
        assert data_bytes == b"a\x00aa"
        assert bitmap.tobytes() == b"\x00\x01\x00\x00"

        expr = claripy.Concat(
            claripy.BVS("flag_0", 1),
            claripy.BVS("flag_1", 2),
            claripy.BVS("flag_2", 3),
            claripy.BVS("flag_3", 6),
            claripy.BVS("flag_4", 4),
        )
        state.memory.store(0x20001, expr)
        data, bitmap = state.memory.concrete_load(0x20000, 4, with_bitmap=True)
        data_bytes = bytes(d if b == 0 else 0 for d, b in zip(data, bitmap))
        assert data_bytes == b"a\x00\x00a"
        assert bitmap.tobytes() == b"\x00\x01\x01\x00"

        expr = claripy.Concat(
            claripy.BVS("flag_0", 1),
            claripy.BVV(1, 2),
            claripy.BVV(3, 3),
            claripy.BVV(6, 6),
            claripy.BVS("flag_4", 4),
        )
        state.memory.store(0x20005, expr)
        data, bitmap = state.memory.concrete_load(0x20004, 4, with_bitmap=True)
        data_bytes = bytes(d if b == 0 else 0 for d, b in zip(data, bitmap))
        assert data_bytes == b"b\x00\x00b"
        assert bitmap.tobytes() == b"\x00\x01\x01\x00"

        expr = claripy.Concat(
            claripy.BVV(7, 7),
            claripy.BVS("flag_0", 2),
            claripy.BVV(7, 7),
        )
        state.memory.store(0x20005, expr)
        data, bitmap = state.memory.concrete_load(0x20004, 4, with_bitmap=True)
        data_bytes = bytes(d if b == 0 else 0 for d, b in zip(data, bitmap))
        assert data_bytes == b"b\x00\x00b"
        assert bitmap.tobytes() == b"\x00\x01\x01\x00"

        expr = claripy.Concat(
            claripy.BVV(1, 1),
            claripy.BVS("flag_0", 14),
            claripy.BVV(1, 1),
        )
        state.memory.store(0x20005, expr)
        data, bitmap = state.memory.concrete_load(0x20004, 4, with_bitmap=True)
        data_bytes = bytes(d if b == 0 else 0 for d, b in zip(data, bitmap))
        assert data_bytes == b"b\x00\x00b"
        assert bitmap.tobytes() == b"\x00\x01\x01\x00"


def test_multivalued_list_page():
    state = SimState(arch="AMD64", mode="symbolic", plugins={"memory": MultiValuedMemory()})

    # strong update
    state.memory.store(0x100, claripy.BVV(0x40, 64))
    state.memory.store(0x100, claripy.BVV(0x80818283, 64))
    a = state.memory.load(0x100, size=8).one_value()
    assert a is not None
    assert a is claripy.BVV(0x80818283, 64)

    # strong update with partial overwrites
    state.memory.store(0x100, claripy.BVV(0x0, 64))
    state.memory.store(0x104, claripy.BVV(0x1337, 32))
    a = state.memory.load(0x100, size=8).one_value()
    assert a is not None
    assert a is claripy.BVV(0x1337, 64)

    # weak updates
    state.memory.store(0x120, claripy.BVV(0x40, 64))
    state.memory.store(0x120, claripy.BVV(0x85868788, 64), weak=True)
    a = state.memory.load(0x120, size=8)
    assert len(a.keys()) == 1
    assert 0 in a
    assert len(list(a.values())[0]) == 2
    assert {state.solver.eval_exact(item, 1)[0] for item in list(a.values())[0]} == {0x40, 0x85868788}

    # weak updates with symbolic values
    A = claripy.BVS("a", 64)
    state.memory.store(0x140, A, endness=state.arch.memory_endness)
    state.memory.store(0x141, claripy.BVS("b", 64), endness=state.arch.memory_endness, weak=True)
    a = state.memory.load(0x140, size=8)
    assert len(a.keys()) == 2
    assert 0 in a
    assert 1 in a
    assert len(list(a.values())[0]) == 1
    assert next(iter(a[0])) is A[7:0]
    assert len(a[1]) == 2


def test_conditional_concretization():
    class ZeroFillerMemory(UltraPageMemory):
        def _default_value(self, *args, size=None, **kwargs):
            return self.state.solver.BVV(0, size)

    state = SimState(arch="AMD64", mode="symbolic", plugins={"memory": ZeroFillerMemory()})
    state.options.add(o.ZERO_FILL_UNCONSTRAINED_MEMORY)

    cond = state.solver.BoolS("cond")
    addr = state.solver.BVS("addr", 32)

    state.memory.store(addr, 0x12345678, size=4, condition=cond, endness=state.arch.memory_endness)
    val = state.memory.load(addr, size=4, condition=cond, endness=state.arch.memory_endness)
    assert set(state.solver.eval_upto(cond, 2)) == {True, False}
    assert (val == 0x12345678).is_true()


if __name__ == "__main__":
    test_conditional_concretization()
    test_multivalued_list_page()
    test_address_wrap()
    test_concrete_load()
    test_crosspage_store()
    test_mv_crosspage_store()
    test_crosspage_read()
    test_fast_memory()
    test_light_memory()
    test_false_condition()
    test_symbolic_write()
    test_fullpage_write()
    test_memory()
    test_copy()
    test_abstract_memory()
    test_abstract_memory_find()
    test_registers()
    test_concrete_memset()
    test_underconstrained()
    test_hex_dump()
    test_concrete_load_non_adjacent_pages()
