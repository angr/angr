import claripy
import nose
import ctypes

from archinfo import Endness
from angr import SimState
from angr.sim_type import register_types, parse_types

def test_simple_concrete():
    s = SimState(arch="AMD64")
    addr = 0xba5e0

    def check_read(val):
        nose.tools.assert_equal(s.se.eval(s.memory.load(addr, 8, endness=Endness.LE), cast_to=int), val)

        nose.tools.assert_equal(s.mem[addr].char.concrete, chr(val & 0xFF))
        nose.tools.assert_equal(s.mem[addr].byte.concrete, val & 0xFF)

        nose.tools.assert_equal(s.mem[addr].int16_t.concrete, ctypes.c_int16(val & 0xFFFF).value)
        nose.tools.assert_equal(s.mem[addr].uint16_t.concrete, val & 0xFFFF)

        nose.tools.assert_equal(s.mem[addr].qword.concrete, val)

    s.memory.store(addr, claripy.BVV(0x11223344aabbcc7d, 64), endness=Endness.LE)
    check_read(0x11223344aabbcc7d)

    # test storing
    s.mem[addr].uint16_t = 0xef6d
    check_read(0x11223344aabbef6d)

def test_string_concrete():
    s = SimState(arch="AMD64")
    addr = 0xba5e0

    def check_read(val):
        nose.tools.assert_equal(s.se.eval(s.memory.load(addr, len(val)), cast_to=str), val)
        nose.tools.assert_equal(s.se.eval(s.memory.load(addr + len(val), 1), cast_to=int), 0)

        nose.tools.assert_equal(s.mem[addr].string.concrete, val)

    s.memory.store(addr, "a string!\0")
    check_read("a string!")

    # not supported yet
    # s.mem[addr].string = "shorter"
    # check_read("shorter")

    # s.mem[addr].string = "a longer string"
    # check_read("a longer string")

def test_array_concrete():
    s = SimState(arch="AMD64")
    addr = 0xba5e0

    s.memory.store(addr, claripy.BVV(0x1, 32), endness=Endness.LE)
    s.memory.store(addr + 4, claripy.BVV(0x2, 32), endness=Endness.LE)
    s.memory.store(addr + 8, claripy.BVV(0x3, 32), endness=Endness.LE)
    s.memory.store(addr + 12, claripy.BVV(0x4, 32), endness=Endness.LE)
    s.memory.store(addr + 16, claripy.BVV(0x5, 32), endness=Endness.LE)

    nose.tools.assert_equal(s.mem[addr].dword.array(5).concrete, [0x1, 0x2, 0x3, 0x4, 0x5])
    nose.tools.assert_equal(s.mem[addr].dword.array(5)[2].concrete, 0x3)
    nose.tools.assert_equal(s.mem[addr].qword.array(2).concrete, [0x0000000200000001, 0x0000000400000003])
    nose.tools.assert_equal(s.mem[addr].dword.array(2).array(2).concrete, [[0x1, 0x2], [0x3, 0x4]])

    s.mem[addr].dword.array(5)[3] = 10
    nose.tools.assert_equals(s.se.eval(s.memory.load(addr + 12, 4, endness=Endness.LE), cast_to=int), 10)

    s.mem[addr].dword.array(5).store([20,2,3,4,5])
    nose.tools.assert_equals(s.mem[addr].dword.array(4).concrete, [20,2,3,4])

    s.mem[addr].dword.array(2).array(2).store([[1,2], [4,3]])
    nose.tools.assert_equals(s.mem[addr].dword.array(4).concrete, [1,2,4,3])

def test_pointer_concrete():
    s = SimState(arch="AMD64")
    addr = 0xba5e0
    ptraddr = 0xcd0

    s.memory.store(ptraddr, claripy.BVV(addr, 64), endness=Endness.LE)
    s.memory.store(addr, "abcdef\0")

    nose.tools.assert_equal(s.mem[ptraddr].deref.string.concrete, "abcdef")
    s.mem[ptraddr].deref.dword = 123954
    nose.tools.assert_equal(s.se.eval(s.memory.load(addr, 4, endness=Endness.LE), cast_to=int), 123954)
    nose.tools.assert_equal(s.mem[ptraddr].deref.dword.concrete, 123954)

def test_structs():
    s = SimState(arch='AMD64')

    register_types(parse_types("""
struct abcd {
  int a;
  long b;
};
"""))

    s.mem[0x8000].struct.abcd = {'a': 10, 'b': 20}
    assert s.mem[0x8000].struct.abcd.a.concrete == 10
    assert s.solver.eval(s.memory.load(0x8000, 16), cast_to=str) == '0a000000000000001400000000000000'.decode('hex')


if __name__ == '__main__':
    test_simple_concrete()
    test_string_concrete()
    test_array_concrete()
    test_pointer_concrete()
