from collections import OrderedDict

import angr
import claripy
import ctypes

from archinfo import Endness
from angr import SimState
from angr.sim_type import register_types, parse_types, SimStruct, SimTypeNumOffset


def test_simple_concrete():
    s = SimState(arch="AMD64")
    addr = 0xBA5E0

    def check_read(val):
        assert s.solver.eval(s.memory.load(addr, 8, endness=Endness.LE), cast_to=int) == val

        assert s.mem[addr].char.concrete == chr(val & 0xFF).encode()
        assert s.mem[addr].byte.concrete == val & 0xFF

        assert s.mem[addr].int16_t.concrete == ctypes.c_int16(val & 0xFFFF).value
        assert s.mem[addr].uint16_t.concrete == val & 0xFFFF

        assert s.mem[addr].qword.concrete == val

    s.memory.store(addr, claripy.BVV(0x11223344AABBCC7D, 64), endness=Endness.LE)
    check_read(0x11223344AABBCC7D)

    # test storing
    s.mem[addr].uint16_t = 0xEF6D
    check_read(0x11223344AABBEF6D)


def test_string_concrete():
    s = SimState(arch="AMD64")
    addr = 0xBA5E0

    def check_read(val):
        assert s.solver.eval(s.memory.load(addr, len(val)), cast_to=bytes) == val
        assert s.solver.eval(s.memory.load(addr + len(val), 1), cast_to=int) == 0

        assert s.mem[addr].string.concrete == val

    s.memory.store(addr, b"a string!\0")
    check_read(b"a string!")

    # not supported yet
    # s.mem[addr].string = "shorter"
    # check_read(b"shorter")

    # s.mem[addr].string = "a longer string"
    # check_read(b"a longer string")


def test_array_concrete():
    s = SimState(arch="AMD64")
    addr = 0xBA5E0

    s.memory.store(addr, claripy.BVV(0x1, 32), endness=Endness.LE)
    s.memory.store(addr + 4, claripy.BVV(0x2, 32), endness=Endness.LE)
    s.memory.store(addr + 8, claripy.BVV(0x3, 32), endness=Endness.LE)
    s.memory.store(addr + 12, claripy.BVV(0x4, 32), endness=Endness.LE)
    s.memory.store(addr + 16, claripy.BVV(0x5, 32), endness=Endness.LE)

    assert s.mem[addr].dword.array(5).concrete == [0x1, 0x2, 0x3, 0x4, 0x5]
    assert s.mem[addr].dword.array(5)[2].concrete == 0x3
    assert s.mem[addr].qword.array(2).concrete == [
        0x0000000200000001,
        0x0000000400000003,
    ]
    assert s.mem[addr].dword.array(2).array(2).concrete == [[0x1, 0x2], [0x3, 0x4]]

    s.mem[addr].dword.array(5)[3] = 10
    assert s.solver.eval(s.memory.load(addr + 12, 4, endness=Endness.LE), cast_to=int) == 10

    s.mem[addr].dword.array(5).store([20, 2, 3, 4, 5])
    assert s.mem[addr].dword.array(4).concrete == [20, 2, 3, 4]

    s.mem[addr].dword.array(2).array(2).store([[1, 2], [4, 3]])
    assert s.mem[addr].dword.array(4).concrete == [1, 2, 4, 3]


def test_pointer_concrete():
    s = SimState(arch="AMD64")
    addr = 0xBA5E0
    ptraddr = 0xCD0

    s.memory.store(ptraddr, claripy.BVV(addr, 64), endness=Endness.LE)
    s.memory.store(addr, b"abcdef\0")

    assert s.mem[ptraddr].deref.string.concrete == b"abcdef"
    s.mem[ptraddr].deref.dword = 123954
    assert s.solver.eval(s.memory.load(addr, 4, endness=Endness.LE), cast_to=int) == 123954
    assert s.mem[ptraddr].deref.dword.concrete == 123954


def test_structs():
    s = SimState(arch="AMD64")

    register_types(
        parse_types(
            """
struct test_structs {
  int a;
  long b;
};
"""
        )
    )

    s.memory.store(0x8000, bytes(16))
    s.mem[0x8000].struct.test_structs = {"a": 10, "b": 20}
    assert s.mem[0x8000].struct.test_structs.a.concrete == 10
    assert s.solver.eval(s.memory.load(0x8000, 16), cast_to=bytes) == bytes.fromhex("0a000000000000001400000000000000")


def test_struct_bitfield_simple():
    """
    Tests if a struct with bitfields like
    struct {
        uint32_t a:8, b:1, c:23;
    }
    can be used with a memview
    :return:
    """
    state = SimState(arch="AMD64")
    register_types(
        SimStruct(
            name="bitfield_struct",
            pack=True,
            fields=OrderedDict(
                [
                    ("a", SimTypeNumOffset(8, signed=False)),
                    ("b", SimTypeNumOffset(1, signed=False)),
                    ("c", SimTypeNumOffset(23, signed=False)),
                ]
            ),
        )
    )

    data = [
        (b"\x0e\x02\x00\x00", (14, 0, 1)),
        (b"\x14T\x00\x00", (20, 0, 42)),
        (b"\x04\n\x01\x00", (4, 0, 133)),
        (b"\x04j\x01\x00", (4, 0, 181)),
        (b"\x04\xa2\x01\x00", (4, 0, 209)),
        (b"\x04\xf4\x01\x00", (4, 0, 250)),
        (b"\x04\\\x02\x00", (4, 0, 302)),
        (b"\x04\x98\x02\x00", (4, 0, 332)),
        (b"\x04\xe0\x02\x00", (4, 0, 368)),
        (b"\x04\x1e\x03\x00", (4, 0, 399)),
    ]
    state.memory.store(
        0x8000,
        b"\x0e\x02\x00\x00"
        b"\x14T\x00\x00"
        b"\x04\n\x01\x00"
        b"\x04j\x01\x00"
        b"\x04\xa2\x01\x00"
        b"\x04\xf4\x01\x00"
        b"\x04\\\x02\x00"
        b"\x04\x98\x02\x00"
        b"\x04\xe0\x02\x00"
        b"\x04\x1e\x03\x00",
    )
    view = state.mem[0x8000].struct.bitfield_struct.array(5)
    for idx, (b, result) in enumerate(data):
        v = view[idx]
        s = v.concrete
        assert s.a == result[0], f"Field a was {s.a}, expected {result[0]}, from bytes {b}"
        assert v.a.concrete == result[0], f"Field a was {v.a.concrete}, expected {result[0]}, from bytes {b}"

        assert s.b == result[1], f"Field b was {s.b}, expected {result[1]}, from bytes {b}"
        assert v.b.concrete == result[1], f"Field b was {s.b}, expected {result[1]}, from bytes {b}"

        assert s.c == result[2], f"Field c was {s.c}, expected {result[2]}, from bytes {b}"
        assert v.c.concrete == result[2], f"Field c was {v.c.concrete}, expected {result[2]}, from bytes {b}"


def test_struct_bitfield_complex():
    bitfield_struct2 = angr.types.parse_type(
        """struct bitfield_struct2
    {
        uint64_t    target    : 36,
                    high8     :  8,
                    reserved  :  7,
                    next      : 12,
                    bind      :  1;
    }"""
    )

    angr.types.register_types(bitfield_struct2)
    state = SimState(arch="AMD64")
    state.memory.store(0x1000, b"\xb3\xc7\xe9|\xad\xd7\xee$")  # store some random data
    struct = state.mem[0x1000].struct.bitfield_struct2.concrete
    assert struct.target == 0xD7CE9C7B3
    assert struct.high8 == 0x7A
    assert struct.next == 0x49D
    assert struct.bind == 0
    pass


if __name__ == "__main__":
    test_simple_concrete()
    test_string_concrete()
    test_array_concrete()
    test_pointer_concrete()
    test_structs()
    test_struct_bitfield_simple()
    test_struct_bitfield_complex()
