import angr
import sys

import claripy


def get_unconstrained_bytes(state, name, bits, source=None, memory=None):

    if (memory is not None and memory.category == 'mem' and
                angr.options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY in state.options):
        # CGC binaries zero-fill the memory for any allocated region
        # Reference: (https://github.com/CyberGrandChallenge/libcgc/blob/master/allocate.md)
        return state.se.BVV(0x0, bits)

    return state.se.Unconstrained(name, bits)

def get_obj_byte(obj, offset):

    # BVV slicing is extremely slow...
    if obj.op == 'BVV':
        assert type(obj.args[0]) == int
        value = obj.args[0]
        return claripy.BVV(value >> 8 * (len(obj) // 8 - 1 - offset) & 0xFF, 8)

    # slice the object using angr
    left = len(obj) - (offset * 8) - 1
    right = left - 8 + 1
    return obj[left:right]

def get_obj_bytes(obj, offset, size):

    # full obj is needed
    if offset == 0 and size * 8 == len(obj):
        return obj, size, size

    size = min(size, (len(obj) / 8) - offset)

    # slice the object... very slow :/
    left = len(obj) - (offset * 8) - 1
    right = left - (size * 8) + 1
    return obj[left:right], size, size


def convert_to_ast(state, data_e, size_e=None):
    """
    Make an AST out of concrete @data_e
    """
    if type(data_e) is str:
        # Convert the string into a BVV, *regardless of endness*
        bits = len(data_e) * 8
        data_e = state.se.BVV(data_e, bits)
    elif type(data_e) == int:
        data_e = state.se.BVV(data_e, size_e*8 if size_e is not None else state.arch.bits)
    else:
        data_e = data_e.to_bv()

    return data_e

def resolve_location_name(memory, name):

    stn_map = { 'st%d' % n: n for n in range(8) }
    tag_map = { 'tag%d' % n: n for n in range(8) }

    if memory.category == 'reg':
        if memory.state.arch.name in ('X86', 'AMD64'):
            if name in stn_map:
                return (((stn_map[name] + memory.load('ftop')) & 7) << 3) + memory.state.arch.registers['fpu_regs'][0], 8
            elif name in tag_map:
                return ((tag_map[name] + memory.load('ftop')) & 7) + memory.state.arch.registers['fpu_tags'][0], 1

        return memory.state.arch.registers[name]
    elif name[0] == '*':
        return memory.state.registers.load(name[1:]), None
    else:
        raise angr.errors.SimMemoryError("Trying to address memory with a register name.")

def reverse_addr_reg(memory, addr):

    assert memory.category == 'reg'
    assert type(addr) == int

    for name, offset_size in memory.state.arch.registers.items():
        offset = offset_size[0]
        size = offset_size[1]
        if addr in range(offset, offset + size):
            return name

    assert False
