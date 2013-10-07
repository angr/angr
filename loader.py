#!/usr/bin/env python

import pysex
import idalink
import z3

def load_binary(ida):
    mem = pysex.s_memory.Memory()
    dst = z3.BitVec('dst', mem.get_bit_address())

    for k in ida.mem.keys():
        bit_len = ((ida.mem[k].bit_length() / 8) + (1 if ida.mem[k].bit_length() % 8 else 0)) * 8
        if bit_len == 0:
            bit_len = 8
        mem.store(dst, z3.BitVecVal(ida.mem[k], bit_len), [dst == k], 4)

    return mem
