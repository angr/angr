#!/usr/bin/env python
from z3 import *
import symbolic_value
import logging


logging.basicConfig()
l = logging.getLogger("symbolic_memory")
l.setLevel(logging.DEBUG)

    #Store value in memory (size has to be expressed in bytes)
def store(mmap, dst, src, bytes_size):
    # assert z3.is_bv(src), "Stored value unrecognized"
    # start = 0
    # for mem in range(0, bytes_size):
    #     ex = z3.Extract(start + 7, start, src)
    #     mmap[dst + (mem * 8)] = ex
    #     l.debug("Stored at 0x%s value: %s" % (str(dst + (mem * 8)), ex))
    #     start += 7
    return []

    #Load x bit from memory
def load(expr, constraints):
    v = symbolic_value.Value(expr, constraints)
    r = ( v.min, v.max )
    l.debug("Index range: %s" % str(r))
    # value = {}
    # for mem in range(0, bytes_size):
    #     try:
    #         value[mem] = mmap[dst + (mem * 8)]
    #         l.debug("Loaded from 0x%s value: %s" % (str(dst + (mem * 8)), value[mem]))
    #     except:
    #         l.debug("No value previously loaded. Symbolic Variable found!")
    #         _sym_var.append(dst + (mem * 8))
    # return value
    return []
