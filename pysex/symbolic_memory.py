#!/usr/bin/env python
from z3 import *
import symbolic_value
import random

import logging


logging.basicConfig()
l = logging.getLogger("symbolic_memory")
l.setLevel(logging.DEBUG)


class Memory:
    def __init__(self):
        self.__mem = {}
        self.__limit = 1024

    def store(self, mmap, dst, src, bytes_size):
        # assert z3.is_bv(src), "Stored value unrecognized"
        # start = 0
        # for mem in range(0, bytes_size):
        #     ex = z3.Extract(start + 7, start, src)
        #     mmap[dst + (mem * 8)] = ex
        #     l.debug("Stored at 0x%s value: %s" % (str(dst + (mem * 8)), ex))
        #     start += 7
        return []

    #Load x bit from memory
    def load(self, cp_mem, expr, constraints):
        v = symbolic_value.Value(expr, constraints)
        r = ( v.min, v.max )
        l.debug("Index range: %s" % str(r))

        if abs(v.max - v.min) < self.__limit:
            w_k = range(v.min, v.max)
            w_k.append(v.max)
            ret = dict((i, self.__mem[i]) for i in w_k if i in self.__mem)
            #TODO manage cases in which no memory is intantiated yet
            if len(ret) == 0:
                l.debug("Reading without a previous writing, symbolic variable found")
            return ret

        #address concretization
        if len(cp_mem) == 0:
            return {}

        # unattainable under the current path
        cp_addr_att = cp_mem.keys()
        n_r = range(cp_addr_att[0], cp_addr_att[-1])
        n_r.append(cp_addr_att[-1])
        sub_dic = dict((i, self.__mem[i]) for i in n_r if i in self.__mem)
        sub_r = sub_dic.keys()
        for i in sub_r:
            if i not in cp_addr_att:
                return sub_r[i]

        i = random.randint(0, len(cp_mem))
        # one picked up randomly among the attainable ones
        return ret[i]
