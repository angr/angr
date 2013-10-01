#!/usr/bin/env python
from z3 import *
import s_value
import random
import copy

import logging


logging.basicConfig()
l = logging.getLogger("s_memory")
l.setLevel(logging.DEBUG)


class Memory:
    def __init__(self, initial=None):
        #TODO: copy-on-write behaviour
        self.__mem = copy.deepcopy(initial) if ( initial != None) else {}
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
    def load(self, expr, constraints=None, size=None):
        if len(self.__mem) == 0:
            return None

        v = s_value.Value(expr, constraints)
        r = ( v.min, v.max )

        if abs(v.max - v.min) < self.__limit:
            w_k = range(v.min, v.max)
            w_k.append(v.max)
            ret = dict((i, self.__mem[i]) for i in w_k if i in self.__mem)
            if len(ret) == 0:
                #TODO manage cases in which no memory is intantiated yet
                l.debug("Load operation outside its boundaries, symbolic variable found")
                return None
            else:
                expr = self._mem[w_k[0]]
                w_k.pop(0)

                for i in w_k:
                    if size != None:
                        size--
                        if size == 0:
                            break
                    expr = z3.Or(expr == True, self._mem[i] == True)
                    expr = z3.simplify(expr)

                return z3.simplify(expr)

        # unattainable under the current path
        # cp_addr_att = cp_mem.keys()
        # n_r = range(cp_addr_att[0], cp_addr_att[-1])
        # n_r.append(cp_addr_att[-1])
        # sub_dic = dict((i, self.__mem[i]) for i in n_r if i in self.__mem)
        # sub_r = sub_dic.keys()
        # for i in sub_r:
        #     if i not in cp_addr_att:
        #         return sub_r[i]

        i = random.randint(0, len(cp_mem))
        # one picked up randomly among the attainable ones
        return ret[i]

    #TODO: copy-on-write behaviour
    def copy(self):
        return copy.deepcopy(self)
