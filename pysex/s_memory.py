#!/usr/bin/env python
from z3 import *
import s_value
import random
import copy
import pdb
import logging


logging.basicConfig()
l = logging.getLogger("s_memory")
l.setLevel(logging.DEBUG)


class Memory:
    def __init__(self, initial=None, sys=None):
        #TODO: copy-on-write behaviour
        self.__mem = copy.copy(initial) if ( initial != None) else {}
        self.__limit = 1024
        self.__sys = sys if (sys != None) else 8

    def store(self, expr_dst, expr_src, constraints_dst=None, constraints_src=None):
        pdb.set_trace()
        if len(self.__mem) == 0:
            i = random.randint(0, 2**self.__sys - 1)
            self.__mem[i] = cnt
            return

        v = s_value.Value(expr_dst, constraints_dst)
        r = ( v.min, v.max )
        w_k = range(v.min, v.max)
        w_k.append(v.max)

        # use z3.sover()? It returns one solution

        if abs(v.max - v.min) < self.__limit:
            ret = dict((i, self.__mem[i]) for i in w_k if i in self.__mem)
            if len(ret) != 0: #ORed writings
                for i in w_k:
                    self._mem[i] = z3.Or(cnt == True, self._mem[i] == True)
                    self._mem[i] = z3.simplify(self._mem[i])
            else:
                i = random.choice(w_k)
                self.__mem[w_k[i]] = cnt
        else:
            #which one should we write?
            #TODO: for the moment one that is free
            i = random.randint(0, 2**self.__sys - 1)
            if i not in self.__mem.keys():
                self.__mem[i] = cnt

        return

    #Load expressions from memory
    def load(self, src, dst, constraints=None):
        if len(self.__mem) == 0:
            return None

        expr = False
        ret = None
        v = s_value.Value(src, constraints)
        r = ( v.min, v.max )

        if abs(v.max - v.min) < self.__limit:
            w_k = range(v.min, v.max)
            w_k.append(v.max)
            p_k = list(set(w_k) & set(self.__mem.keys()))
            if len(p_k) == 0:
                l.debug("Load operation outside its boundaries, symbolic variable found")
            else:
                for i in p_k:
                    new_expr = z3.Or(dst == self.__mem[i], expr)
                    expr = z3.simplify(new_expr)
                ret = expr
        else:
            # one picked up randomly among the attainable ones
            i = random.choice(self.__mem.keys())
            ret = self.__mem[i]

        return ret

    #TODO: copy-on-write behaviour
    def copy(self):
        return copy.copy(self)
