#!/usr/bin/env python
import z3
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

    def store(self, dst, var, constraints):
        if len(self.__mem) == 2**self.__sys:
            raise Exception("Memory is full.")

        if len(self.__mem) == 0:
            i = random.randint(0, 2**self.__sys - 1)
            self.__mem[i] = constraints
            return i

        v = s_value.Value(dst, constraints)
        r = ( v.min, v.max )

        if abs(v.max - v.min) < self.__limit:
            w_k = range(v.min, v.max)
            w_k.append(v.max)
            p_k = list(set(w_k) & set(self.__mem.keys()))
            if len(p_k) != 0: #ORed writings
                for i in p_k:
                    self._mem[i] = z3.Or(var == constraints, self._mem[i])
                    self._mem[i] = z3.simplify(self._mem[i])
            else:
                i = random.choice(p_k)
                self.__mem[p_k[i]] = constraints
        else:
            #which one should we write?
            #TODO: for the moment one that is free
            while 1: # TODO improve this approach!
                i = random.randint(0, 2**self.__sys - 1)
                if i not in self.__mem.keys():
                    self.__mem[i] = constraints
                    return i

        return None

    #Load expressions from memory
    def load(self, dst, var, constraints=None):
        if len(self.__mem) == 0:
            return None
        expr = False
        ret = None
        v = s_value.Value(dst, constraints)
        r = ( v.min, v.max )

        if abs(v.max - v.min) < self.__limit:
            w_k = range(v.min, v.max)
            w_k.append(v.max)
            p_k = list(set(w_k) & set(self.__mem.keys()))
            if len(p_k) == 0:
                l.debug("Load operation outside its boundaries, symbolic variable found")
            else:
                for i in p_k:
                    expr = z3.Or(var == self.__mem[i], expr)
                    expr = z3.simplify(expr)
                ret = expr
        else:
            # one picked up randomly among the attainable ones
            i = random.choice(self.__mem.keys())
            ret = self.__mem[i]

        return ret

    def get_bit_address(self):
        return self.__sys

    #TODO: copy-on-write behaviour
    def copy(self):
        return copy.copy(self)
