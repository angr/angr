#!/usr/bin/env python
import z3
import s_value
import random
import copy
import pdb
import itertools

import logging


logging.basicConfig()
l = logging.getLogger("s_memory")
addr_mem_counter = 0
var_mem_counter = 0

l.setLevel(logging.DEBUG)

class Memory:
    def __init__(self, initial=None, sys=None):
        #TODO: copy-on-write behaviour
        self.__mem = copy.copy(initial) if ( initial != None) else {}
        self.__limit = 1024
        self.__freemem = [(0, (2**64) - 1)]
        self.__max_mem = 2**64
        self.__sys = sys if (sys != None) else 8


    def store(self, dst, cnt, constraints):
        if len(self.__mem) == self.__max_mem:
            raise Exception("Memory is full.")

        v = s_value.Value(dst, constraints)
        r = ( v.min, v.max )
        ret = []

        if v.max == v.min:
            addr = v.min
        else:
            s = z3.Solver()
            con = False

            for i in range(0, len(self.__freemem)):
                con = z3.Or(z3.And(z3.UGE(dst, self.__freemem[i][0]), z3.ULE(dst, self.__freemem[i][1])), con)

            con = z3.simplify(con)
            if con == True: #it is always satisfiable%
                #TODO: pick up one random instead
                addr = (long(self.__mem.keys()[-1]) + 1) if len(self.__mem.keys()) != 0 else 0
                ret = [dst == addr]
            else:
                s.add(con)
                if s.check() == z3.unsat:
                    raise Exception("Unable to store new values in memory.")
                addr = s.model().get_interp(dst)
                ret = [dst == addr]

        for off in range(0, cnt.size() / 8):
            self.__mem[(addr + off)] = z3.Extract((off << 3) + 7, (off << 3), cnt)

        keys = [ -1 ] + self.__mem.keys() + [ 2**64 ]
        self.__freemem = [ j for j in [ ((keys[i] + 1, keys[i+1] - 1) if keys[i+1] - keys[i] > 1 else ()) for i in range(len(keys)-1) ] if j ]

        return ret

    #Load expressions from memory
    def load(self, dst, size, constraints=None):
        global addr_mem_counter

        if len(self.__mem) == 0:
            return [ ], [ ]

        expr = False
        ret = None

        size_b = size >> 3
        v = s_value.Value(dst, constraints)
        r = ( v.min, v.max )

        if abs(v.max - v.min) <= self.__limit:
            w_k = range(v.min, v.max)
            w_k.append(v.max)
            p_k = list(set(w_k) & set(self.__mem.keys()))

            if len(p_k) == 0:
                l.debug("Loading operation outside its boundaries, symbolic variable found")
                expr = []
            else:
                var = z3.BitVec("%s_addr_%s" %(dst, addr_mem_counter), self.__sys)
                addr_mem_counter += 1

                # specific read
                if len(p_k)/size_b == 0:
                    addr = p_k[0]
                    expr = z3.Concat(*[ self.__mem[addr + i] for i in range( 0, size_b)])
                    expr = z3.simplify(expr)
                else:
                    try:
                        for cnt in range(0, len(p_k)/size_b):
                            cnc = z3.Concat(*[ self.__mem[p_k[i + (cnt*size_b)]] for i in range( 0, size_b)])
                            new_expr = z3.Or(var == cnc, expr)
                            expr = z3.simplify(new_expr)
                    except:
                        l.debug("Loading not mutiple of %d" % size_b)
            ret = expr, []
        else:
            pos = range(0, len(self.__mem.keys()) / size_b)
            addr = random.choice(pos)
            cnc = z3.Concat(*[ self.__mem[(addr*size_b) + i] for i in range( 0, size_b)])
            cnc = z3.simplify(cnc)
            pdb.set_trace()
            ret = cnc, [dst == addr]

        return ret

    def get_bit_address(self):
        return self.__sys

    #TODO: copy-on-write behaviour
    def copy(self):
        return copy.copy(self)
