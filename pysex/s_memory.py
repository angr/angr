#!/usr/bin/env python
import z3
import s_value
import random
import copy
import collections
import logging

logging.basicConfig()
l = logging.getLogger("s_memory")
l.setLevel(logging.INFO)

addr_mem_counter = 0
var_mem_counter = 0

class Cell:
        # Type: RWX bits
        def __init__(self, ctype, cnt):
                self.type = ctype | 4 # memory has to be readable
                self.cnt = cnt

class Memory:
        def __init__(self, initial=None, sys=None, id="mem"):
                def default_mem_value():
                        global var_mem_counter
                        var = z3.BitVec("%s_%d" % (id, var_mem_counter), 8)
                        var_mem_counter += 1
                        return Cell(6, var)

                #TODO: copy-on-write behaviour
                self.__mem = copy.copy(initial) if initial else collections.defaultdict(default_mem_value)
                self.__limit = 1024
                self.__bits = sys if sys else 64
                self.__max_mem = 2**self.__bits
                self.__freemem = [(0, self.__max_mem - 1)]

        def is_readable(self, addr):
                return self.__mem[addr].type & 4

        def is_writable(self, addr):
                return self.__mem[addr].type & 2

        def is_executable(self, addr):
                return self.__mem[addr].type & 1

        def read_from(self, addr, num_bytes):
                # Check every addresses insted only the first one?
                if self.is_readable(addr):
                        if num_bytes == 1:
                                return self.__mem[addr].cnt
                        else:
                                return z3.Concat(*[self.__mem[addr + i].cnt for i in range( 0, num_bytes)])
                else:
                        l.info("Attempted reading in a not readable location")
                        # FIX ME
                        return None

        def write_to(self, addr, cnt, w_type=7):
                if self.is_writable(addr):
                        for off in range(0, cnt.size() / 8):
                                self.__mem[(addr + off)].cnt = z3.Extract((off << 3) + 7, (off << 3), cnt)
                                self.__mem[(addr + off)].type = w_type #change permission

                        keys = [ -1 ] + self.__mem.keys() + [ self.__max_mem ]
                        self.__freemem = [ j for j in [ ((keys[i] + 1, keys[i+1] - 1) if keys[i+1] - keys[i] > 1 else ()) for i in range(len(keys)-1) ] if j ]
                        return 1
                else:
                        l.info("Attempted writing in a not writable location")
                        return 0

        def store(self, dst, cnt, constraints, w_type=7):
                v = s_value.Value(dst, constraints)
                ret = []

                if v.is_unique():
                        # if there's only one option, let's do it
                        addr = v.any()
                else:
                        fcon = z3.Or([ z3.And(z3.UGE(dst,a), z3.ULE(dst,b)) for a,b in self.__freemem ])
                        v_free = s_value.Value(dst, constraints + [ fcon ])

                        if v_free.satisfiable():
                                # ok, found some memory!
                                # free memory is always writable
                                addr = v_free.any()
                                ret = [dst == addr]
                        else:
                                # ok, no free memory that this thing can address
                                #FIX ME: check whether the memory is writable
                                addr = v.any()
                                ret = [dst == addr]

                self.write_to(addr, cnt, w_type)

                return ret

        #Load expressions from memory
        def load(self, dst, size, constraints=None):
                global addr_mem_counter
                expr = False
                ret = None
                size_b = size >> 3
                v = s_value.Value(dst, constraints)
                l.debug("Got load with size %d (%d bytes)" % (size, size_b))

                # specific read
                if v.is_unique():
                        addr = v.any()
                        expr = self.read_from(addr, size/8)
                        expr = z3.simplify(expr)
                        ret = expr, [ ]

                elif abs(v.max() - v.min()) <= self.__limit:
                        # within the limit to keep it symbolic
                        fcon = z3.Or([ z3.And(z3.UGE(dst,a), z3.ULE(dst,b)) for a,b in self.__freemem ])
                        v_free = s_value.Value(dst, constraints + [ z3.Not(fcon) ])

                        # try to point it to satisfiable memory if possible
                        if v_free.satisfiable():
                                to_iterate = v_free
                        else:
                                to_iterate = v

                        var = z3.BitVec("%s_addr_%s" %(dst, addr_mem_counter), self.__bits)
                        addr_mem_counter += 1
                        for addr in to_iterate.iter():
                                cnc = self.read_from(addr, size_b)
                                expr = z3.simplify(z3.Or(var == cnc, expr))

                        ret = expr, []
                else:
                        # too big, time to concretize!
                        if len(self.__mem):
                                #first try to point it somewhere valid
                                fcon = z3.Or([ dst == addr for addr in self.__mem.keys() ])
                                v_bsy = s_value.Value(dst, constraints + [ fcon ])

                                if v_bsy.satisfiable():
                                        addr = v_bsy.rnd()
                                else:
                                        addr = v.rnd() # at least the max value is included!

                                cnc = self.read_from(addr, size_b)
                                cnc = z3.simplify(cnc)
                                ret = cnc, [dst == addr]
                        else:
                                # otherwise, concretize to a random, page-aligned location, just for fun
                                # FIXME page aligned
                                addr = v.rnd()
                                cnc = self.read_from(addr, size_b)
                                cnc = z3.simplify(cnc)
                                ret = cnc, [dst == addr]

                return ret

        def get_bit_address(self):
                return self.__bits

        def pp(self):
                [l.info("%d: [%s, %s]" %(addr, self.__mem[addr].cnt, self.__mem[addr].type)) for addr in self.__mem.keys()]

        #TODO: copy-on-write behaviour
        def copy(self):
                return copy.copy(self)
