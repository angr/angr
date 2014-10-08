import simuvex
from simuvex.s_type import SimTypeString

import logging
l = logging.getLogger("simuvex.procedures.libc.strstr")

class strstr(simuvex.SimProcedure):
    def __init__(self, haystack_strlen=None, needle_strlen=None): # pylint: disable=W0231,
        haystack_addr = self.arg(0)
        needle_addr = self.arg(1)
        self.argument_types = { 0: self.ty_ptr(SimTypeString()),
                                   1: self.ty_ptr(SimTypeString())}
        self.return_type = self.ty_ptr(SimTypeString())

        strlen = simuvex.SimProcedures['libc.so.6']['strlen']
        strncmp = simuvex.SimProcedures['libc.so.6']['strncmp']

        haystack_strlen = self.inline_call(strlen, haystack_addr) if haystack_strlen is None else haystack_strlen
        needle_strlen = self.inline_call(strlen, needle_addr) if needle_strlen is None else needle_strlen

        # naive approach
        haystack_maxlen = haystack_strlen.max_null_index
        needle_maxlen = needle_strlen.max_null_index

        l.debug("strstr with size %d haystack and size %d needle...", haystack_maxlen, needle_maxlen)

        if needle_maxlen == 0:
            l.debug("... zero-length needle.")
            self.ret(haystack_addr)
            return
        elif haystack_maxlen == 0:
            l.debug("... zero-length haystack.")
            self.ret(self.state.BitVecVal(0, self.state.arch.bits))
            return

        if self.state.se.symbolic(needle_strlen.ret_expr):
            cases = [ [ needle_strlen.ret_expr == 0, haystack_addr ] ]
            exclusions = [ needle_strlen.ret_expr != 0 ]
            remaining_symbolic = self.state['libc'].max_symbolic_strstr
            for i in range(haystack_maxlen):
                l.debug("... case %d (%d symbolic checks remaining)", i, remaining_symbolic)

                # big hack!
                cmp_res = self.inline_call(strncmp, haystack_addr + i, needle_addr, needle_strlen.ret_expr, a_len=haystack_strlen, b_len=needle_strlen)
                c = self.state.se.And(*([ self.state.se.UGE(haystack_strlen.ret_expr, needle_strlen.ret_expr), cmp_res.ret_expr == 0 ] + exclusions))
                exclusions.append(cmp_res.ret_expr != 0)

                if self.state.se.symbolic(c):
                    remaining_symbolic -= 1

                #print "CASE:", c
                cases.append([ c, haystack_addr + i ])
                haystack_strlen.ret_expr = haystack_strlen.ret_expr - 1

                if remaining_symbolic == 0:
                    l.debug("... exhausted remaining symbolic checks.")
                    break

            cases.append([ self.state.se.And(*exclusions), 0 ])
            l.debug("... created %d cases", len(cases))
            r = self.state.se.ite_cases(cases, 0)
            c = [ self.state.se.Or(*[c for c,_ in cases]) ]
        else:
            needle_length = self.state.se.any_int(needle_strlen.ret_expr)
            needle_str = self.state.mem_expr(needle_addr, needle_length)

            r, c, i = self.state.memory.find(haystack_addr, needle_str, haystack_strlen.max_null_index, max_symbolic=self.state['libc'].max_symbolic_strstr, default=0)

            self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, needle_addr, needle_str, needle_length*8))
            self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, haystack_addr, self.state.BVV(0, 8), haystack_strlen.max_null_index*8))

        self.state.add_constraints(*c)
        self.ret(r)
