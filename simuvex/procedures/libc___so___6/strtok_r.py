import simuvex
from simuvex.s_type import SimTypeString

import logging
l = logging.getLogger("simuvex.procedures.libc.strtok_r")

class strtok_r(simuvex.SimProcedure):
    def __init__(self, str_strlen=None, delim_strlen=None): # pylint: disable=W0231,
        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: self.ty_ptr(SimTypeString()),
                               2: self.ty_ptr(self.ty_ptr(SimTypeString()))}
        self.return_type = self.ty_ptr(SimTypeString())

        if self.state['libc'].simple_strtok:
            str_ptr = self.arg(0)
            delim_ptr = self.arg(1)
            save_ptr = self.arg(2)

            malloc = simuvex.SimProcedures['libc.so.6']['malloc']
            token_ptr = self.inline_call(malloc, self.state['libc'].strtok_token_size).ret_expr
            r = self.state.se.If(self.state.BV('strtok_case', self.state.arch.bits) == 0, token_ptr, self.state.BVV(0, self.state.arch.bits))
            self.state['libc'].strtok_heap.append(token_ptr)
            self.ret(r)
        else:
            strstr = simuvex.SimProcedures['libc.so.6']['strstr']
            strlen = simuvex.SimProcedures['libc.so.6']['strlen']

            l.debug("Doin' a strtok_r!")

            str_ptr = self.arg(0)
            delim_ptr = self.arg(1)
            save_ptr = self.arg(2)

            l.debug("... geting the saved state")

            saved_str_ptr = self.state.mem_expr(save_ptr, self.state.arch.bytes, endness=self.state.arch.memory_endness)
            start_ptr = self.state.se.If(str_ptr == 0, saved_str_ptr, str_ptr)

            l.debug("... getting the lengths")
            str_strlen = self.inline_call(strlen, start_ptr) if str_strlen is None else str_strlen
            delim_strlen = self.inline_call(strlen, delim_ptr) if delim_strlen is None else delim_strlen

            l.debug("... STRTOK SLOW PATH (symbolic-length delimiteter and/or string)")
            l.debug("... calling strstr")
            where = self.inline_call(strstr, start_ptr, delim_ptr, haystack_strlen=str_strlen, needle_strlen=delim_strlen)
            write_length = self.state.se.If(where.ret_expr != 0, delim_strlen.ret_expr, 0)
            write_content = self.state.se.BitVecVal(0, delim_strlen.max_null_index*8)

            # do a symbolic write (we increment the limit because of the possibility that the write target is 0, in which case the length will be 0, anyways)
            l.debug("... doing the symbolic write")
            self.state.store_mem(where.ret_expr, write_content, size=write_length, strategy=["symbolic_nonzero", "any"], limit=str_strlen.max_null_index+1)

            l.debug("... creating the return address")
            new_start = write_length + where.ret_expr
            new_state = self.state.se.If(new_start != 0, new_start, start_ptr)

            l.debug("... saving the state")
            self.state.store_mem(save_ptr, new_state, endness=self.state.arch.memory_endness)

            l.debug("... done")
            self.ret(new_start)
