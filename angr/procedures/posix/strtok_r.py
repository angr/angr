import angr

import logging
l = logging.getLogger(name=__name__)

class strtok_r(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, str_ptr, delim_ptr, save_ptr, str_strlen=None, delim_strlen=None):
        if self.state.libc.simple_strtok:
            malloc = angr.SIM_PROCEDURES['libc']['malloc']
            token_ptr = self.inline_call(malloc, self.state.libc.strtok_token_size).ret_expr
            r = self.state.solver.If(self.state.solver.Unconstrained('strtok_case', self.state.arch.bits) == 0, token_ptr, self.state.solver.BVV(0, self.state.arch.bits))
            self.state.libc.strtok_heap.append(token_ptr)
            return r
        else:
            strstr = angr.SIM_PROCEDURES['libc']['strstr']
            strlen = angr.SIM_PROCEDURES['libc']['strlen']

            l.debug("Doin' a strtok_r!")
            l.debug("... geting the saved state")

            saved_str_ptr = self.state.memory.load(save_ptr, self.state.arch.bytes, endness=self.state.arch.memory_endness)
            start_ptr = self.state.solver.If(str_ptr == 0, saved_str_ptr, str_ptr)

            l.debug("... getting the lengths")
            str_strlen = self.inline_call(strlen, start_ptr) if str_strlen is None else str_strlen
            delim_strlen = self.inline_call(strlen, delim_ptr) if delim_strlen is None else delim_strlen

            l.debug("... STRTOK SLOW PATH (symbolic-length delimiteter and/or string)")
            l.debug("... calling strstr")
            where = self.inline_call(strstr, start_ptr, delim_ptr, haystack_strlen=str_strlen, needle_strlen=delim_strlen)
            write_length = self.state.solver.If(where.ret_expr != 0, delim_strlen.ret_expr, 0)
            write_content = self.state.solver.BVV(0, delim_strlen.max_null_index*8)

            # do a symbolic write (we increment the limit because of the possibility that the write target is 0, in which case the length will be 0, anyways)
            l.debug("... doing the symbolic write")
            self.state.memory.store(where.ret_expr, write_content, size=write_length, strategy=["symbolic_nonzero", "any"], limit=str_strlen.max_null_index+1)

            l.debug("... creating the return address")
            new_start = write_length + where.ret_expr
            new_state = self.state.solver.If(new_start != 0, new_start, start_ptr)

            l.debug("... saving the state")
            self.state.memory.store(save_ptr, new_state, endness=self.state.arch.memory_endness)

            l.debug("... done")
            return new_start
