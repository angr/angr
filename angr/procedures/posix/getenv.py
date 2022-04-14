import angr

######################################
# getenv
######################################

class getenv(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, m_name):
        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        name_len = self.inline_call(strlen, m_name)
        name_expr = self.state.memory.load(m_name, name_len.max_null_index, endness='Iend_BE')
        name = self.state.solver.eval(name_expr, cast_to=bytes)
        
        p = self.state.posix.environ
        while True:
            m_line = self.state.memory.load(p, self.state.arch.byte_width, endness=self.arch.memory_endness)
            if self.state.solver.eval(m_line, cast_to=int) == 0:
                break
            line_len = self.inline_call(strlen, m_line)
            line_expr = self.state.memory.load(m_line, line_len.max_null_index, endness='Iend_BE')
            line = self.state.solver.eval(line_expr, cast_to=bytes)
            kv = line.split(b'=', maxsplit=2)
            if len(kv) == 2 and kv[0] == name:
                return m_line + (name_len.max_null_index + 1)
            p += self.state.arch.bytes
        return self.state.solver.BVV(0, self.state.arch.bits)
