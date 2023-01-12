import angr

######################################
# getenv
######################################


class getenv(angr.SimProcedure):
    """
    The getenv() function searches the environment list to find the
    environment variable name, and returns a pointer to the
    corresponding value string.
    """

    # pylint:disable=arguments-differ

    def run(self, m_name):
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
        name_len = self.inline_call(strlen, m_name)
        name_expr = self.state.memory.load(m_name, name_len.max_null_index, endness="Iend_BE")
        name = self.state.solver.eval(name_expr, cast_to=bytes)

        p = self.state.posix.environ
        if p is None:
            return self.state.solver.BVS(b"getenv__" + name, self.state.arch.bits, key=("api", "getenv", name.decode()))

        while True:
            m_line = self.state.memory.load(p, self.state.arch.byte_width, endness=self.arch.memory_endness)
            if self.state.solver.eval(m_line, cast_to=int) == 0:
                break
            line_len = self.inline_call(strlen, m_line)
            line_expr = self.state.memory.load(m_line, line_len.max_null_index, endness="Iend_BE")
            line = self.state.solver.eval(line_expr, cast_to=bytes)
            kv = line.split(b"=", maxsplit=1)
            if len(kv) == 2 and kv[0] == name:
                return m_line + (name_len.max_null_index + 1)
            p += self.state.arch.bytes
        return 0
