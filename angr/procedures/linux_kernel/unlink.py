import angr

######################################
# unlink
######################################


class unlink(angr.SimProcedure):  # pylint:disable=W0622
    # pylint:disable=arguments-differ

    def run(self, path_addr):
        # This is a dummy for now
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]

        p_strlen = self.inline_call(strlen, path_addr)
        str_expr = self.state.memory.load(path_addr, p_strlen.max_null_index, endness="Iend_BE")
        str_val = self.state.solver.eval(str_expr, cast_to=bytes)

        # Check if entity exists before attempting to unlink
        if not self.state.fs.get(str_val):
            return self.state.libc.ret_errno("ENOENT")

        if self.state.fs.delete(str_val):
            return 0
        else:
            return -1
