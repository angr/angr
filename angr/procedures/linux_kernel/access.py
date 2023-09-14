# pylint:disable=arguments-differ,unused-argument,missing-class-docstring
import angr


class access(angr.SimProcedure):
    def run(self, pathname, mode):
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
        p_strlen = self.inline_call(strlen, pathname)
        p_expr = self.state.memory.load(pathname, p_strlen.max_null_index, endness="Iend_BE")
        path = self.state.solver.eval(p_expr, cast_to=bytes)

        simfile = self.state.fs.get(path)
        if simfile is None:
            # the file does not exist
            return -1

        return 0
