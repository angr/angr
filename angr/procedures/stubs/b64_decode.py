import angr


class b64_decode(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, src, dst, length):
        strncpy = angr.SIM_PROCEDURES["libc"]["strncpy"]

        cpy = self.inline_call(strncpy, dst, src, length)
        self.state.memory.store(dst + 16, self.state.solver.BVV(0, 8))
        return cpy.ret_expr
