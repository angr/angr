import angr

class toupper(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, c):
        return self.state.solver.If(
            self.state.solver.And(c >= 97, c <= 122),  # a - z
            c - 32, c)
