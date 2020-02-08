import angr

class tolower(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, c):
        return self.state.solver.If(
            self.state.solver.And(c >= 65, c <= 90),  # A - Z
            c + 32, c)
