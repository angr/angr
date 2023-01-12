import angr


class GetKeyboardType(angr.SimProcedure):
    def run(self, param):
        # return the values present at time of author's testing
        if self.state.solver.is_true(param == 0):
            return 4
        if self.state.solver.is_true(param == 1):
            return 0
        if self.state.solver.is_true(param == 2):
            return 12
        return 0
