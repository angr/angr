import angr

######################################
# access
######################################


class access(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, path, mode):
        ret = self.state.solver.BVS("access", self.arch.sizeof["int"])
        self.state.add_constraints(self.state.solver.Or(ret == 0, ret == -1))
        return ret
