import angr


class tgkill(angr.SimProcedure):
    def run(self, tgid, tid, sig):  # pylint:disable=arguments-differ,unused-argument
        # TODO: actually do something
        return self.state.solver.BVV(0, self.arch.sizeof["int"])
