import angr

######################################
# __getmainargs
######################################

class __getmainargs(angr.SimProcedure):
    #pylint:disable=arguments-differ,unused-argument

    def run(self, argc_p, argv_ppp, env_ppp, dowildcard, startupinfo_p):
        if any(map(self.state.solver.symbolic, [argc_p, argv_ppp, env_ppp])):
            raise angr.errors.SimProcedureError("__getmainargs cannot handle symbolic pointers")

        self.state.memory.store(argc_p, self.state.posix.argc, endness=self.state.arch.memory_endness)
        self.state.memory.store(argv_ppp, self.state.posix.argv, endness=self.state.arch.memory_endness)
        self.state.memory.store(env_ppp, self.state.posix.environ, endness=self.state.arch.memory_endness)

        return 0
