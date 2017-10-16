import logging

import angr
from angr.sim_type import SimTypeInt, SimTypeTop

l = logging.getLogger("angr.procedures.msvcr.__getmainargs")

######################################
# __getmainargs
######################################

class __getmainargs(angr.SimProcedure):
    #pylint:disable=arguments-differ,unused-argument

    def run(self, argc_p, argv_ppp, env_ppp, dowildcard, startupinfo_p):
        self.argument_types = {0: self.ty_ptr(SimTypeInt()),
                               1: self.ty_ptr(SimTypeTop()),
                               2: self.ty_ptr(SimTypeTop()),
                               3: SimTypeInt(),
                               4: self.ty_ptr(SimTypeTop())
        }
        self.return_type = SimTypeInt()

        if any(map(self.state.se.symbolic, [argc_p, argv_ppp, env_ppp])):
            l.warn("got a symbolic argument... aborting")
            return -1

        self.state.memory.store(argc_p, self.state.posix.argc, self.state.posix.argc.length/8, endness=self.state.arch.memory_endness)
        self.state.memory.store(argv_ppp, self.state.posix.argv, self.state.posix.argv.length/8, endness=self.state.arch.memory_endness)
        self.state.memory.store(env_ppp, self.state.posix.environ, self.state.posix.environ.length/8, endness=self.state.arch.memory_endness)

        return 0
