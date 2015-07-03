import simuvex
from simuvex.s_type import SimTypeString, SimTypeInt, SimTypeFd

######################################
# open
######################################

class open(simuvex.SimProcedure): #pylint:disable=W0622
    #pylint:disable=arguments-differ

    def run(self, p_addr, flags):
        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: SimTypeInt(32, True)}
        self.return_type = SimTypeFd()

        strlen = simuvex.SimProcedures['libc.so.6']['strlen']

        p_strlen = strlen(self.state, inline=True, arguments=[p_addr])
        p_expr = self.state.memory.load(p_addr, p_strlen.max_null_index, endness='Iend_BE')
        path = self.state.se.any_str(p_expr)

        fd = self.state.posix.open(path, flags)
        return fd
