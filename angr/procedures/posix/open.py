import angr
from angr.sim_type import SimTypeString, SimTypeInt, SimTypeFd

######################################
# open
######################################

class open(angr.SimProcedure): #pylint:disable=W0622
    #pylint:disable=arguments-differ

    def run(self, p_addr, flags, mode):  # pylint:disable=unused-argument
        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: SimTypeInt(32, True)}
        self.return_type = SimTypeFd()

        strlen = angr.SIM_PROCEDURES['libc']['strlen']

        p_strlen = self.inline_call(strlen, p_addr)
        p_expr = self.state.memory.load(p_addr, p_strlen.max_null_index, endness='Iend_BE')
        path = self.state.solver.eval(p_expr, cast_to=bytes)

        fd = self.state.posix.open(path, flags)
        if fd is None:
            return -1
        return fd
