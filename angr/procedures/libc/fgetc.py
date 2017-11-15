import angr
from angr.sim_type import SimTypeInt, SimTypeFd

######################################
# fgetc
######################################


class fgetc(angr.SimProcedure):
    # pylint:disable=arguments-differ
    def run(self, stream, simfile=None):
        self.argument_types = {0: SimTypeFd()}
        self.return_type = SimTypeInt(32, True)

        if simfile is None:
            fileno = angr.SIM_PROCEDURES['posix']['fileno']
            fd = self.inline_call(fileno, stream).ret_expr
            simfile = self.state.posix.get_file(fd)

        pos = simfile.pos
        limit = 1 if simfile.size is None else self.state.se.max_int(simfile.size - pos)

        if limit != 0:
            data = simfile.read_from(1)
            data = data.zero_extend(self.state.arch.bits - len(data))
        else:
            data = -1 #EOF
            data = self.state.solver.BVV(data, self.state.arch.bits)
        return data

getc = fgetc
