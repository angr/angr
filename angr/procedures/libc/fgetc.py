import angr
from angr.sim_type import SimTypeInt, SimTypeFd

######################################
# fgetc
######################################


class fgetc(angr.SimProcedure):
    # pylint:disable=arguments-differ
    def run(self, stream, simfd=None):
        self.argument_types = {0: SimTypeFd()}
        self.return_type = SimTypeInt(32, True)

        if simfd is None:
            fileno = angr.SIM_PROCEDURES['posix']['fileno']
            fd = self.inline_call(fileno, stream).ret_expr
            try:
                simfd = self.state.posix.get_fd(fd)
            except angr.SimUnsatError:
                # XXX: fileno may return symbolic value
                return self.state.solver.Unconstrained("fgetc_char", 32, uninitialized=False)

        if simfd is None:
            return -1

        data, real_length, = simfd.read_data(1)
        return self.state.solver.If(real_length == 0, -1, data.zero_extend(24))

getc = fgetc
