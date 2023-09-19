import angr

import logging

l = logging.getLogger(name=__name__)


class bind(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, fd, addr_ptr, addr_len):  # pylint:disable=unused-argument
        return self.state.solver.Unconstrained("bind", self.arch.sizeof["int"], key=("api", "bind"))
