import angr

######################################
# unlink
######################################


class unlink(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, path):
        # TODO: do this the other way around
        unlink_sys = angr.SIM_PROCEDURES["linux_kernel"]["unlink"]
        return self.inline_call(unlink_sys, path).ret_expr
