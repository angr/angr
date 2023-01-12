import angr

######################################
# err
######################################


class err(angr.SimProcedure):  # pylint:disable=redefined-builtin
    # pylint:disable=arguments-differ,missing-class-docstring,redefined-builtin

    NO_RET = True

    def run(self, eval, fmt):
        fd = self.state.posix.get_fd(1)
        fprintf = angr.SIM_PROCEDURES["libc"]["fprintf"]
        self.inline_call(fprintf, fd, fmt)  # FIXME: This will not properly replace format strings
        self.exit(eval)
