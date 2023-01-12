import angr

######################################
# __errno_location
######################################


class __errno_location(angr.SimProcedure):
    def run(self):  # pylint:disable=arguments-differ
        return self.state.libc.errno_location
