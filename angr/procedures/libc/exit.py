import angr

######################################
# exit
######################################


class exit(angr.SimProcedure):  # pylint:disable=redefined-builtin
    # pylint:disable=arguments-differ

    NO_RET = True

    def run(self, exit_code):
        self.exit(exit_code)
