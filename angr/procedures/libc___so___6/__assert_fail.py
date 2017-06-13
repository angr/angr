import angr

######################################
# __assert_fail
######################################

class __assert_fail(angr.SimProcedure):
    NO_RET = True

    def run(self):
        self.exit(1)
