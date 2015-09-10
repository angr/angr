import simuvex

######################################
# __assert_fail
######################################

class __assert_fail(simuvex.SimProcedure):
    NO_RET = True

    def run(self):
        self.exit(1)
