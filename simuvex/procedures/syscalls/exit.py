import simuvex

######################################
# exit
######################################

#pylint:disable=redefined-builtin,arguments-differ
class exit(simuvex.SimProcedure):
    NO_RET = True

    def run(self, exit_code):
        self.exit(exit_code)

