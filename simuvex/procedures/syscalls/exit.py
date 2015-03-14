import simuvex

######################################
# exit
######################################

class exit(simuvex.SimProcedure): #pylint:disable=redefined-builtin
    NO_RET = True

    def run(self):
        return

