import simuvex

######################################
# open
######################################

class open(simuvex.SimProcedure): #pylint:disable=W0622
    #pylint:disable=arguments-differ

    def run(self, path, flags):
        return self.state.posix.open(path, flags)
