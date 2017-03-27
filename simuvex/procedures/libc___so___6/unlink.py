import simuvex

######################################
# unlink
######################################

class unlink(simuvex.SimProcedure): #pylint:disable=W0622
    #pylint:disable=arguments-differ

    def run(self, path):
        unlink = simuvex.SimProcedures['syscalls']['unlink']
        return self.inline_call(unlink, path).ret_expr
