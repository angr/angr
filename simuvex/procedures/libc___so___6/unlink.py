import simuvex

######################################
# unlink
######################################

class unlink(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, path):
        unlink_sys = simuvex.SimProcedures['syscalls']['unlink']
        return self.inline_call(unlink_sys, path).ret_expr
