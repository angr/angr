import angr

######################################
# unlink
######################################

class unlink(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, path):
        unlink_sys = angr.SimProcedures['syscalls']['unlink']
        return self.inline_call(unlink_sys, path).ret_expr
