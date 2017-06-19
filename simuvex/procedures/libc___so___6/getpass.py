import simuvex

######################################
# getpass
######################################

class getpass(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, prompt):
        # write out the prompt
        self.inline_call(simuvex.SimProcedures['libc.so.6']['puts'], prompt)

        # malloc a buffer
        buf = self.inline_call(simuvex.SimProcedures['libc.so.6']['malloc'], 1024).ret_expr

        # read into the buffer
        self.inline_call(simuvex.SimProcedures['libc.so.6']['read'], 0, buf, 1024)

        # return the buffer
        return buf
