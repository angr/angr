import angr

######################################
# rewind
######################################

class rewind(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, file_ptr):
        fseek = angr.SimProcedures['libc.so.6']['fseek']
        self.inline_call(fseek, file_ptr, 0, 0)

        return None
