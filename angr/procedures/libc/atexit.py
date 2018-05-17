import angr

######################################
# atexit: register exit handlers
######################################

class atexit(angr.SimProcedure):
    def run(self, func):
        self.state.libc._exit_handlers.append(func)
