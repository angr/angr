import angr

######################################
# Doing nothing
######################################

class pthread_cond_signal(angr.SimProcedure):
    def run(self):
        _ = self.arg(0)
