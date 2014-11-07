import simuvex

######################################
# Doing nothing
######################################

class pthread_cond_signal(simuvex.SimProcedure):
    def analyze(self):
        _ = self.arg(0)
        self.ret()
