import simuvex

######################################
# Doing nothing
######################################

class pthread_cond_signal(simuvex.SimProcedure):
    def run(self):
        _ = self.arg(0)
