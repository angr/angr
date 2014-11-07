import simuvex

######################################
# Doing nothing
######################################

class pthread_mutex_unlock(simuvex.SimProcedure):
    def analyze(self):
        _ = self.arg(0)
        self.ret()
