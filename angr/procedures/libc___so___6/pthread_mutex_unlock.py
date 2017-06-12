import simuvex

######################################
# Doing nothing
######################################

class pthread_mutex_unlock(simuvex.SimProcedure):
    def run(self):
        _ = self.arg(0)
