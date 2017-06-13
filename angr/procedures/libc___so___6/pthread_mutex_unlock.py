import angr

######################################
# Doing nothing
######################################

class pthread_mutex_unlock(angr.SimProcedure):
    def run(self):
        _ = self.arg(0)
