import angr

######################################
# Doing nothing
######################################

class pthread_mutex_lock(angr.SimProcedure):
    def run(self):
        _ = self.arg(0)
