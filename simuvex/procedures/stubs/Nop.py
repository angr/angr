import simuvex

######################################
# Doing nothing
######################################


class Nop(simuvex.SimProcedure):
    def analyze(self):
        self.ret()
