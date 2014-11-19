import simuvex

######################################
# Doing nothing
######################################


class Nop(simuvex.SimProcedure):
    def run(self):
        self.ret()
