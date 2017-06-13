import angr

######################################
# Doing nothing
######################################


class Nop(angr.SimProcedure):
    def run(self):
        pass
