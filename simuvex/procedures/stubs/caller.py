
import simuvex

######################################
# Caller
######################################


class Caller(simuvex.SimProcedure):
    """
    Caller stub. Creates a Ijk_Call exit to the specified function
    """

    NO_RET = True

    def run(self, target_addr=None):
        self.call(target_addr, [ ], 'after_call')

    def after_call(self, target_addr=None):
        pass
