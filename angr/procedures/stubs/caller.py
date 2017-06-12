import simuvex

######################################
# Caller
######################################


class Caller(simuvex.SimProcedure):
    """
    Caller stub. Creates a Ijk_Call exit to the specified function
    """

    IS_FUNCTION = True

    def run(self, target_addr=None, target_cc=None):
        self.call(target_addr, [ ], 'after_call', cc=target_cc)

    def after_call(self, target_addr=None, target_cc=None):
        pass
