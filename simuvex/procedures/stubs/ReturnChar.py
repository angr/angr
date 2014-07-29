import simuvex

######################################
# Returns a valid char
######################################

class ReturnChar(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231,
        s_var = self.state.BV("char_ret", self.state.arch.bits)
        self.state.add_constraints(self.state.se.And(self.state.se.ULE(s_var, 126), self.state.se.UGE(s_var, 9)))
        self.exit_return(s_var)
