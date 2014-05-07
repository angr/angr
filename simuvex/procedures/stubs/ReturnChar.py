import simuvex
import symexec as se

######################################
# Returns a valid char
######################################

class ReturnChar(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231,
        s_var = self.state.new_symbolic("char_ret", self.state.arch.bits)
        self.state.add_constraints(se.And(se.ULE(s_var, 126), se.UGE(s_var, 9)))
        self.exit_return(s_var)
