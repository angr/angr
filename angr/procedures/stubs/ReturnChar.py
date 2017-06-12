import simuvex

######################################
# Returns a valid char
######################################

class ReturnChar(simuvex.SimProcedure):
    def run(self):
        s_var = self.state.se.Unconstrained("char_ret", self.state.arch.bits)
        self.state.add_constraints(self.state.se.And(self.state.se.ULE(s_var, 126), self.state.se.UGE(s_var, 9)))
        return s_var
