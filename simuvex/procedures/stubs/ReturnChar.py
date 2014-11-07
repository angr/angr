import simuvex

######################################
# Returns a valid char
######################################

class ReturnChar(simuvex.SimProcedure):
    def analyze(self):
        s_var = self.state.BV("char_ret", self.state.arch.bits)
        self.state.add_constraints(self.state.se.And(self.state.se.ULE(s_var, 126), self.state.se.UGE(s_var, 9)))
        self.ret(s_var)
