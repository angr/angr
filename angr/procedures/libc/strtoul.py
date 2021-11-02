import angr

class strtoul(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, nptr, endptr, base):
        strtol = angr.SIM_PROCEDURES['libc']['strtol']
        result = self.inline_call(strtol, nptr, endptr, base).ret_expr
        return result
