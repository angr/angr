import angr

class strtoul(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, nptr, endptr, base):
        strtol = angr.SIM_PROCEDURES['libc']['strtol']
        return self.inline_call(strol, nptr, endptr, base)
        