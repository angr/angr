import simuvex

class _terminate(simuvex.SimProcedure): #pylint:disable=redefined-builtin
    #pylint:disable=arguments-differ

    NO_RET = True
    def run(self, exit_code): #pylint:disable=unused-argument
        return
