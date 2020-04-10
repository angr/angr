import angr

######################################
# std::terminate
######################################

class std__terminate(angr.SimProcedure): #pylint:disable=redefined-builtin
    #pylint:disable=arguments-differ

    NO_RET = True
    __altnames__ = ('std::terminate()', )

    def run(self):
        # FIXME: Call terminate handlers
        self.exit(1)
