import angr

######################################
# getsockopt
######################################

class getsockopt(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, sockfd, level, optname, optval, optlen):

        # TODO: ...

        return 0
