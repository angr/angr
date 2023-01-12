import angr

######################################
# setsockopt
######################################


class setsockopt(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, sockfd, level, optname, optval, optmain):
        return 0
