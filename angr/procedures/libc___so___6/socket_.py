import simuvex

######################################
# socket
######################################

class socket(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, sim_sock_type):
        # TODO: Handling parameters

        sock_type = self.state.se.any_int(sim_sock_type)
        # TODO handle errors and symbolic path
        fd = self.state.posix.open("socket_socket", "rw")

        #if type is 0, it's UDP so create a socket for it, if not then it's 1 and we create a socket later in accept()
        if sock_type is 0:
            self.state.posix.back_with_pcap(fd)
        self.state.posix.add_socket(fd)
        return fd
