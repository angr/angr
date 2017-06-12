import simuvex

######################################
# accept (but not really)
######################################

class accept(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, sockfd):
        #### IGNORE ALL ARGUMENTS FOR NOW AND JUST RETURN A FD SOCKET
        ## TODO: Symbolic fd
        ## this is the name for now

        #this is the mode for now
        sockaddr_struct_ptr = self.arg(1)

        #socklen_t_addrlen = self.arg(2)
        ## TODO handle mode if flags == O_CREAT

        ##NOTE: might be misinterpretting 'falgs' here
        #flags = 'wr'

        # TODO handle errors and symbolic path
        key = self.state.posix.open(sockfd, sockaddr_struct_ptr)
        #add this socket to the SimStateSystem list of sockets
        self.state.posix.add_socket(key)

        #should back the SimFile associated with this key by the first pcap on the pcap queue
        #and then transfer that pcap to the list/queue of used_pcaps
        self.state.posix.back_with_pcap(key)
        return key

