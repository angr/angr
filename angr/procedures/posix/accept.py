import angr

######################################
# accept (but not really)
######################################

class accept(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, sockfd, addr, addrlen):
        conc_addrlen = self.state.mem[addrlen].int.concrete
        addr_data = self.state.solver.BVS('accept_addr', conc_addrlen*8, key=('api', 'accept', 'addr'))
        self.state.memory.store(addr, addr_data)

        ident = 'unknown'
        if not sockfd.symbolic:
            sockfd = self.state.solver.eval(sockfd)
            if sockfd in self.state.posix.fd:
                simsockfd = self.state.posix.fd[sockfd]
                for potential_ident in self.state.posix.sockets:
                    if self.state.posix.sockets[potential_ident][0] is simsockfd.read_storage and \
                            self.state.posix.sockets[potential_ident][1] is simsockfd.write_storage:
                        ident = potential_ident
                        break

        ident_counters = dict(self.state.globals.get('accept_idents', {}))
        ident_counters[ident] = ident_counters.get(ident, 0) + 1
        self.state.globals['accept_idents'] = ident_counters
        fd = self.state.posix.open_socket(('accept', ident, ident_counters[ident]))
        return fd
