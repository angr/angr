import angr

######################################
# socket
######################################

class socket(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, domain, typ, protocol):
        conc_domain = self.state.solver.eval(domain)
        conc_typ = self.state.solver.eval(typ)
        conc_protocol = self.state.solver.eval(protocol)
        nonce = self.state.globals.get('socket_counter', 0) + 1
        self.state.globals['socket_counter'] = nonce
        fd = self.state.posix.open_socket(('socket', conc_domain, conc_typ, conc_protocol, nonce))
        return fd
