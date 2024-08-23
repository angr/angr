from __future__ import annotations
import angr


class socket(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, domain, typ, protocol):
        conc_domain = self.state.solver.eval(domain)
        conc_typ = self.state.solver.eval(typ)
        conc_protocol = self.state.solver.eval(protocol)

        if self.state.posix.uid != 0 and conc_typ == 3:  # SOCK_RAW
            return self.state.libc.ret_errno("EPERM")

        nonce = self.state.globals.get("socket_counter", 0) + 1
        self.state.globals["socket_counter"] = nonce
        return self.state.posix.open_socket(("socket", conc_domain, conc_typ, conc_protocol, nonce))
