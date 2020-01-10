import angr
import logging
import claripy

l = logging.getLogger('angr.procedures.win32.gethostbyname')

class gethostbyname(angr.SimProcedure):

    def run(self, _): #pylint:disable=arguments-differ
        self.argument_types = {0: self.ty_ptr(angr.sim_type.SimTypeString()), }
        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))
        ret_expr = claripy.BVS('gethostbyname_retval', 32)
        return ret_expr
