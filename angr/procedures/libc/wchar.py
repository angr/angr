import angr
from angr.sim_type import SimTypeString, SimTypeInt

class wcscmp(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, lpString1, lpString2):
        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(signed=True)

        strcmp = angr.SIM_PROCEDURES['libc']['strcmp']
        return self.inline_call(strcmp, lpString1, lpString2, wchar=True).ret_expr

class wcscasecmp(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, lpString1, lpString2):
        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(signed=True)

        strcmp = angr.SIM_PROCEDURES['libc']['strcmp']
        return self.inline_call(strcmp, lpString1, lpString2, wchar=True, ignore_case=True).ret_expr
