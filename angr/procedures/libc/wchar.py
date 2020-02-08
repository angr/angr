import angr

class wcscmp(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, lpString1, lpString2):
        strcmp = angr.SIM_PROCEDURES['libc']['strcmp']
        return self.inline_call(strcmp, lpString1, lpString2, wchar=True).ret_expr

class wcscasecmp(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, lpString1, lpString2):
        strcmp = angr.SIM_PROCEDURES['libc']['strcmp']
        return self.inline_call(strcmp, lpString1, lpString2, wchar=True, ignore_case=True).ret_expr
