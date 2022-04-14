import angr
import logging

l = logging.getLogger(name=__name__)

class strnlen(angr.SimProcedure):
    def run(self, s, n, wchar=False): #pylint:disable=arguments-differ,unused-argument
        strlen = angr.SIM_PROCEDURES['libc']['strlen']

        maxlen = self.state.solver.eval_one(n)
        length = self.inline_call(strlen, s, maxlen=maxlen).ret_expr
        return length
