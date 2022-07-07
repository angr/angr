import copy
import angr

######################################
# open
######################################

class open(angr.SimProcedure): #pylint:disable=W0622
    #pylint:disable=arguments-differ,unused-argument

    # enormous, catastrophically bad hack
    def execute(self, *args, **kwargs):
        if self.prototype is not None and len(self.prototype.args) == 3:
            self.prototype = copy.copy(self.prototype)
            self.prototype.args = self.prototype.args[:2]

        return super().execute(*args, **kwargs)

    def run(self, p_addr, flags):
        strlen = angr.SIM_PROCEDURES['libc']['strlen']

        p_strlen = self.inline_call(strlen, p_addr)
        p_expr = self.state.memory.load(p_addr, p_strlen.max_null_index, endness='Iend_BE')
        path = self.state.solver.eval(p_expr, cast_to=bytes)

        fd = self.state.posix.open(path, flags)
        if fd is None:
            return -1
        return fd
