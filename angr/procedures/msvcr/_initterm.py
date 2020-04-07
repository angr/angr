import logging
import angr

l = logging.getLogger(name=__name__)

######################################
# __initterm
######################################

class _initterm(angr.SimProcedure):
    local_vars = ('callbacks',)
    callbacks = []

    #pylint:disable=arguments-differ
    def run(self, fp_a, fp_z):
        if self.state.solver.symbolic(fp_a) or self.state.solver.symbolic(fp_z):
            l.warning("Symbolic argument to _initterm{_e} is not supported... returning")
            self.ret(0) # might as well try to keep going

        self.callbacks = self.get_callbacks(fp_a, fp_z)
        self.do_callbacks(fp_a, fp_z)

    def get_callbacks(self, fp_a, fp_z):
        callbacks = []
        table_size = fp_z - fp_a + self.state.arch.bytes
        for addr in reversed(self.state.memory.load(fp_a, table_size, endness=self.state.arch.memory_endness).chop(self.state.arch.bits)):
            addr = self.state.solver.eval(addr)
            if addr != 0:
                callbacks.append(addr)
        return callbacks

    def do_callbacks(self, fp_a, fp_z): # pylint:disable=unused-argument
        if len(self.callbacks) == 0:
            self.ret(0)  # probably best to assume each callback returned 0
        else:
            callback_addr = self.callbacks.pop(0)
            l.debug("Calling %#x", callback_addr)
            self.call(callback_addr, [], continue_at='do_callbacks')
