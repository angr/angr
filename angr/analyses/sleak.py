from ..analysis import Analysis
import logging
import simuvex

l = logging.getLogger("analysis.sleak")
class Sleak(Analysis):
    """
    Stack leak detection - general stuff.
    See XSleak and Sleakslice for actual implementations.
    """

    def __init__():
        pass

    def find_targets(self):
        """
        What are the target addresses we are interested in ?
        These are output or interface functions.
        """
        targets={}
        out_functions = ['send', 'printf', 'vprintf', 'fprintf', 'vfprintf',
                         'wprintf', 'fwprintf', 'vwprintf', 'vfwprintf',
                         'write', 'putc', 'puts', 'putw', 'fputwc', 'putwc',
                         'putchar', 'send', 'fwrite', 'pwrite', 'putc_unlocked',
                         'putchar_unlocked', 'writev', 'pwritev', 'pwritev64',
                         'pwrite', 'pwrite64', 'fwrite_unlocked', 'write']

        for f in out_functions:
            if f in self._p.main_binary.jmprel:
                plt = self._p.main_binary.get_plt_stub_addr(f)
                targets[f] = plt

        l.info("Found targets %s" % repr(targets))
        return tuple(targets.values())

    def check_parameters(self, state):
        """
        TODO
        Check whether the parameters to the output function contain any
        information about a stack address.
        """

        # TODO: support function signatures, or something else better than
        # checking these four values for everything.
        params={}
        for i in range(0,5):
            conv = simuvex.Conventions[self._p.arch.name](self._p.arch)
            params[i] = conv.peek_arg(i, state)

        for index, val in params.iteritems():
            if "STACK_TRACK" in repr(val):
                print "FOUND tainted parameter: index %d" % index
                import pdb; pdb.set_trace()

    def track_mem_read(self, state):
        return self._track_mem_op(state, mode='r')

    def track_mem_write(self, state):
        return self._track_mem_op(state, mode='w')

    def _track_mem_op(self, state, mode=None):
        """
        Anything that concretizes to an address is made symbolic and tracked
        """

        if mode == 'w':
            addr_xpr = state.inspect.mem_write_expr

        elif mode == 'r':
            addr_xpr = state.inspect.mem_read_expr
        else:
            raise Exception ("Invalid mode")

        # Todo: something better here, we should check boundaries and stuff to
        # make sure we don't miss possible stack values
        addr = state.se.any_int(addr_xpr)
        #import pdb; pdb.set_trace()

        l.debug("\taddr 0x%x" % addr)

        if self.is_stack_addr(addr, state):
            l.info("Tracking 0x%x" % addr)
            state.memory.make_symbolic("tracked_addr", addr, self._p.arch.bits/8)
            self.tracked.append(addr)

    def make_sp_symbolic(self, state):
        if state.inspect.reg_write_offset == self._p.arch.sp_offset or state.inspect.reg_read_offset == self._p.arch.sp_offset:
            state.registers.make_symbolic("STACK_TRACK", "rsp")
            l.debug("SP set symbolic")

    def get_stack_top(self, state):
        """
        We keep tracks of the highest stack address the program has accessed.
        """

        # We suppose the stack pointer has only one concrete solution
        sp = state.se.any_int(state.reg_expr("rsp"))

        if self.stack_top is None:
            self.stack_top = sp
        else:
           if sp < self.stack_top:
               self.stack_top = sp
        l.debug("Stack top is at 0x%x" % self.stack_top)

    def is_stack_addr(self, addr, state):
        self.get_stack_top(state)
        return addr >= self.stack_top and addr <= self.stack_bottom



