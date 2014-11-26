from ..analysis import Analysis
from ..errors import AngrAnalysisError
import logging
import simuvex

l = logging.getLogger("analysis.sleak")
class SleakMeta(Analysis):
    """
    Stack leak detection - general stuff.
    See XSleak and Sleakslice for actual implementations.
    """

    def __init__():
        raise Exception("Not implemented - use subclasses")


    """
    Methods subclasses must implement
    """

    def terminated_paths(self):
        """
        Returns a list of paths where the analysis stopped for whatever reasons
        """
        raise Exception("Not implemented - use subclasses")


    """
    General methods
    """


    def prepare(self, mode=None, targets=None):
        """
        Explore the binary until targets are found.
        @targets: a tuple of manually identified targets.
        If @targets is none, we try to identify targets automatically.
        @mode:
            - "track_sp": make the stack pointer symbolic and track everything that depends on it.
            - "track_addr": Stuff concretizable to addresses is tracked.

        """
        self.targets = self.find_targets() if targets is None else targets

        self.target_reached = False # Whether we made it to at least one target
        self.found_leaks = False # Whether at least one leak was found
        self.results = None

        if self.targets is None:
            raise AngrAnalysisError("No targets found and none defined!")
            return

        if mode is None or mode == "track_sp":
            self.mode = "track_sp"
        elif mode == "track_addr":
            self.mode = "track_addr"
        else:
            raise AngrAnalysisError("Invalid mode")

        self.stack_bottom = self._p.arch.initial_sp
        l.debug("Stack bottom is at 0x%x" % self.stack_bottom)
        self.stack_top = None
        self.tracked = []

        self.iexit = self._p.initial_exit

        if self.mode == "track_sp":
            #self.iexit.state.inspect.add_breakpoint('reg_write',
            #                                        simuvex.BP(simuvex.BP_AFTER,
            #                                                   action=self.make_sp_symbolic))
            self.iexit.state.inspect.add_breakpoint('reg_read',
                                                    simuvex.BP(simuvex.BP_BEFORE,
                                                               action=self.make_sp_symbolic))
        else:
            # Look for all memory writes
            self.iexit.state.inspect.add_breakpoint(
                'mem_write', simuvex.BP(simuvex.BP_AFTER, action=self.track_mem_write))

            # Make sure the stack pointer is symbolic before we read it
            self.iexit.state.inspect.add_breakpoint(
                'mem_read', simuvex.BP(simuvex.BP_AFTER, action=self.track_mem_read))

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
                plt = self._p.main_binary.get_call_stub_addr(f)
                targets[f] = plt

        l.info("Found targets (output functions) %s" % repr(targets))
        return tuple(targets.values())

    def results(self):
        """
        Results of the analysis: did we find any matching output parameter ?
        Return: an array of matching states.
        """
        if self.results is not None:
            return self.results

        st = []
        found = self.found_paths()
        if len(found) > 0:
            self.target_reached = True

        for p in found:
            st.append(self._check_state_args(p.last_initial_state))
            for ex in p.exits():
                st.append(self._check_state_args(ex.state))

        if len(st) > 0:
            self.found_leaks = True

        self.results = st
        return self.results

    def found_paths(self):
        """
        Filter paths - only keep those reaching targets
        """
        found = []
        for p in  self.terminated_paths():

            # Last_run's addr is target
            if p.last_run.addr in self.targets:
                found.append(p)

            # Exits to target
            for ex in p.exits():
                for t in self.targets:
                    if ex.state.se.solution(ex.target, t):
                        found.append(p)
                        break
        return list(set(found))


    """
    Args checking stuff
    """

    def _check_state_args(self, state, count=5):
        """
        TODO
        Check whether the parameters to the output function contain any
        information about a stack address.

            @state: the state instance to check (initial state of the function to
            check, or exit state of the previous block.

            @count: the number of parameters to check.

            Returns: a tuple of (state, [matching argument indexes])
        """

        # TODO: support function signatures, or something else better than
        # checking these four values for everything.
        args={}
        for i in range(0, count):
            conv = simuvex.Conventions[self._p.arch.name](self._p.arch)
            args[i] = conv.peek_arg(i, state)

        matching=[]
        for arg, expr in args.iteritems():
            if self._matching_arg(expr):
                matching.append(arg)
        return (state, matching) if len(matching) > 0 else None

    def _matching_arg(self, arg_expr):
        if self.mode == "track_sp":
            tstr = "STACK_TRACK"
        else:
            tstr = "TRACKED_ADDR"

        if tstr in repr(arg_expr):
            return True
        return False


    """
    Stack tracking stuff
    """


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
            state.memory.make_symbolic("TRACKED_ADDR", addr, self._p.arch.bits/8)
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



