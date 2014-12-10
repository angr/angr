from ..analysis import Analysis
from ..errors import AngrAnalysisError
import logging
import simuvex
import re

l = logging.getLogger("analysis.sleak")

class SleakMeta(Analysis):
    """
    Stack leak detection - general stuff.
    See XSleak and Sleakslice for actual implementations.
    """

    out_functions = ['send', 'printf', 'vprintf', 'fprintf', 'vfprintf',
                 'wprintf', 'fwprintf', 'vwprintf', 'vfwprintf',
                 'putc', 'puts', 'putw', 'fputwc', 'putwc',
                 'putchar', 'fwrite', 'putc_unlocked',
                 'putchar_unlocked', 'writev', 'pwritev', 'pwritev64',
                 'pwrite', 'pwrite64', 'fwrite_unlocked', 'write']



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


    def prepare(self, mode=None, targets=None, iexit=None):
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
        #self.results = None

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

        if iexit is None:
            self.iexit = self._p.initial_exit()
        else:
            self.iexit = iexit

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
        Returns a dict {name: addresses} where addresses are the PLT stubs of
        target functions.
        """
        targets={}
        for f in self.out_functions:
            if f in self._p.main_binary.jmprel:
                plt = self._p.main_binary.get_call_stub_addr(f)
                targets[f] = plt

        l.info("Found targets (output functions) %s" % repr(targets))
        return targets
        #return tuple(targets.values())

    def results(self):
        """
        Results of the analysis: did we find any matching output parameter ?
        Returns: a dict of {path: [ ( state1, [matching_arguments1] ), ( state2,
        [matching_arguments2] ), ... ]}
        """
        #if self.results is not None:
        #return self.results

        st = {}
        found = self.found_paths()
        if len(found) > 0:
            self.target_reached = True

        # Found paths
        for func, paths in found.iteritems():

            # For fixed args functions
            for p in paths:
                r = []
                states = [p.last_initial_state]
                for ex in p.exits():
                    states.append(ex.state)

                for s in states:
                    sp = SleakProcedure(func, s, self.mode)
                    if len(sp.badargs) > 0:
                        r.append(sp)

                if len(r) > 0:
                    st[p] = r

        if len(st) > 0:
            self.found_leaks = True

        #self.results = st
        return st

    def found_paths(self):
        """
        Filter paths - only keep paths that reach at least one of the targets
        Returns: a dict {target_function_name: [path1,... pathn] }
        """
        found = {}
        for p in  self.terminated_paths():

            # Last_run's addr is target
            if p.last_run.addr in self.targets.values():
                name = self.target_name(p.last_run.addr)
                if name in found.keys():
                    found[name].append(p)
                else:
                    found[name] = [p]

            # Exits to target
            for ex in p.exits():
                for t in self.targets.values():
                    if ex.state.se.solution(ex.target, t):
                        name = self.target_name(t)
                        if name in found.keys():
                            found[name].append(t)
                        else:
                            found[name] = [t]
                        break
        return found


    """
    Args checking stuff
    """

    def target_name(self, addr):
        """
        Name from target addr
        """
        for name, target in self.targets.iteritems():
            if addr == target:
                return name


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


class SleakProcedure(object):
    """
    SleakProcedure: check procedure parameters.
    It only interprets what the procedure outputs in terms of pointers.
    """

    # Parameters to functions expressed in terms of pointers (p) or values (v)
    params={}
    params['puts'] = ['p']
    params['send'] = ['v', 'p', 'v', 'v' ]
    params['printf'] = []
    params['fprintf'] = []
    params['vprintf'] = []
    params['vfprintf'] = []
    params['wprintf'] = []
    params['fwprintf'] = []
    params['vwprintf'] = []
    params['vfwprintf'] = []
    params['write'] = ['v', 'p', 'v']
    params['putc'] = ['v', 'p']
    params['puts'] = ['p']
    params['putw'] = ['v', 'p']
    params['putwc'] = ['v', 'p']
    params['fputwc'] = ['v', 'p']
    params['putchar'] = ['v']
    params['fwrite'] = ['p', 'v', 'v', 'p']
    params['fwrite_unlocked'] = ['p', 'v', 'v', 'p']
    params['pwrite'] = ['v', 'p', 'v', 'v']
    params['putc_unlocked'] = ['v','p']
    params['putchar_unlocked'] = ['v']
    params['writev'] = ['v', 'p', 'v']
    params['pwritev'] = ['v', 'p', 'v', 'v']
    params['pwritev64'] = ['v', 'p', 'v', 'v']
    params['pwrite'] = ['v', 'p', 'v', 'v']

    def __init__(self, name, state, mode='track_sp'):

        self.state = state
        self.name = name
        self.mode = mode

        # Functions depending on a string format
        if len(self.params[name]) == 0:
            # The first argument to a function that requires a format string is
            # a ponter to the format string itself.
            self.types = ['p'] + self._parse_format_string(self.get_format_string())
            self.n_args = len(self.types) # The format string and the args
        else:
            self.types = self.params[name]
            self.n_args = len(self.types)

        self.badargs = self.check_args() # args leaking pointer info

    def get_arg_expr(self, arg_num):
        """
        What is the expression of argument number @arg_num ?
        """
        convention = simuvex.Conventions[self.state.arch.name](self.state.arch)
        return convention.peek_arg(arg_num, self.state)

    def check_args(self):
        """
        Check whether any of the args contains information about a stack (or
        tracked) address.
        """

        count = self.n_args
        args={}
        for i in range(0, count):
            args[i] = self.get_arg_expr(i)

        matching={}
        for arg_num, expr in args.iteritems():
            if self._check_ptr_leak(expr, arg_num):
                matching[arg_num] = self.state.se.simplify(expr)

        return matching

    def _check_ptr_leak(self, expr, arg_num):
        """
        Check whether @expr passed as argument number @arg_num to the output
        function (self) ends up leaking address information.
        """
        # Type of the argument w.r.t the function's prototype
        arg_type = self.types[arg_num]

        # Does expr depends on a stack_addr ?
        if self._arg_depends_on_address(expr):
            # Pointer (or variable depending on pointer) passed as value, that's
            # a leak !
            if arg_type == 'v':
                return True

        # Otherwise, if we got a pointer for a pointer, nothing wrong... but the
        # output function is going to dereference it, and
        # the target of the pointer might, in turn, depend on an address ?
        if arg_type == 'p':
            if not self.state.se.unique(expr):
                raise Exception("TODO: handle multiple addresses")
            addr = self.state.se.any_int(expr)

            val = self.state.mem_expr(addr, self.state.arch.bits/8)
            if self._arg_depends_on_address(val):
                return True

    def get_format_string(self):
        """
        Determines the number of arguments passed to printf-like functions based
        on the format string, given the state @state
        """
        # The address of the first argument (the pointer to the format string)
        arg0 = self.get_arg_expr(0)
        if not self.state.se.unique(arg0):
            raise Exception("TODO: handle multiple addresses")

        addr = self.state.se.any_int(arg0)

        string = ""
        size = 0

        # We increaze the size of the string by 10 characters each time
        # until we find the ending \x00
        while len(re.findall("\x00", string)) == 0:
            size = size + 10
            string = self.state.se.any_str(self.state.mem_expr(addr, size))

        # Only get the part of the string we are interested in
        return string[0:string.find('\x00')]

    def _parse_format_string(self, fstr):
        fmt = re.findall(r'%[a-z]+', fstr)
        return map(self._format_str_types, fmt)

    def _format_str_types(self, fmt):
        """
        Conversion of format str types to simple types 'v' or 'p'
        """
        if fmt == "%s" or fmt == "%p":
            return "p"
        else:
            return "v"

    def _arg_depends_on_address(self, arg_expr):
        """
        This determines whether the argument depends on an address (tracked or stack)
        """
        if self.mode == "track_sp":
            tstr = "STACK_TRACK"
        else:
            tstr = "TRACKED_ADDR"

        if tstr in repr(arg_expr):
            return True
        return False
