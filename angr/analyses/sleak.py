from ..analysis import Analysis
from ..errors import AngrAnalysisError
import logging
import simuvex
import re
from angr.path import Path

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


    def prepare(self, mode="track_all", targets=None, istate=None):
        """
        Explore the binary until targets are found.
        @targets: a tuple of manually identified targets.
        If @targets is none, we try to identify targets automatically.
        @mode:
            - "track_sp": make the stack pointer symbolic and track everything that depends on it.
            - "track_addr": Stuff concretizable to addresses is tracked.

        """
        if targets is None:
            self.targets = self.find_targets()
        else:
            targets = {}
            for t in targets:
                name = self.target_name(t)
                if name is not None:
                    targets[name] = t
                else:
                    raise AngrAnalysisError("Target doesn't match any known function %s"
                                            % t)
            self.targets = targets

        self.reached_target = False # Whether we made it to at least one target
        self.leaks = [] # Found leaking paths
        self.mode = mode if mode is not None else "track_all"

        if self.targets is None:
            raise AngrAnalysisError("No targets found and none defined!")
            return

        # Stack
        self.stack_bottom = self._p.arch.initial_sp
        l.debug("Stack bottom is at 0x%x" % self.stack_bottom)
        self.stack_top = None
        self.tracked_addrs = []

        # Initial state
        if istate is None:
            self.istate = self._p.initial_state()
        else:
            self.istate = istate

        # Mode
        if "heap" in self.mode:
            self._set_heap_bp()

        elif "got" in self.mode:
            self._set_got_bp()

        elif "data" in self.mode:
            self._set_data_bp()

        elif "addr" in self.mode:
            self._set_addr_bp()

        elif "all" in self.mode:
            self._set_heap_bp()
            self._set_got_bp()
            self._set_data_bp()
            self._set_addr_bp()

        else:
            raise AngrAnalysisError("Invalid mode")

        # Finally, create the initial path
        self.ipath = Path(self._p, self.istate)


    ## Setting the breakpoints ##
    def _set_stack_bp(self):
        """
        Track stack pointer reads and propagate its symbolic variable across the
        analysis
        """
        bp = simuvex.BP(simuvex.BP_BEFORE, action=self.make_sp_symbolic)
        self.istate.inspect.add_breakpoint('reg_read', bp)

    def _set_data_bp(self):
        """
        Track access to data
        """
        self.make_data_symbolic(self.istate)

    def _set_got_bp(self):
        """
        Make GOT addresses symbolic
        """
        self.make_got_symbolic(self.istate)

    def _set_heap_bp(self):
        """
        Track malloc return pointers
        """
        malloc_plt = self._p.main_binary.get_call_stub_addr("malloc")
        if malloc_plt is None:
            l.info("Could not find PLT stub addr for malloc, heap pointers "
                   "won't be tracked")
        else:
            action=self.make_heap_ptr_symbolic
            bp = simuvex.BP(simuvex.BP_AFTER, instruction=malloc_plt, action=action)
            self.istate.inspect.add_breakpoint('instruction', bp)

    def _set_addr_bp(self):
        """
        Track anything that concretizes to an address
        """
        self.istate.inspect.add_breakpoint(
            'mem_write', simuvex.BP(simuvex.BP_AFTER, action=self.track_mem_write))

            # Make sure the stack pointer is symbolic before we read it
        self.istate.inspect.add_breakpoint(
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

    def _check_found_paths(self):
        """
        Did we reach the targets ?
        Does any of the found paths contain a leak ?
        """
        results = []
        if len(self.found_paths) > 0:
            self.reached_target = True

        # Found paths : output function reached
        for p, func in self.found_paths.iteritems():
            sp = SleakProcedure(func, p, self.mode)
            if len(sp.badargs) > 0:
                results.append(sp)

        self.leaks = results

    @property
    def found_paths(self):
        """
        Found paths: paths to the output functions
        """
        found={}

        for p in self.terminated_paths:
            if self._reached_target(p) is not None:
                found[p] = self._reached_target(p)

            for succ in p.successors:
                if self._reached_target(succ) is not None:
                    found[succ] = self._reached_target(succ)

        return found

    def _reached_target(self, p):
        """
        Which target was reached by path @p
        """
        for t in self.targets.values():
            if p.state.se.solution(p.addr,t):
                return self.target_name(t)

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

        # Any address in the binary OR any stack addr
        if self._p.ld.addr_is_mapped(addr) or self.is_stack_addr(addr, state):
            l.info("Auto tracking addr 0x%x" % addr)
            state.memory.make_symbolic("TRACKED_ADDR", addr, self._p.arch.bits/8)
            self.tracked_addrs.append({addr:state.mem_expr(addr, self._p.arch.bits/8)})

    def make_sp_symbolic(self, state):
        if state.inspect.reg_write_offset == self._p.arch.sp_offset or state.inspect.reg_read_offset == self._p.arch.sp_offset:
            state.registers.make_symbolic("STACK_TRACK", "rsp")
            l.debug("SP set symbolic")

    def make_heap_ptr_symbolic(self, state):
        """
        Make heap pointer returned by malloc and cmalloc symbolic
        """
        #if state.inspect.function_name == "malloc" or state.inspect.function_name == "calloc":
        #convention = simuvex.Conventions[state.arch.name](state.arch)
        #addr = convention.return_val(state)
        reg = state.arch.ret_offset
        state.registers.make_symbolic("HEAP_TRACK", reg, self._p.arch.bits/8)
        #addr = state.se.any_int(state.reg_expr(reg))
        #state.memory.make_symbolic("TRACKED_HEAPPTR", addr, self._p.arch.bits/8)
        #l.debug("Heap ptr @0x%x made symbolic" % state.se.any_int(addr))
        l.debug("Heap ptr made symbolic - reg off %d" % reg)
        #import pdb; pdb.set_trace()

    def make_got_symbolic(self, state):
        """
        Make GOT addresses symbolic
        """
        got = self._p.main_binary.gotaddr
        gotsz = self._p.main_binary.gotsz

        pltgot = self._p.main_binary.pltgotaddr
        pltgotsz = self._p.main_binary.pltgotsz

        for addr in range(got, got+gotsz):
            state.memory.make_symbolic("GOT_TRACK", addr, self._p.arch.bits/8)

        for addr in range(pltgot, pltgot+pltgotsz):
            state.memory.make_symbolic("PLTGOT_TRACK", addr, self._p.arch.bits/8)

    def make_data_symbolic(self, state):
        strtab = self._p.main_binary.strtab_vaddr
        for off, _ in self._p.main_binary.strtab.iteritems():
            addr = off + strtab
            state.memory.make_symbolic("DATA_TRACK", addr, self._p.arch.bits/8)

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
    _fn_parameters={}
    _fn_parameters['puts'] = ['p']
    _fn_parameters['send'] = ['v', 'p', 'v', 'v' ]
    _fn_parameters['printf'] = []
    _fn_parameters['fprintf'] = []
    _fn_parameters['vprintf'] = []
    _fn_parameters['vfprintf'] = []
    _fn_parameters['wprintf'] = []
    _fn_parameters['fwprintf'] = []
    _fn_parameters['vwprintf'] = []
    _fn_parameters['vfwprintf'] = []
    _fn_parameters['write'] = ['v', 'p', 'v']
    _fn_parameters['putc'] = ['v', 'p']
    _fn_parameters['puts'] = ['p']
    _fn_parameters['putw'] = ['v', 'p']
    _fn_parameters['putwc'] = ['v', 'p']
    _fn_parameters['fputwc'] = ['v', 'p']
    _fn_parameters['putchar'] = ['v']
    _fn_parameters['fwrite'] = ['p', 'v', 'v', 'p']
    _fn_parameters['fwrite_unlocked'] = ['p', 'v', 'v', 'p']
    _fn_parameters['pwrite'] = ['v', 'p', 'v', 'v']
    _fn_parameters['putc_unlocked'] = ['v','p']
    _fn_parameters['putchar_unlocked'] = ['v']
    _fn_parameters['writev'] = ['v', 'p', 'v']
    _fn_parameters['pwritev'] = ['v', 'p', 'v', 'v']
    _fn_parameters['pwritev64'] = ['v', 'p', 'v', 'v']
    _fn_parameters['pwrite'] = ['v', 'p', 'v', 'v']

    def __init__(self, name, path, mode='track_sp'):

        self.path = path
        self.state = self.path.state
        self.name = name
        self.mode = mode

        # Functions depending on a format string
        if len(self._fn_parameters[name]) == 0:
            # The first argument to a function that requires a format string is
            # a pointer to the format string itself.
            self.types = ['p'] + self._parse_format_string(self.get_format_string())
            self.n_args = len(self.types) # The format string and the args
        else:
            self.types = self._fn_parameters[name]
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
                raise Exception("Oops, we got a symbolic pointer...")
            addr = self.state.se.any_int(expr)

            val = self.state.mem_expr(addr, self.state.arch.bits/8)
            if self._arg_depends_on_address(val):
                return True
        return False

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
        elif self.mode == "track_all":
            tstr = "TRACK"
        else:
            tstr = "TRACKED_ADDR"

        if tstr in repr(arg_expr):
            return True
        return False

    def __repr__(self):
        addr = self.path.addr
        return "<SleakProcedure at addr 0x%x (%s)>" % (addr, self.name)

