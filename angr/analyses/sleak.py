from ..analysis import Analysis
from ..errors import AngrAnalysisError
from ..tablespecs import StringSpec
import logging
import simuvex
import re
import struct

l = logging.getLogger("analysis.sleak")

class SleakError(AngrAnalysisError):
    pass

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


    def prepare(self, mode="all", istate=None, argc=2):
        """
        Explore the binary until targets are found.
        @targets: a tuple of manually identified targets.
        If @targets is none, we try to identify targets automatically.
        @mode:
            - "stack": track stack addresses.
            - "got": make the content of GOT stubs symbolic. It has the effect
               of tracking leakage of PLT stub addresses.
            - "data": TODO
            - "heap": track heap pointers
            - "none": track nothing (fast, just executes the slice)

        @argc: how many symbolic arguments to we want ?
        By default, we consider argv[1] as the filename, and argv[2] as being symbolic

        """

        # Find targets automatically
        self._targets = self.find_targets()
        if len(self._targets) == 0:
            l.warning("Could not find any target. Specify it manually (add_target()")

        try:
            self._malloc = self.project.loader.main_bin.get_call_stub_addr("malloc")
        except:
            self._malloc = None

        self._custom_targets={}
        self._custom_protos={}

        self.reached_target = False # Whether we made it to at least one target
        self.leaks = [] # Found leaking paths
        self.mode = mode if mode is not None else "all"

        # Stack
        self.stack_bottom = self.project.arch.initial_sp
        l.debug("Stack bottom is at 0x%x" % self.stack_bottom)
        self.stack_top = None
        self.tracked_addrs = []

        # Initial state
        if istate is None:
            istate = self.project.factory.entry_state(args = self._make_sym_argv(argc))

        # Initial path, comprising the initial state
        self.ipath = self.project.factory.path(istate)

        # Mode
        if "heap" in self.mode:
            self._set_heap_bp()

        elif "got" in self.mode:
            self.make_got_symbolic(self.ipath.state)

        elif "data" in self.mode:
            self._set_data_bp()

        elif "stack" in self.mode:
            self._set_stack_bp()

        elif "addr" in self.mode:
            self._set_addr_bp()

        elif "all" in self.mode:
            self._set_heap_bp()
            self._set_data_bp()
            self._set_addr_bp()
            self.make_got_symbolic(self.ipath.state)
            self._set_stack_bp()

        elif "none" in self.mode:
            l.info("Mode is none, won't track anything")
            pass # No tracking

        else:
            raise AngrAnalysisError("Invalid mode")

    def add_target(self, name, addr, proto):
        """
        Manually add a target to find.
        @proto is SleakProcedure prototype
        """
        self._custom_targets[name] = addr
        self._custom_protos[name] = proto

    def remove_target(self, name):
        try:
            self._targets.pop(name)
            self._custom_targets.pop(name)
        except:
            pass

    def set_malloc(self, addr):
        """
        Manually set the address of malloc() to track heap pointers
        """
        self._malloc = addr
        self._set_heap_bp()

    @property
    def targets(self):
        return dict(self._targets.items() + self._custom_targets.items())

    def _make_sym_argv(self, argc):
        """
        Make a symbolic argv, where argv[1] is concrete
        """
        if argc < 1:
            return []

        argv= [self.project.loader.main_bin.binary]

        if argc > 1:
            for i in range(1, argc):
                argv.append(StringSpec(sym_length=12))
        return argv

    ## Setting the breakpoints ##
    def _set_stack_bp(self):
        """
        Track stack pointer reads and make its content symbolic.
        """
        bp = simuvex.BP(simuvex.BP_BEFORE, action=self.make_sp_symbolic)
        self.ipath.state.inspect.add_breakpoint('reg_read', bp)

    def _set_data_bp(self):
        """
        Track access to data
        """
        self.make_data_symbolic(self.ipath.state)


    def _set_heap_bp(self):
        """
        Track malloc return pointers
        """

        if self._malloc is None:
            l.info("Could not find PLT stub addr for malloc, heap pointers "
                   "won't be tracked")
        else:
            action=self.make_heap_ptr_symbolic
            bp = simuvex.BP(simuvex.BP_AFTER, instruction=self._malloc, action=action)
            self.ipath.state.inspect.add_breakpoint('instruction', bp)
            l.info("Registering bp for malloc at 0x%x" % self._malloc)

    def _set_addr_bp(self):
        """
        Track anything that concretizes to an address inside the binary
        """

        # Mem writes: we store an expression in memory - this expression is an
        # address inside the binary
        self.ipath.state.inspect.add_breakpoint(
            'mem_write', simuvex.BP(simuvex.BP_AFTER, action=self.track_mem_write))

        #self.ipath.state.inspect.add_breakpoint(
        #    'reg_write', simuvex.BP(simuvex.BP_AFTER, action=self.track_reg_write))

    def find_targets(self):
        """
        What are the target addresses we are interested in ?
        These are output or interface functions.
        Returns a dict {name: addresses} where addresses are the PLT stubs of
        target functions.
        """
        targets={}
        for f in self.out_functions:
            if f in self.project.loader.main_bin.jmprel:
                try:
                    plt = self.project.loader.main_bin.get_call_stub_addr(f)
                    targets[f] = plt
                except:
                    l.warning("Could not detect plt stub addr for target %s" % repr(f))
                    pass

        l.info("Found targets (output functions) %s" % repr(targets))
        return targets
        #return tuple(targets.values())

    def _check_found_paths(self):
        """
        Iterates over all found paths to identify leaking ones
        """
        results = []
        if len(self.found_paths) > 0:
            self.reached_target = True

        # Found paths : output function reached
        for p in self.found_paths:
            r = self._check_path(p)
            if r is not None:
                results.append(r)
        self.leaks = results

    def _check_path(self, p):
        '''
        Check whether an individual path leaks
        '''
        sp = self.make_sleak_procedure(p)
        if sp is None:
            return
        if len(sp.badargs) > 0:
            l.info("Found leaking path - %s" % repr(sp))
            return sp

    def make_sleak_procedure(self, p):
        """
        @p: path where to make the SleakProcecure
        Note: the path must reach a known target, i.e., either one of the
        predefined ones, or the custom ones.
        """
        func = self._reached_target(p)
        if func is None:
            return
        sp = SleakProcedure(func, p, self.mode, self._find_proto(func))
        return sp

    def _find_proto(self, name):
        proto = []
        if name in self._custom_protos.keys():
            proto = self._custom_protos[name]
        return proto

    @property
    def found_paths(self):
        """
        Found paths: paths to the output functions
        """
        found=[]

        for p in self.terminated_paths:
            if self._reached_target(p) is not None:
                #found[p] = self._reached_target(p)
                found.append(p)

           # for succ in p.successors:
           #     if self._reached_target(succ) is not None:
           #         #found[succ] = self._reached_target(succ)
           #         found.append(succ)

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
        addr_xpr = state.inspect.mem_write_expr
        caddr = self._check_is_mapped_addr(state, addr_xpr)
        if caddr is None:
            return

        mem_loc_xpr = state.inspect.mem_write_address
        mem_loc = state.se.any_int(mem_loc_xpr)

        l.info("Auto tracking addr 0x%x" % caddr)
        state.memory.make_symbolic("TRACKED_MAPPED_ADDR", mem_loc, self.project.arch.bits/8)
        #state.memory.make_symbolic("TRACKED_MAPPED_ADDR", caddr, self._p.arch.bits/8)
        #self.tracked_addrs.append({addr:state.memory.load(caddr, self._p.arch.bits/8)})

    def _check_is_mapped_addr(self, state, addr_xpr):
        """
        Check whether the given expr concretizes to an address inside the binary
        """
        addr = state.se.any_int(addr_xpr)
        try:
            caddr = self._canonical_addr(addr)
        except:
            return None

        if self.project.loader.addr_is_mapped(caddr):
            return caddr

    def track_reg_write(self, state):
        xpr = state.inspect.reg_write_expr
        caddr = self._check_is_mapped_addr(self, state, xpr)
        if caddr is None:
            return

        off_xpr = state.inspect.reg_write_offset
        off = state.se.any_int(off_xpr)

        l.info("Auto tracking addr 0x%x" % caddr)
        state.registers.make_symbolic("TRACKED_MAPPED_ADDR", off, self.project.arch.bits/8)
        #self.tracked_addrs.append({addr:state.memory.load(addr, self._p.arch.bits/8)})


    def _canonical_addr(self, addr):
        """
        Canonical representation of addr - unused
        """
        fmtin = self.project.arch.struct_fmt()
        if not "<" in fmtin:
            return addr

        fmtout = fmtin.replace('<','>')
        return struct.unpack(fmtout, struct.pack(fmtin, addr))[0]

    def _track_mem_op(self, state, mode=None):
        """
        Look for addresses in memory expressions
        """

        if mode == 'w':
            addr_xpr = state.inspect.mem_write_expr
            mem_loc_xpr = state.inspect.mem_write_address

        elif mode == 'r':
            addr_xpr = state.inspect.mem_read_expr
            mem_loc_xpr = state.inspect.mem_read_address
        else:
            raise Exception ("Invalid mode")

        '''
        A better, but expensive solution using the constraint solver:
        # Add a constraint and return a new expression
        nxpr = state.se.ULT(addr_xpr, 2^bits)
        if state.se.solution(nxpr, False):
            return
        if not state.se.unique(addr_xpr):
            l.debug("Warning: there are mu
        '''

        # This is faster, and acutally, addresses referring to objects of the
        # binary should be hardcoded as immediate values by the compiler anyway
        addr = state.se.any_int(addr_xpr)
        mem_loc = state.se.any_int(mem_loc_xpr)

        # Any address in the binary
        if self.project.loader.addr_is_mapped(addr):
            l.info("Auto tracking addr 0x%x [%s]" % (addr, mode))
            state.memory.make_symbolic("TRACKED_ADDR", mem_loc, self.project.arch.bits/8)
            self.tracked_addrs.append({addr:state.memory.load(addr, self.project.arch.bits/8)})


    def make_sp_symbolic(self, state):
        """
        Whatever we read from the stack pointer register is made symbolic.
        It has the effect of "tainting" all stack variable addresses (not their content).
        """
        if state.inspect.reg_write_offset == self.project.arch.sp_offset or state.inspect.reg_read_offset == self.project.arch.sp_offset:
            state.registers.make_symbolic("STACK_TRACK", self.project.arch.sp_offset, self.project.arch.bits/8)
            l.debug("SP set symbolic")

    def make_heap_ptr_symbolic(self, state):
        """
        Make heap pointer returned by malloc and cmalloc symbolic
        """
        #if state.inspect.function_name == "malloc" or state.inspect.function_name == "calloc":
        #convention = simuvex.Conventions[state.arch.name](state.arch)
        #addr = convention.return_val(state)
        reg = state.arch.ret_offset
        state.registers.make_symbolic("HEAP_TRACK", reg, self.project.arch.bits/8)
        #addr = state.se.any_int(state.registers.load(reg))
        #state.memory.make_symbolic("TRACKED_HEAPPTR", addr, self._p.arch.bits/8)
        #l.debug("Heap ptr @0x%x made symbolic" % state.se.any_int(addr))
        l.debug("Heap ptr made symbolic - reg off %d" % reg)

    def make_got_symbolic(self, state):
        """
        Make the content of GOT slots symbolic. The GOT addresses themselves
        are not made symbolic.
        """
        got = self.project.loader.main_bin.gotaddr
        gotsz = self.project.loader.main_bin.gotsz

        pltgot = self.project.loader.main_bin.pltgotaddr
        pltgotsz = self.project.loader.main_bin.pltgotsz

        jmprel = self.project.loader.main_bin.jmprel

        # First, let's try to do it using the dynamic info
        if len(jmprel) > 0:
            for symbol, addr in jmprel.iteritems():
                state.memory.make_symbolic("PLTGOT_TRACK", addr, self.project.arch.bits/8)
                l.debug("pltgot entry 0x%x (%s) made symbolic" % (addr, symbol))

        # Otherwise, we do it from static info, if there are any
        elif pltgotsz is not None:
            for addr in range(pltgot, pltgot+pltgotsz, self.project.arch.bits/8):
                state.memory.make_symbolic("PLTGOT_TRACK", addr, self.project.arch.bits/8)
                l.debug("Make PLTGOT addr 0x%x symbolic" % addr)

        else:
            l.info("We don't know where is got.plt in this binary, not GOT addr tracking")


        if gotsz is not None:
            for addr in range(got, got+gotsz, self.project.arch.bits/8):
                l.debug("Make GOT addr 0x%x symbolic" % addr)
                state.memory.make_symbolic("GOT_TRACK", addr, self.project.arch.bits/8)


    def make_data_symbolic(self, state):
        """
        This is broken
        """
        strtab = self.project.loader.main_bin.strtab_vaddr
        for off, _ in self.project.loader.main_bin.strtab.iteritems():
            addr = off + strtab
            state.memory.make_symbolic("DATA_TRACK", addr, self.project.arch.bits/8)

    def get_stack_top(self, state):
        """
        We keep tracks of the highest stack address the program has accessed.
        """

        # We suppose the stack pointer has only one concrete solution
        sp = state.se.any_int(state.registers.load(self.project.arch.sp_offset))

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

    def __init__(self, name, path, mode='track_sp', fn_parameters=[]):
        """
        @name: name of the function
        @path: path reaching this function (or its PLT stub)
        @fn_parameters: custom prototype for this function (see self._fn_parameters)
        """

        self.path = path
        self.state = self.path.state # expected: the initial state of the PLT stub
        self.name = name
        self.mode = mode

        # Add custom prototype to the list
        if len(fn_parameters) > 0:
            self._fn_parameters[name] = fn_parameters

        # Functions depending on a format string
        if len(self._fn_parameters[name]) == 0:
            # The first argument to a function that requires a format string is
            # a pointer to the format string itself.
            self.types = ['p'] + self._parse_format_string(self.get_format_string())
            l.debug("Got types vector %s" % repr(self.types))
            self.n_args = len(self.types) # The format string and the args
        else:
            self.types = self._fn_parameters[name]
            self.n_args = len(self.types)

        self.badargs = self._check_args() # args leaking pointer info

    def get_arg_expr(self, arg_num):
        """
        What is the expression of argument number @arg_num ?
        """
        convention = Conventions[self.state.arch.name](self.state.arch)
        return convention.peek_arg(arg_num, self.state)

    def get_arg_val(self, arg_num):
        expr = self.get_arg_expr(arg_num)
        if not self.state.se.unique(expr):
            l.warning("There are multiple solutions, this is just one")
        return self.state.se.any_int(expr)

    def _check_args(self):
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
                #raise Exception("Oops, we got a symbolic pointer...")
                l.info("We got a symbolic pointer...")

            addr = self.state.se.any_int(expr)
            val = self.state.memory.load(addr, self.state.arch.bits/8)
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
            raise Exception("Symbolic string pointer... something is probably wrong")

        addr = self.state.se.any_int(arg0)

        string = ""
        size = 0

        # We increaze the size of the string by 10 characters each time
        # until we find the ending \x00
        while len(re.findall("\x00", string)) == 0:
            size = size + 10
            string = self.state.se.any_str(self.state.memory.load(addr, size))

        # Only get the part of the string we are interested in
        return string[0:string.find('\x00')]

    def _parse_format_string(self, fstr):

        '''
        TODO: We should assume that a format string:
            - starts with %
            - contains a number of characters for precision, length etc
            - ends with one of the specifiers cduxXefg%
        '''
        #fmt = re.findall(r'%.*(?cduxXefg%', fstr)

        fmt = re.findall(r'%[a-z]+', fstr)
        return map(self._format_str_types, fmt)

    def _format_str_types(self, fmt):
        """
        Conversion of format str types to simple types 'v' or 'p'
        """
        if fmt == "%s": #or fmt == "%p":
            return "p"
        else:
            return "v"

    def _arg_depends_on_address(self, arg_expr):
        """
        This determines whether the argument depends on an address (tracked or stack)
        """

        tstr = "TRACK"

        if tstr in repr(arg_expr):
            return True
        return False

    def __repr__(self):
        addr = self.path.addr
        return "<SleakProcedure at addr 0x%x (%s)>" % (addr, self.name)


"""
Calling conventions for supported architectures.
"""
class Convention(object):
    def __init__(self, arch):
        self.arch = arch
        self.skip=0

    def call_convention(self):
        call = self._call_convention()
        if call is None:
            raise Exception("Unsupported architecture for this convention")
        return call

    def _call_convention(self):
        raise Exception("Not yet implemented !")

    def return_addr(self):
        raise Exception("Not yet implemented !")

    def return_val(self, state):
        off = self.arch.ret_offset
        return state.registers.load(off, endness = state.arch.register_endness)

    def peek_arg(self, index, state):
        """
        Given a state, peek arg number @index from the right place (stack,
        registers...)
        """
        # Skip the return address
        args_mem_base = state.registers.load(state.arch.sp_offset) + self.arch.bits/8
        return self._arg_getter(self.call_convention(), args_mem_base,
                               self.arch.bits/8, index, state)

    def _arg_getter(self, reg_offsets, args_mem_base, stack_step, index,
                    state):
            """
            This function does NOT add refs, be careful to wrap it into something
            that does when it matters
            """
            if index < len(reg_offsets):
                expr = state.registers.load(reg_offsets[index],
                                           endness=state.arch.register_endness)
            else:
                index -= len(reg_offsets)
                mem_addr = args_mem_base + (index * stack_step)
                expr = state.memory.load(mem_addr, stack_step,
                                           endness=state.arch.memory_endness)
            return expr

class SYSCALL(Convention):
    def _call_convention(self):
        if self.arch.name == "AMD64":
            # Reg offsets for rdi, rsi, rdx, rcx, r8, r9
            return [ 72, 64, 32, 24, 80, 88 ]

class CDECL(Convention):

    def _call_convention(self):
        if self.arch.name== "X86":
            return [] # all on the stack

"""
Architecture specific stuff
"""

class Systemv_x64(Convention):
    def _call_convention(self):
            if self.arch.name == "AMD64":
                # rdi, rsi, rdx, rcx, r8, r9
                return [ 72, 64, 32, 24, 80, 88 ]

class ARM(Convention):
    def _call_convention(self):
        if self.arch.name in ("ARMEL", "ARMHF"):
            # Reg offsets of r0, r1, r2, r3
            return [ 8, 12, 16, 20 ]

class PPC32(Convention):
    def _call_convention(self):
        if self.arch.name == "PPC32":
            return [ 28, 32, 36, 40, 44, 48, 52, 56 ] # r3 through r10

class PPC64(Convention):
    def _call_convention(self):
        if self.arch.name == "PPC64":
            return [ 40, 48, 56, 64, 72, 80, 88, 96 ] # r3 through r10

class MIPS32(Convention):
    def _call_convention(self):
        if self.arch.name == "MIPS32":
            return [ 'a0', 'a1', 'a2', 'a3' ] # r4 through r7

Conventions = {'AMD64': Systemv_x64,
                        'ARM': ARM,
                        'PPC32': PPC32,
                        'PPC64': PPC64,
                        'MIPS32': MIPS32,
                        'X86': CDECL,
                        'SYSCALL': SYSCALL
                        }
