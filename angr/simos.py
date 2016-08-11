"""
Manage OS-level configuration.
"""

import logging

from archinfo import ArchARM, ArchMIPS32, ArchMIPS64, ArchX86, ArchAMD64, ArchPPC32, ArchPPC64, ArchAArch64
from simuvex import SimState, SimIRSB, SimStateSystem, SimActionData
from simuvex import s_options as o, s_cc
from simuvex import SimProcedures
from simuvex.s_procedure import SimProcedure, SimProcedureContinuation
from cle import MetaELF, BackedCGC
import pyvex
import claripy

from .errors import AngrSyscallError, AngrUnsupportedSyscallError, AngrCallableError, AngrSimOSError
from .tablespecs import StringTableSpec

l = logging.getLogger("angr.simos")

class IRange(object):
    __slots__ = ('start', 'end')

    def __init__(self, start, end):
        self.start = start
        self.end = end

    def __contains__(self, k):
        if type(k) in (int, long):
            return k >= self.start and k < self.end
        return False

    def __getstate__(self):
        return self.start, self.end

    def __setstate__(self, state):
        self.start, self.end = state


class SyscallEntry(object):
    """
    Describes a syscall.

    :ivar str name:         Name of the syscall.
    :ivar int pseudo_addr:  The pseudo address assigned to this syscall.
    :ivar simproc:          The SimProcedure class for handling this syscall.
    :ivar bool supported:   True if this syscall is defined and has a SimProcedure implemented, False otherwise.
    """
    def __init__(self, name, pseudo_addr, simproc, supported=True):
        """
        Constructor.

        :param str name:        Syscall name.
        :param int pseudo_addr: The pseudo address assigned to this syscall.
        :param simproc:         The SimProcedure for handling this syscall.
        :param bool supported:  True if this syscall is defined and there is a SimProcedure implemented for it.
        """

        self.name = name
        self.pseudo_addr = pseudo_addr
        self.simproc = simproc
        self.supported = supported

    def __repr__(self):
        s = "<Syscall %s @ %#x%s>" % (self.name, self.pseudo_addr, ", unsupported" if not self.supported else "")
        return s


class SyscallTable(object):
    """
    Represents a syscall table.

    :ivar int max_syscall_number:       The maximum syscall number of all supported syscalls in the platform.
    :ivar int unknown_syscall_number:   The syscall number of the "unknown" syscall used for unsupported syscalls.
    """
    def __init__(self, max_syscall_number=None):
        """
        Constructor.

        :param int or None max_syscall_number: The maximum syscall number of all supported syscalls in the platform.
        """
        self.max_syscall_number = max_syscall_number

        self.unknown_syscall_number = None

        self._table = { }

    def __setitem__(self, syscall_number, syscall):
        """
        Insert a syscall entry to the table.

        :param int syscall_number:      Number of the syscall.
        :param SyscallEntry syscall:    The syscall to insert.
        :return: None
        """

        if syscall_number > self.max_syscall_number:
            self.max_syscall_number = syscall_number

        self._table[syscall_number] = syscall

    def __getitem__(self, syscall_number):
        """
        Get a syscall entry from the table.

        :param int syscall_number:  Number of the syscall.
        :return:                    The syscall entry.
        :rtype: SyscallEntry
        """

        if syscall_number in self._table:
            return self._table[syscall_number]
        raise KeyError('Syscall number %d not found in syscall table.' % syscall_number)

    def __len__(self):
        """
        Get the number of all syscalls supported by this syscall table.

        :return: The number of all syscalls supported.
        :rtype: int
        """

        return len(self._table)

    def __contains__(self, syscall_number):
        """
        Check if the sycall number is defined in this syscall table.

        :param int syscall_number: The syscall number to check.
        :return: True if the syscall is defined in this table, False otherwise.
        :rtype: int
        """

        return syscall_number in self._table

    @property
    def max_syscall(self):
        """
        Get the maximum syscall number, or None if the syscall table is empty and `max_syscall_number` is not set..

        :return: The syscall number.
        :rtype: int or None
        """

        return self.max_syscall_number

    @property
    def unknown_syscall(self):
        """
        Get the "unknown" syscall entry.

        :return: The syscall entry for unknown syscalls.
        :rtype: SyscallEntry
        """

        if self.unknown_syscall_number is None:
            raise AngrSyscallError('The unknown syscall number of this syscall table is not set.')

        return self[self.unknown_syscall_number]

    def supports(self, syscall_number):
        """
        Check if the syscall number is defined and supported.

        :param int syscall_number: The number of syscall to check.
        :return: True if the syscall number is defined and supported by angr, False otherwise
        :rtype: bool
        """

        if syscall_number not in self._table:
            return False

        return self._table[syscall_number].supported


class SimOS(object):
    """
    A class describing OS/arch-level configuration.
    """

    def __init__(self, project, name=None):
        self.arch = project.arch
        self.proj = project
        self.name = name
        self.continue_addr = None
        self.return_deadend = None
        self.syscall_table = SyscallTable()

    def _load_syscalls(self, syscall_table, syscall_lib):
        """
        Load a table of syscalls to self.proj._syscall_obj. Each syscall entry takes 8 bytes no matter what
        architecture it is on.

        :param dict syscall_table: Syscall table.
        :param str syscall_lib: Name of the syscall library
        :return: None
        """

        base_addr = self.proj._syscall_obj.rebase_addr

        syscall_entry_count = 0 if not syscall_table else max(syscall_table.keys()) + 1
        for syscall_number in xrange(syscall_entry_count):

            syscall_addr = base_addr + syscall_number * 8

            if syscall_number in syscall_table:
                name, simproc_name = syscall_table[syscall_number]

                if simproc_name in SimProcedures[syscall_lib]:
                    simproc = SimProcedures[syscall_lib][simproc_name]
                else:
                    # no SimProcedure is implemented for this syscall
                    simproc = SimProcedures["syscalls"]["stub"]

                self.syscall_table[syscall_number] = SyscallEntry(name, syscall_addr, simproc)

                # Write it to the SimProcedure dict
                self.proj._sim_procedures[syscall_addr] = (simproc, { })

            else:
                # no syscall number available in the pre-defined syscall table
                self.syscall_table[syscall_number] = SyscallEntry("_unsupported", syscall_addr,
                                                                  SimProcedures["syscalls"]["stub"],
                                                                  supported=False
                                                                  )

                # Write it to the SimProcedure dict
                self.proj._sim_procedures[syscall_addr] = (SimProcedures["syscalls"]["stub"], { })

        # Now here is the fallback syscall stub
        unknown_syscall_addr = base_addr + (syscall_entry_count + 1) * 8
        unknown_syscall_number = syscall_entry_count + 1
        self.syscall_table.unknown_syscall_number = unknown_syscall_number
        self.syscall_table[unknown_syscall_number] = SyscallEntry("_unknown", unknown_syscall_addr,
                                                                   SimProcedures["syscalls"]["stub"],
                                                                   supported=False
                                                                   )

        self.proj._sim_procedures[unknown_syscall_addr] = (SimProcedures["syscalls"]["stub"], { })

    def syscall_info(self, state):
        """
        Get information about the syscall that is about to be called. Note that symbolic syscalls are not supported -
        the syscall number *must* have only one solution.

        :param simuvex.s_state.SimState state: the program state.
        :return: A tuple of (cc, syscall_addr, syscall_name, syscall_class)
        :rtype: tuple
        """

        if state.os_name in s_cc.SyscallCC[state.arch.name]:
            cc = s_cc.SyscallCC[state.arch.name][state.os_name](state.arch)
        else:
            # Use the default syscall calling convention - it may bring problems
            cc = s_cc.SyscallCC[state.arch.name]['default'](state.arch)

        syscall_num = cc.syscall_num(state)

        possible = state.se.any_n_int(syscall_num, 2)

        if len(possible) > 1 and len(self.syscall_table) > 0:
            # Symbolic syscalls are not supported - we will create a 'unknown syscall" stub for it
            n = self.syscall_table.unknown_syscall_number
        elif not possible:
            # The state is not satisfiable
            raise AngrUnsupportedSyscallError("The program state is not satisfiable")
        else:
            n = possible[0]

        if not self.syscall_table.supports(n):
            if o.BYPASS_UNSUPPORTED_SYSCALL in state.options:
                state.log.add_event('resilience', resilience_type='syscall', syscall=n, message='unsupported syscall')

                syscall = self.syscall_table.unknown_syscall if n not in self.syscall_table else self.syscall_table[n]

            else:
                l.error("Syscall %d is not found for arch %s", n, state.arch.name)
                raise AngrUnsupportedSyscallError("Syscall %d is not found for arch %s" % (n, state.arch.name))
        else:
            syscall = self.syscall_table[n]

        return cc, syscall.pseudo_addr, syscall.name, syscall.simproc

    def handle_syscall(self, state):
        """
        Handle a state whose immediate preceding jumpkind is syscall by creating a new SimRun. Note that symbolic
        syscalls are not supported - the syscall number *must* have only one solution.

        :param simuvex.s_state.SimState state: the program state.
        :return: a new SimRun instance.
        :rtype: simuvex.s_procedure.SimProcedure
        """

        cc, syscall_addr, syscall_name, syscall_class = self.syscall_info(state)

        # The ip_at_syscall register is misused to save the return address for this syscall
        ret_to = state.regs.ip_at_syscall
        state.ip = syscall_addr

        syscall = syscall_class(state, addr=syscall_addr, ret_to=ret_to, convention=cc, syscall_name=syscall_name)

        return syscall

    def configure_project(self):
        """
        Configure the project to set up global settings (like SimProcedures).
        """
        self.continue_addr = self.proj._extern_obj.get_pseudo_addr('angr##simproc_continue')
        self.proj.hook(self.continue_addr, SimProcedureContinuation)
        self.return_deadend = self.proj._extern_obj.get_pseudo_addr('angr##return_deadend')
        self.proj.hook(self.return_deadend, CallReturn)

        def irelative_resolver(resolver_addr):
            resolver = self.proj.factory.callable(resolver_addr, concrete_only=True)
            try:
                val = resolver()
            except AngrCallableError:
                l.error("Resolver at %#x failed to resolve!", resolver_addr)
                return None

            if not val.singlevalued:
                l.error("Resolver at %#x failed to resolve! (multivalued)", resolver_addr)
                return None

            return val._model_concrete.value

        self.proj.loader.perform_irelative_relocs(irelative_resolver)

    def state_blank(self, addr=None, initial_prefix=None, stack_size=1024*1024*8, **kwargs):
        """
        Initialize a blank state.

        All parameters are optional.

        :param addr:            The execution start address.
        :param initial_prefix:
        :return:                The initialized SimState.
        :rtype:                 simuvex.SimState
        """
        if kwargs.get('mode', None) is None:
            kwargs['mode'] = self.proj._default_analysis_mode
        if kwargs.get('permissions_backer', None) is None:
            # just a dict of address ranges to permission bits
            permission_map = { }
            for obj in self.proj.loader.all_objects:
                for seg in obj.segments:
                    perms = 0
                    # bit values based off of protection bit values from sys/mman.h
                    if seg.is_readable:
                        perms |= 1 # PROT_READ
                    if seg.is_writable:
                        perms |= 2 # PROT_WRITE
                    if seg.is_executable:
                        perms |= 4 # PROT_EXEC
                    permission_map[(obj.rebase_addr + seg.min_addr, obj.rebase_addr + seg.max_addr)] = perms
            permissions_backer = (self.proj.loader.main_bin.execstack, permission_map)
            kwargs['permissions_backer'] = permissions_backer
        if kwargs.get('memory_backer', None) is None:
            kwargs['memory_backer'] = self.proj.loader.memory
        if kwargs.get('arch', None) is None:
            kwargs['arch'] = self.proj.arch
        if kwargs.get('os_name', None) is None:
            kwargs['os_name'] = self.name

        state = SimState(**kwargs)

        stack_end = state.arch.initial_sp
        if o.ABSTRACT_MEMORY not in state.options:
            state.memory.mem._preapproved_stack = IRange(stack_end - stack_size, stack_end)

        if o.INITIALIZE_ZERO_REGISTERS in state.options:
            highest_reg_offset, reg_size = max(state.arch.registers.values())
            for i in range(0, highest_reg_offset + reg_size, state.arch.bytes):
                state.registers.store(i, state.se.BVV(0, state.arch.bits))

        state.regs.sp = stack_end

        if initial_prefix is not None:
            for reg in state.arch.default_symbolic_registers:
                state.registers.store(reg, claripy.BVS(initial_prefix + "_" + reg,
                                                        state.arch.bits,
                                                        explicit_name=True))

        for reg, val, is_addr, mem_region in state.arch.default_register_values:

            region_base = None # so pycharm does not complain

            if is_addr:
                if isinstance(mem_region, tuple):
                    # unpack it
                    mem_region, region_base = mem_region
                elif mem_region == 'global':
                    # Backward compatibility
                    region_base = 0
                else:
                    raise AngrSimOSError('You must specify the base address for memory region "%s". ' % mem_region)

            if o.ABSTRACT_MEMORY in state.options and is_addr:
                address = claripy.ValueSet(state.arch.bits, mem_region, region_base, val)
                state.registers.store(reg, address)
            else:
                state.registers.store(reg, val)

        if addr is None: addr = self.proj.entry
        state.regs.ip = addr

        state.scratch.ins_addr = addr
        state.scratch.bbl_addr = addr
        state.scratch.stmt_idx = 0
        state.scratch.jumpkind = 'Ijk_Boring'

        state.procedure_data.hook_addr = self.continue_addr
        return state

    def state_entry(self, **kwargs):
        return self.state_blank(**kwargs)

    def state_full_init(self, **kwargs):
        return self.state_entry(**kwargs)

    def state_call(self, addr, *args, **kwargs):
        cc = kwargs.pop('cc', s_cc.DefaultCC[self.arch.name](self.proj.arch))
        state = kwargs.pop('base_state', None)
        toc = kwargs.pop('toc', None)

        ret_addr = kwargs.pop('ret_addr', self.return_deadend)
        stack_base = kwargs.pop('stack_base', None)
        alloc_base = kwargs.pop('alloc_base', None)
        grow_like_stack = kwargs.pop('grow_like_stack', True)

        if state is None:
            state = self.state_blank(addr=addr, **kwargs)
        else:
            state = state.copy()
            state.regs.ip = addr
        cc.setup_callsite(state, ret_addr, args, stack_base, alloc_base, grow_like_stack)

        if state.arch.name == 'PPC64' and toc is not None:
            state.regs.r2 = toc

        return state

    def prepare_call_state(self, calling_state, initial_state=None,
                           preserve_registers=(), preserve_memory=()):
        """
        This function prepares a state that is executing a call instruction.
        If given an initial_state, it copies over all of the critical registers to it from the
        calling_state. Otherwise, it prepares the calling_state for action.

        This is mostly used to create minimalistic for CFG generation. Some ABIs, such as MIPS PIE and
        x86 PIE, require certain information to be maintained in certain registers. For example, for
        PIE MIPS, this function transfer t9, gp, and ra to the new state.
        """

        if isinstance(self.arch, ArchMIPS32):
            if initial_state is not None:
                initial_state = self.state_blank()
            mips_caller_saves = ('s0', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 'gp', 'sp', 'bp', 'ra')
            preserve_registers = preserve_registers + mips_caller_saves + ('t9',)

        if initial_state is None:
            new_state = calling_state.copy()
        else:
            new_state = initial_state.copy()
            for reg in set(preserve_registers):
                new_state.registers.store(reg, calling_state.registers.load(reg))
            for addr, val in set(preserve_memory):
                new_state.memory.store(addr, calling_state.memory.load(addr, val))

        return new_state

    def prepare_function_symbol(self, symbol_name):
        """
        Prepare the address space with the data necessary to perform relocations pointing to the given symbol
        """
        return self.proj._extern_obj.get_pseudo_addr(symbol_name)

class SimLinux(SimOS):
    """
    OS-specific configuration for \\*nix-y OSes.
    """

    SYSCALL_TABLE = {
        'AMD64': {
            0: ('read', 'read'),
            1: ('write', 'write'),
            2: ('open', 'open'),
            3: ('close', 'close'),
            4: ('stat', 'stat'),
            5: ('fstat', 'fstat'),
            6: ('stat', 'stat'),
            9: ('mmap', 'mmap'),
            11: ('munmap', 'munmap'),
            12: ('brk', 'brk'),
            13: ('sigaction', 'sigaction'),
            14: ('sigprocmask', 'sigprocmask'),
            39: ('getpid', 'getpid'),
            60: ('exit', 'exit'),
            158: ('arch_prctl','arch_prctl'),
            186: ('gettid', 'gettid'),
            231: ('exit_group', 'exit'),  # really exit_group, but close enough
            234: ('tgkill', 'tgkill'),
        },
        'X86': {
            1: ('exit', 'exit'),
            3: ('read', 'read'),
            4: ('write', 'write'),
            5: ('open', 'open'),
            6: ('close', 'close'),
            45: ('brk', 'brk'),
            252: ('exit_group', 'exit'),  # really exit_group, but close enough
        },
        'PPC32': {

        },
        'PPC64': {

        },
        'MIPS32': {

        },
        'MIPS64': {

        },
        'ARM': {

        },
        'ARMEL': {

        },
        'ARMHF': {

        },
        'AARCH64': {

        }
    }

    def __init__(self, *args, **kwargs):
        super(SimLinux, self).__init__(*args, name="Linux", **kwargs)

        self._loader_addr = None
        self._loader_lock_addr = None
        self._loader_unlock_addr = None
        self._vsyscall_addr = None

    def configure_project(self):
        super(SimLinux, self).configure_project()

        self._loader_addr = self.proj._extern_obj.get_pseudo_addr('angr##loader')
        self._loader_lock_addr = self.proj._extern_obj.get_pseudo_addr('angr##loader_lock')
        self._loader_unlock_addr = self.proj._extern_obj.get_pseudo_addr('angr##loader_unlock')
        self._vsyscall_addr = self.proj._extern_obj.get_pseudo_addr('angr##vsyscall')
        self.proj.hook(self._loader_addr, LinuxLoader, kwargs={'project': self.proj})
        self.proj.hook(self._loader_lock_addr, _dl_rtld_lock_recursive)
        self.proj.hook(self._loader_unlock_addr, _dl_rtld_unlock_recursive)
        self.proj.hook(self._vsyscall_addr, _vsyscall)

        ld_obj = self.proj.loader.linux_loader_object
        if ld_obj is not None:
            tlsfunc = ld_obj.get_symbol('__tls_get_addr')
            if tlsfunc is not None:
                self.proj.hook(tlsfunc.rebased_addr, _tls_get_addr, kwargs={'ld': self.proj.loader})
            tlsfunc2 = ld_obj.get_symbol('___tls_get_addr')
            if tlsfunc2 is not None:
                if self.proj.arch.name == 'X86':
                    self.proj.hook(tlsfunc2.rebased_addr, _tls_get_addr_tunder_x86, kwargs={'ld': self.proj.loader})
                else:
                    l.error("Found an unknown ___tls_get_addr, please tell Andrew")

            _rtld_global = ld_obj.get_symbol('_rtld_global')
            if _rtld_global is not None:
                if isinstance(self.proj.arch, ArchAMD64):
                    self.proj.loader.memory.write_addr_at(_rtld_global.rebased_addr + 0xF08, self._loader_lock_addr)
                    self.proj.loader.memory.write_addr_at(_rtld_global.rebased_addr + 0xF10, self._loader_unlock_addr)

            _rtld_global_ro = ld_obj.get_symbol('_rtld_global_ro')
            if _rtld_global_ro is not None:
                pass

        tls_obj = self.proj.loader.tls_object
        if tls_obj is not None:
            if isinstance(self.proj.arch, ArchAMD64):
                self.proj.loader.memory.write_addr_at(tls_obj.thread_pointer + 0x28, 0x5f43414e4152595f)
                self.proj.loader.memory.write_addr_at(tls_obj.thread_pointer + 0x30, 0x5054524755415244)
            elif isinstance(self.proj.arch, ArchX86):
                self.proj.loader.memory.write_addr_at(tls_obj.thread_pointer + 0x10, self._vsyscall_addr)
            elif isinstance(self.proj.arch, ArchARM):
                self.proj.hook(0xffff0fe0, _kernel_user_helper_get_tls, kwargs={'ld': self.proj.loader})


        # Only set up ifunc resolution if we are using the ELF backend on AMD64
        if isinstance(self.proj.loader.main_bin, MetaELF):
            if isinstance(self.proj.arch, ArchAMD64):
                for binary in self.proj.loader.all_objects:
                    if not isinstance(binary, MetaELF):
                        continue
                    for reloc in binary.relocs:
                        if reloc.symbol is None or reloc.resolvedby is None:
                            continue
                        if reloc.resolvedby.type != 'STT_GNU_IFUNC':
                            continue
                        gotaddr = reloc.addr + binary.rebase_addr
                        gotvalue = self.proj.loader.memory.read_addr_at(gotaddr)
                        if self.proj.is_hooked(gotvalue):
                            continue
                        # Replace it with a ifunc-resolve simprocedure!
                        kwargs = {
                                'proj': self.proj,
                                'funcaddr': gotvalue,
                                'gotaddr': gotaddr,
                                'funcname': reloc.symbol.name
                        }
                        randaddr = self.proj._extern_obj.get_pseudo_addr('ifunc_' + reloc.symbol.name)
                        self.proj.hook(randaddr, IFuncResolver, kwargs=kwargs)
                        self.proj.loader.memory.write_addr_at(gotaddr, randaddr)

        self._load_syscalls(SimLinux.SYSCALL_TABLE[self.arch.name], "syscalls")

    def state_blank(self, fs=None, concrete_fs=False, chroot=None, **kwargs):
        state = super(SimLinux, self).state_blank(**kwargs) #pylint:disable=invalid-name

        if self.proj.loader.tls_object is not None:
            if isinstance(state.arch, ArchAMD64):
                state.regs.fs = self.proj.loader.tls_object.user_thread_pointer
            elif isinstance(state.arch, ArchX86):
                state.regs.gs = self.proj.loader.tls_object.user_thread_pointer >> 16
            elif isinstance(state.arch, (ArchMIPS32, ArchMIPS64)):
                state.regs.ulr = self.proj.loader.tls_object.user_thread_pointer
            elif isinstance(state.arch, ArchPPC32):
                state.regs.r2 = self.proj.loader.tls_object.user_thread_pointer
            elif isinstance(state.arch, ArchPPC64):
                state.regs.r13 = self.proj.loader.tls_object.user_thread_pointer
            elif isinstance(state.arch, ArchAArch64):
                state.regs.tpidr_el0 = self.proj.loader.tls_object.user_thread_pointer

        state.register_plugin('posix', SimStateSystem(fs=fs, concrete_fs=concrete_fs, chroot=chroot))

        if self.proj.loader.main_bin.is_ppc64_abiv1:
            state.libc.ppc64_abiv = 'ppc64_1'

        return state

    def state_entry(self, args=None, env=None, argc=None, **kwargs):
        state = super(SimLinux, self).state_entry(**kwargs)

        # Handle default values
        if args is None:
            args = []

        if env is None:
            env = {}

        # Prepare argc
        if argc is None:
            argc = claripy.BVV(len(args), state.arch.bits)
        elif type(argc) in (int, long):  # pylint: disable=unidiomatic-typecheck
            argc = claripy.BVV(argc, state.arch.bits)

        # Make string table for args/env/auxv
        table = StringTableSpec()

        # Add args to string table
        for arg in args:
            table.add_string(arg)
        table.add_null()

        # Add environment to string table
        for k, v in env.iteritems():
            if type(k) is str:  # pylint: disable=unidiomatic-typecheck
                k = claripy.BVV(k)
            elif type(k) is unicode:  # pylint: disable=unidiomatic-typecheck
                k = claripy.BVV(k.encode('utf-8'))
            elif isinstance(k, claripy.ast.Bits):
                pass
            else:
                raise TypeError("Key in env must be either string or bitvector")

            if type(v) is str:  # pylint: disable=unidiomatic-typecheck
                v = claripy.BVV(v)
            elif type(v) is unicode:  # pylint: disable=unidiomatic-typecheck
                v = claripy.BVV(v.encode('utf-8'))
            elif isinstance(v, claripy.ast.Bits):
                pass
            else:
                raise TypeError("Value in env must be either string or bitvector")

            table.add_string(k.concat(claripy.BVV('='), v))
        table.add_null()

        # Prepare the auxiliary vector and add it to the end of the string table
        # TODO: Actually construct a real auxiliary vector
        # current vector is an AT_RANDOM entry where the "random" value is 0xaec0aec0aec0...
        aux = [(25, ("AEC0"*8).decode('hex'))]
        for a, b in aux:
            table.add_pointer(a)
            if isinstance(b, str):
                table.add_string(b)
            else:
                table.add_pointer(b)

        table.add_null()
        table.add_null()

        # Dump the table onto the stack, calculate pointers to args, env, and auxv
        state.memory.store(state.regs.sp - 16, claripy.BVV(0, 8*16))
        argv = table.dump(state, state.regs.sp - 16)
        envp = argv + ((len(args) + 1) * state.arch.bytes)
        auxv = argv + ((len(args) + len(env) + 2) * state.arch.bytes)

        # Put argc on stack and fix the stack pointer
        newsp = argv - state.arch.bytes
        state.memory.store(newsp, argc, endness=state.arch.memory_endness)
        state.regs.sp = newsp

        if state.arch.name in ('PPC32',):
            state.stack_push(claripy.BVV(0, 32))
            state.stack_push(claripy.BVV(0, 32))
            state.stack_push(claripy.BVV(0, 32))
            state.stack_push(claripy.BVV(0, 32))

        # store argc argv envp auxv in the posix plugin
        state.posix.argv = argv
        state.posix.argc = argc
        state.posix.environ = envp
        state.posix.auxv = auxv
        self.set_entry_register_values(state)

        return state

    def set_entry_register_values(self, state):
        for reg, val in state.arch.entry_register_values.iteritems():
            if isinstance(val, (int, long)):
                state.registers.store(reg, val, size=state.arch.bytes)
            elif isinstance(val, (str,)):
                if val == 'argc':
                    state.registers.store(reg, state.posix.argc, size=state.arch.bytes)
                elif val == 'argv':
                    state.registers.store(reg, state.posix.argv)
                elif val == 'envp':
                    state.registers.store(reg, state.posix.environ)
                elif val == 'auxv':
                    state.registers.store(reg, state.posix.auxv)
                elif val == 'ld_destructor':
                    # a pointer to the dynamic linker's destructor routine, to be called at exit
                    # or NULL. We like NULL. It makes things easier.
                    state.registers.store(reg, 0)
                elif val == 'toc':
                    if self.proj.loader.main_bin.is_ppc64_abiv1:
                        state.registers.store(reg, self.proj.loader.main_bin.ppc64_initial_rtoc)
                elif val == 'thread_pointer':
                    state.registers.store(reg, self.proj.loader.tls_object.user_thread_pointer)
                else:
                    l.warning('Unknown entry point register value indicator "%s"', val)
            else:
                l.error('What the ass kind of default value is %s?', val)

    def state_full_init(self, **kwargs):
        kwargs['addr'] = self.proj._extern_obj.get_pseudo_addr('angr##loader')
        return super(SimLinux, self).state_full_init(**kwargs)

    def prepare_function_symbol(self, symbol_name):
        """
        Prepare the address space with the data necessary to perform relocations pointing to the given symbol.
        """
        if self.arch.name == 'PPC64':
            pseudo_hookaddr = self.proj._extern_obj.get_pseudo_addr(symbol_name + '#func')
            pseudo_toc = self.proj._extern_obj.get_pseudo_addr(symbol_name + '#func', size=0x18)
            self.proj._extern_obj.memory.write_addr_at(pseudo_toc - self.proj._extern_obj.rebase_addr, pseudo_hookaddr)
            return pseudo_hookaddr
        else:
            return self.proj._extern_obj.get_pseudo_addr(symbol_name)

class SimCGC(SimOS):

    SYSCALL_TABLE = {
        1: ('_terminate', '_terminate'),
        2: ('transmit', 'transmit'),
        3: ('receive', 'receive'),
        4: ('fdwait', 'fdwait'),
        5: ('allocate', 'allocate'),
        6: ('deallocate', 'deallocate'),
        7: ('random', 'random'),
    }

    def __init__(self, *args, **kwargs):
        super(SimCGC, self).__init__(*args, name="CGC", **kwargs)

    def configure_project(self):
        super(SimCGC, self).configure_project()

        self._load_syscalls(SimCGC.SYSCALL_TABLE, "cgc")

    def state_blank(self, fs=None, **kwargs):
        s = super(SimCGC, self).state_blank(**kwargs)  # pylint:disable=invalid-name

        # Special stack base for CGC binaries to work with Shellphish CRS
        s.regs.sp = 0xbaaaaffc

        # Map the special cgc memory
        if o.ABSTRACT_MEMORY not in s.options:
            s.memory.mem._preapproved_stack = IRange(0xbaaab000 - 1024*1024*8, 0xbaaab000)
            s.memory.map_region(0x4347c000, 4096, 1)

        # 'main' gets called with the magic page address as the first fast arg
        s.regs.ecx = 0x4347c000

        s.register_plugin('posix', SimStateSystem(fs=fs))

        # Create the CGC plugin
        s.get_plugin('cgc')

        # set up the address for concrete transmits
        s.unicorn.transmit_addr = self.syscall_table[2].pseudo_addr

        return s

    def state_entry(self, **kwargs):
        if isinstance(self.proj.loader.main_bin, BackedCGC):
            kwargs['permissions_backer'] = (True, self.proj.loader.main_bin.permissions_map)
        kwargs['add_options'] = {o.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY} | kwargs.get('add_options', set())

        state = super(SimCGC, self).state_entry(**kwargs)

        if isinstance(self.proj.loader.main_bin, BackedCGC):
            for reg, val in self.proj.loader.main_bin.initial_register_values():
                if reg in state.arch.registers:
                    setattr(state.regs, reg, val)
                elif reg == 'eflags':
                    pass
                elif reg == 'fctrl':
                    state.regs.fpround = (val & 0xC00) >> 10
                elif reg == 'fstat':
                    state.regs.fc3210 = (val & 0x4700)
                elif reg == 'ftag':
                    empty_bools = [((val >> (x*2)) & 3) == 3 for x in xrange(8)]
                    tag_chars = [claripy.BVV(0 if x else 1, 8) for x in empty_bools]
                    for i, tag in enumerate(tag_chars):
                        setattr(state.regs, 'fpu_t%d' % i, tag)
                elif reg in ('fiseg', 'fioff', 'foseg', 'fooff', 'fop'):
                    pass
                elif reg == 'mxcsr':
                    state.regs.sseround = (val & 0x600) >> 9
                else:
                    l.error("What is this register %s I have to translate?", reg)

            # Update allocation base
            state.cgc.allocation_base = self.proj.loader.main_bin.current_allocation_base

            # Do all the writes
            writes_backer = self.proj.loader.main_bin.writes_backer
            stdout = 1
            for size in writes_backer:
                if size == 0:
                    continue
                str_to_write = state.posix.files[1].content.load(state.posix.files[1].pos, size)
                a = SimActionData(state, 'file_1_0', 'write', addr=claripy.BVV(state.posix.files[1].pos, state.arch.bits), data=str_to_write, size=size)
                state.posix.write(stdout, str_to_write, size)
                state.log.add_action(a)

        else:
            # Set CGC-specific variables
            state.regs.eax = 0
            state.regs.ebx = 0
            state.regs.ecx = 0x4347c000
            state.regs.edx = 0
            state.regs.edi = 0
            state.regs.esi = 0
            state.regs.esp = 0xbaaaaffc
            state.regs.ebp = 0
            state.regs.cc_dep1 = 0x202  # default eflags
            state.regs.cc_op = 0        # OP_COPY
            state.regs.cc_dep2 = 0      # doesn't matter
            state.regs.cc_ndep = 0      # doesn't matter

            # fpu values
            state.regs.mm0 = 0
            state.regs.mm1 = 0
            state.regs.mm2 = 0
            state.regs.mm3 = 0
            state.regs.mm4 = 0
            state.regs.mm5 = 0
            state.regs.mm6 = 0
            state.regs.mm7 = 0
            state.regs.fpu_tags = 0
            state.regs.fpround = 0
            state.regs.fc3210 = 0x0300
            state.regs.ftop = 0

            # sse values
            state.regs.sseround = 0
            state.regs.xmm0 = 0
            state.regs.xmm1 = 0
            state.regs.xmm2 = 0
            state.regs.xmm3 = 0
            state.regs.xmm4 = 0
            state.regs.xmm5 = 0
            state.regs.xmm6 = 0
            state.regs.xmm7 = 0

            # segmentation registers
            state.regs.ds = 0
            state.regs.es = 0
            state.regs.fs = 0
            state.regs.gs = 0
            state.regs.ss = 0
            state.regs.cs = 0

        return state

#
# Loader-related simprocedures
#

class IFuncResolver(SimProcedure):
    NO_RET = True

    # pylint: disable=arguments-differ,unused-argument
    def run(self, proj=None, funcaddr=None, gotaddr=None, funcname=None):
        resolve = proj.factory.callable(funcaddr, concrete_only=True)
        try:
            value = resolve()
        except AngrCallableError:
            l.critical("Ifunc \"%s\" failed to resolve!", funcname)
            #import IPython; IPython.embed()
            raise
        self.state.memory.store(gotaddr, value, endness=self.state.arch.memory_endness)
        self.add_successor(self.state, value, claripy.true, 'Ijk_Boring')

    def __repr__(self):
        return '<IFuncResolver %s>' % self.kwargs.get('funcname', None)

class LinuxLoader(SimProcedure):
    NO_RET = True

    # pylint: disable=unused-argument,arguments-differ,attribute-defined-outside-init
    local_vars = ('initializers',)
    def run(self, project=None):
        self.initializers = project.loader.get_initializers()
        self.run_initializer(project)

    def run_initializer(self, project=None):
        if len(self.initializers) == 0:
            project._simos.set_entry_register_values(self.state)
            self.jump(project.entry)
        else:
            addr = self.initializers.pop(0)
            self.call(addr, (self.state.posix.argc, self.state.posix.argv, self.state.posix.environ), 'run_initializer')

class _tls_get_addr(SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, ptr, ld=None):
        module_id = self.state.se.any_int(self.state.memory.load(ptr, self.state.arch.bytes, endness=self.state.arch.memory_endness))
        offset = self.state.se.any_int(self.state.memory.load(ptr+self.state.arch.bytes, self.state.arch.bytes, endness=self.state.arch.memory_endness))
        return claripy.BVV(ld.tls_object.get_addr(module_id, offset), self.state.arch.bits)

class _tls_get_addr_tunder_x86(SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, ld=None):
        ptr = self.state.regs.eax
        return self.inline_call(_tls_get_addr, ptr, ld=ld).ret_expr

class _dl_rtld_lock_recursive(SimProcedure):
    # pylint: disable=arguments-differ, unused-argument
    def run(self, lock):
        # For future reference:
        # ++((pthread_mutex_t *)(lock))->__data.__count;
        return

class _dl_rtld_unlock_recursive(SimProcedure):
    def run(self):
        return

class _vsyscall(SimProcedure):
    NO_RET = True

    # This is pretty much entirely copied from SimProcedure.ret
    def run(self):
        if self.cleanup:
            self.state.options.discard(o.AST_DEPS)
            self.state.options.discard(o.AUTO_REFS)

        ret_irsb = pyvex.IRSB(self.state.arch.ret_instruction, self.addr, self.state.arch)
        ret_simirsb = SimIRSB(self.state, ret_irsb, inline=True, addr=self.addr)
        if not ret_simirsb.flat_successors + ret_simirsb.unsat_successors:
            ret_state = ret_simirsb.default_exit
        else:
            ret_state = (ret_simirsb.flat_successors + ret_simirsb.unsat_successors)[0]

        if self.cleanup:
            self.state.options.add(o.AST_DEPS)
            self.state.options.add(o.AUTO_REFS)

        self.add_successor(ret_state, ret_state.scratch.target, ret_state.scratch.guard, 'Ijk_Sys')

class _kernel_user_helper_get_tls(SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, ld=None):
        self.state.regs.r0 = ld.tls_object.user_thread_pointer
        return

class CallReturn(SimProcedure):
    NO_RET = True

    def run(self):
        l.info("A factory.call_state-created path returned!")
        return

os_mapping = {
    'unix': SimLinux,
    'unknown': SimOS,
    'windows': SimOS,
    'cgc': SimCGC,
}
