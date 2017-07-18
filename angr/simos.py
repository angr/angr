"""
Manage OS-level configuration.
"""

import logging
from collections import defaultdict
from archinfo import ArchARM, ArchMIPS32, ArchMIPS64, ArchX86, ArchAMD64, ArchPPC32, ArchPPC64, ArchAArch64
from .sim_state import SimState
from .state_plugins import SimStateSystem, SimActionData
from . import sim_options as o
from .calling_conventions import DEFAULT_CC, SYSCALL_CC
from .procedures import SIM_PROCEDURES as P, SIM_LIBRARIES as L
from cle import MetaELF, BackedCGC
from cle.address_translator import AT
import claripy

from .errors import AngrSyscallError, AngrUnsupportedSyscallError, AngrCallableError, AngrCallableMultistateError, AngrSimOSError
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
    def __init__(self, max_syscall_number=None, unknown_syscall_number=None):
        """
        Constructor.

        :param int or None max_syscall_number: The maximum syscall number of all supported syscalls in the platform.
        :param int unknown_syscall_number:     The syscall number to use for unknown/undefined syscalls.
        """
        self.max_syscall_number = max_syscall_number

        self.unknown_syscall_number = unknown_syscall_number

        self._table = { }
        self._addr_to_syscall = { }

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
        self._addr_to_syscall[syscall.pseudo_addr] = syscall

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

    def clear(self):
        """
        Clear all defined syscalls.

        :return: None
        """

        self._table = { }
        self._addr_to_syscall = { }

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

    def get_by_addr(self, addr):
        """
        Get a syscall by the pseudo address.

        :param int addr: The pseudo address assigned to the syscall.
        :return:         The syscall instance if the pseudo address is assigned to a syscall, or None otherwise.
        :rtype:          SyscallEntry or None
        """

        return self._addr_to_syscall.get(addr, None)


class SimOS(object):
    """
    A class describing OS/arch-level configuration.
    """

    def __init__(self, project, name=None):
        self.arch = project.arch
        self.project = project
        self.name = name
        self.continue_addr = None
        self.return_deadend = None

        unknown_syscall = P['syscalls']['stub']
        unknown_syscall_number = 1
        self.syscall_table = SyscallTable(unknown_syscall_number=unknown_syscall_number)
        self.syscall_table[unknown_syscall_number] = SyscallEntry('_unsupported', self.project._syscall_obj.mapped_base,
                                                                  unknown_syscall
                                                                  )

    def _load_syscalls(self, syscall_table, syscall_lib):
        """
        Load a table of syscalls to self.project._syscall_obj. Each syscall entry takes 8 bytes no matter what
        architecture it is on.

        :param dict syscall_table: Syscall table.
        :param str syscall_lib: Name of the syscall library
        :return: None
        """

        self.syscall_table.clear()

        base_addr = self.project._syscall_obj.mapped_base

        syscall_entry_count = 0 if not syscall_table else max(syscall_table.keys()) + 1
        for syscall_number in xrange(syscall_entry_count):

            syscall_addr = base_addr + syscall_number * 8

            if syscall_number in syscall_table:
                name, simproc_name = syscall_table[syscall_number]
                if isinstance(simproc_name, str) and simproc_name in P[syscall_lib]:
                    # They give us a string, do resolution
                    simproc = P[syscall_lib][simproc_name]
                elif isinstance(simproc_name, type):
                    # If they give us the type, just take it
                    simproc = simproc_name
                else:
                    # no SimProcedure is implemented for this syscall
                    simproc = P["syscalls"]["stub"]

                self.syscall_table[syscall_number] = SyscallEntry(name, syscall_addr, simproc)

            else:
                # no syscall number available in the pre-defined syscall table
                self.syscall_table[syscall_number] = SyscallEntry("_unsupported", syscall_addr,
                                                                  P["syscalls"]["stub"],
                                                                  supported=False
                                                                  )

        # Now here is the fallback syscall stub
        unknown_syscall_addr = base_addr + (syscall_entry_count + 1) * 8
        unknown_syscall_number = syscall_entry_count + 1
        # set unknown_syscall_number
        self.syscall_table.unknown_syscall_number = unknown_syscall_number
        self.syscall_table[unknown_syscall_number] = SyscallEntry("_unknown", unknown_syscall_addr,
                                                                   P["syscalls"]["stub"],
                                                                   supported=False
                                                                   )

    def syscall_info(self, state):
        """
        Get information about the syscall that is about to be called. Note that symbolic syscalls are not supported -
        the syscall number *must* have only one solution.

        :param SimState state: the program state.
        :return: A tuple of (cc, syscall_addr, syscall_name, syscall_class)
        :rtype: tuple
        """

        if state.os_name in SYSCALL_CC[state.arch.name]:
            cc = SYSCALL_CC[state.arch.name][state.os_name](state.arch)
        else:
            # Use the default syscall calling convention - it may bring problems
            cc = SYSCALL_CC[state.arch.name]['default'](state.arch)

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
                state.history.add_event('resilience', resilience_type='syscall', syscall=n, message='unsupported syscall')

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

        :param SimState state: the program state.
        :return: an instanciated, but not executed SimProcedure for this syscall
        :rtype: SimProcedure
        """

        cc, syscall_addr, syscall_name, syscall_class = self.syscall_info(state)

        state.ip = syscall_addr
        syscall = syscall_class(
                project=state.project,
                cc=cc,
                display_name=syscall_name)
        return syscall

    def configure_project(self):
        """
        Configure the project to set up global settings (like SimProcedures).
        """
        self.return_deadend = self.project._extern_obj.get_pseudo_addr('angr##return_deadend')
        self.project.hook(self.return_deadend, CallReturn())

        def irelative_resolver(resolver_addr):
            resolver = self.project.factory.callable(resolver_addr, concrete_only=True)
            try:
                val = resolver()
            except AngrCallableMultistateError:
                l.error("Resolver at %#x failed to resolve! (multivalued)", resolver_addr)
                return None
            except AngrCallableError:
                l.error("Resolver at %#x failed to resolve!", resolver_addr)
                return None


            return val._model_concrete.value

        self.project.loader.perform_irelative_relocs(irelative_resolver)

    def state_blank(self, addr=None, initial_prefix=None, stack_size=1024*1024*8, **kwargs):
        """
        Initialize a blank state.

        All parameters are optional.

        :param addr:            The execution start address.
        :param initial_prefix:
        :return:                The initialized SimState.
        :rtype:                 SimState
        """
        if kwargs.get('mode', None) is None:
            kwargs['mode'] = self.project._default_analysis_mode
        if kwargs.get('permissions_backer', None) is None:
            # just a dict of address ranges to permission bits
            permission_map = { }
            for obj in self.project.loader.all_objects:
                for seg in obj.segments:
                    perms = 0
                    # bit values based off of protection bit values from sys/mman.h
                    if seg.is_readable:
                        perms |= 1 # PROT_READ
                    if seg.is_writable:
                        perms |= 2 # PROT_WRITE
                    if seg.is_executable:
                        perms |= 4 # PROT_EXEC
                    permission_map[(seg.min_addr, seg.max_addr)] = perms
            permissions_backer = (self.project.loader.main_bin.execstack, permission_map)
            kwargs['permissions_backer'] = permissions_backer
        if kwargs.get('memory_backer', None) is None:
            kwargs['memory_backer'] = self.project.loader.memory
        if kwargs.get('os_name', None) is None:
            kwargs['os_name'] = self.name

        state = SimState(self.project, **kwargs)

        stack_end = state.arch.initial_sp
        if o.ABSTRACT_MEMORY not in state.options:
            state.memory.mem._preapproved_stack = IRange(stack_end - stack_size, stack_end)

        if o.INITIALIZE_ZERO_REGISTERS in state.options:
            highest_reg_offset, reg_size = max(state.arch.registers.values())
            for i in range(0, highest_reg_offset + reg_size, state.arch.bytes):
                state.registers.store(i, state.se.BVV(0, state.arch.bits))
        if hasattr(state.regs,"sp"):
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

        if addr is None: addr = self.project.entry
        state.regs.ip = addr

        # set up the "root history" node
        state.scratch.ins_addr = addr
        state.scratch.bbl_addr = addr
        state.scratch.stmt_idx = 0
        state.history.jumpkind = 'Ijk_Boring'
        return state

    def state_entry(self, **kwargs):
        return self.state_blank(**kwargs)

    def state_full_init(self, **kwargs):
        return self.state_entry(**kwargs)

    def state_call(self, addr, *args, **kwargs):
        cc = kwargs.pop('cc', DEFAULT_CC[self.arch.name](self.project.arch))
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
        return self.project._extern_obj.get_pseudo_addr(symbol_name)

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
            8: ('lseek', 'lseek'),
            9: ('mmap', 'mmap'),
            10: ('mprotect', 'mprotect'),
            11: ('munmap', 'munmap'),
            12: ('brk', 'brk'),
            13: ('sigaction', 'sigaction'),
            14: ('sigprocmask', 'sigprocmask'),
            39: ('getpid', 'getpid'),
            60: ('exit', 'exit'),
            63: ('uname', 'uname'),
            87: ('unlink', 'unlink'),
            158: ('arch_prctl','arch_prctl'),
            186: ('gettid', 'gettid'),
            201: ('time', 'time'),
            231: ('exit_group', 'exit'),  # really exit_group, but close enough
            234: ('tgkill', 'tgkill'),
        },
        'X86': {
            1: ('exit', 'exit'),
            3: ('read', 'read'),
            4: ('write', 'write'),
            5: ('open', 'open'),
            6: ('close', 'close'),
            13: ('time', 'time'),
            45: ('brk', 'brk'),
            122: ('uname', 'uname'),
            252: ('exit_group', 'exit'),  # really exit_group, but close enough
        },
        'PPC32': {
            1: ('exit', 'exit'),
            3: ('read', 'read'),
            4: ('write', 'write'),
            5: ('open', 'open'),
            6: ('close', 'close'),
            45: ('brk', 'brk'),
        },
        'PPC64': {

        },
        'MIPS32': {
            4001: ('exit', 'exit'),
            4003: ('read', 'read'),
            4004: ('write', 'write'),
            4005: ('open', 'open'),
            4006: ('close', 'close'),
            4045: ('brk', 'brk'),
        },
        'MIPS64': {
            5000: ('read', 'read'),
            5001: ('write', 'write'),
            5002: ('open', 'open'),
            5003: ('close', 'close'),
            5012: ('brk', 'brk'),
            5058: ('exit', 'exit'),
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

        self._loader_addr = self.project._extern_obj.get_pseudo_addr('angr##loader')
        self._loader_lock_addr = self.project._extern_obj.get_pseudo_addr('angr##loader_lock')
        self._loader_unlock_addr = self.project._extern_obj.get_pseudo_addr('angr##loader_unlock')
        self._vsyscall_addr = self.project._extern_obj.get_pseudo_addr('angr##vsyscall')
        self.project.hook(self._loader_addr, P['linux_loader']['LinuxLoader']())
        self.project.hook(self._loader_lock_addr, P['linux_loader']['_dl_rtld_lock_recursive']())
        self.project.hook(self._loader_unlock_addr, P['linux_loader']['_dl_rtld_unlock_recursive']())
        self.project.hook(self._vsyscall_addr, P['linux_kernel']['_vsyscall']())

        ld_obj = self.project.loader.linux_loader_object
        if ld_obj is not None:
            # there are some functions we MUST use the simprocedures for, regardless of what the user wants
            tlsfunc = ld_obj.get_symbol('__tls_get_addr')
            if tlsfunc is not None and not self.project.is_hooked(tlsfunc.rebased_addr):
                self.project.hook(tlsfunc.rebased_addr, P['ld.so'].get('__tls_get_addr'))

            tlsfunc = ld_obj.get_symbol('___tls_get_addr')
            if tlsfunc is not None and not self.project.is_hooked(tlsfunc.rebased_addr):
                self.project.hook(tlsfunc.rebased_addr, P['ld.so'].get('___tls_get_addr'))

            # set up some static data in the loader object...
            _rtld_global = ld_obj.get_symbol('_rtld_global')
            if _rtld_global is not None:
                if isinstance(self.project.arch, ArchAMD64):
                    self.project.loader.memory.write_addr_at(_rtld_global.rebased_addr + 0xF08, self._loader_lock_addr)
                    self.project.loader.memory.write_addr_at(_rtld_global.rebased_addr + 0xF10, self._loader_unlock_addr)

            # TODO: what the hell is this
            _rtld_global_ro = ld_obj.get_symbol('_rtld_global_ro')
            if _rtld_global_ro is not None:
                pass

        tls_obj = self.project.loader.tls_object
        if tls_obj is not None:
            if isinstance(self.project.arch, ArchAMD64):
                self.project.loader.memory.write_addr_at(tls_obj.thread_pointer + 0x28, 0x5f43414e4152595f)
                self.project.loader.memory.write_addr_at(tls_obj.thread_pointer + 0x30, 0x5054524755415244)
            elif isinstance(self.project.arch, ArchX86):
                self.project.loader.memory.write_addr_at(tls_obj.thread_pointer + 0x10, self._vsyscall_addr)
            elif isinstance(self.project.arch, ArchARM):
                self.project.hook(0xffff0fe0, P['linux_kernel']['_kernel_user_helper_get_tls']())


        # Only set up ifunc resolution if we are using the ELF backend on AMD64
        if isinstance(self.project.loader.main_bin, MetaELF):
            if isinstance(self.project.arch, ArchAMD64):
                for binary in self.project.loader.all_objects:
                    if not isinstance(binary, MetaELF):
                        continue
                    for reloc in binary.relocs:
                        if reloc.symbol is None or reloc.resolvedby is None:
                            continue
                        try:
                            if reloc.resolvedby.elftype != 'STT_GNU_IFUNC':
                                continue
                        except AttributeError:
                            continue
                        gotaddr = reloc.addr
                        gotvalue = self.project.loader.memory.read_addr_at(gotaddr)
                        if self.project.is_hooked(gotvalue):
                            continue
                        # Replace it with a ifunc-resolve simprocedure!
                        kwargs = {
                                'funcaddr': gotvalue,
                                'gotaddr': gotaddr,
                                'funcname': reloc.symbol.name
                        }
                        # TODO: should this be replaced with hook_symbol?
                        randaddr = self.project._extern_obj.get_pseudo_addr('ifunc_%s_%s' % (binary.binary, reloc.symbol.name))
                        self.project.hook(randaddr, P['linux_loader']['IFuncResolver'](**kwargs))
                        self.project.loader.memory.write_addr_at(gotaddr, randaddr)

        self._load_syscalls(SimLinux.SYSCALL_TABLE[self.arch.name], "syscalls")

    def state_blank(self, fs=None, concrete_fs=False, chroot=None, **kwargs):
        state = super(SimLinux, self).state_blank(**kwargs) #pylint:disable=invalid-name

        if self.project.loader.tls_object is not None:
            if isinstance(state.arch, ArchAMD64):
                state.regs.fs = self.project.loader.tls_object.user_thread_pointer
            elif isinstance(state.arch, ArchX86):
                state.regs.gs = self.project.loader.tls_object.user_thread_pointer >> 16
            elif isinstance(state.arch, (ArchMIPS32, ArchMIPS64)):
                state.regs.ulr = self.project.loader.tls_object.user_thread_pointer
            elif isinstance(state.arch, ArchPPC32):
                state.regs.r2 = self.project.loader.tls_object.user_thread_pointer
            elif isinstance(state.arch, ArchPPC64):
                state.regs.r13 = self.project.loader.tls_object.user_thread_pointer
            elif isinstance(state.arch, ArchAArch64):
                state.regs.tpidr_el0 = self.project.loader.tls_object.user_thread_pointer

        last_addr = self.project.loader.main_bin.get_max_addr()
        brk = last_addr - last_addr % 0x1000 + 0x1000

        state.register_plugin('posix', SimStateSystem(fs=fs, concrete_fs=concrete_fs, chroot=chroot, brk=brk))

        if self.project.loader.main_bin.is_ppc64_abiv1:
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
                    if self.project.loader.main_bin.is_ppc64_abiv1:
                        state.registers.store(reg, self.project.loader.main_bin.ppc64_initial_rtoc)
                elif val == 'thread_pointer':
                    state.registers.store(reg, self.project.loader.tls_object.user_thread_pointer)
                else:
                    l.warning('Unknown entry point register value indicator "%s"', val)
            else:
                l.error('What the ass kind of default value is %s?', val)

    def state_full_init(self, **kwargs):
        kwargs['addr'] = self._loader_addr
        return super(SimLinux, self).state_full_init(**kwargs)

    def prepare_function_symbol(self, symbol_name):
        """
        Prepare the address space with the data necessary to perform relocations pointing to the given symbol.
        """
        if self.arch.name == 'PPC64':
            pseudo_hookaddr = self.project._extern_obj.get_pseudo_addr(symbol_name + '#func')
            pseudo_toc = self.project._extern_obj.get_pseudo_addr(symbol_name + '#func', size=0x18)
            self.project._extern_obj.memory.write_addr_at(
                AT.from_va(pseudo_toc, self.project._extern_obj).to_rva(), pseudo_hookaddr)
            return pseudo_hookaddr
        else:
            return self.project._extern_obj.get_pseudo_addr(symbol_name)

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

        s.register_plugin('posix', SimStateSystem(fs=fs))

        # Create the CGC plugin
        s.get_plugin('cgc')

        # set up the address for concrete transmits
        s.unicorn.transmit_addr = self.syscall_table[2].pseudo_addr

        return s

    def state_entry(self, **kwargs):
        if isinstance(self.project.loader.main_bin, BackedCGC):
            kwargs['permissions_backer'] = (True, self.project.loader.main_bin.permissions_map)
        kwargs['add_options'] = {o.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY} | kwargs.get('add_options', set())

        state = super(SimCGC, self).state_entry(**kwargs)

        if isinstance(self.project.loader.main_bin, BackedCGC):
            for reg, val in self.project.loader.main_bin.initial_register_values():
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
            state.cgc.allocation_base = self.project.loader.main_bin.current_allocation_base

            # Do all the writes
            writes_backer = self.project.loader.main_bin.writes_backer
            stdout = 1
            for size in writes_backer:
                if size == 0:
                    continue
                str_to_write = state.posix.files[1].content.load(state.posix.files[1].pos, size)
                a = SimActionData(state, 'file_1_0', 'write', addr=claripy.BVV(state.posix.files[1].pos, state.arch.bits), data=str_to_write, size=size)
                state.posix.write(stdout, str_to_write, size)
                state.history.add_action(a)

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


os_mapping = defaultdict(lambda: SimOS)


def register_simos(name, cls):
    os_mapping[name] = cls

register_simos('unix', SimLinux)
register_simos('windows', SimOS)
register_simos('cgc', SimCGC)
