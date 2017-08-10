"""
Manage OS-level configuration.
"""

import os
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

from .errors import AngrUnsupportedSyscallError, AngrCallableError, AngrCallableMultistateError, AngrSimOSError
from .tablespecs import StringTableSpec

l = logging.getLogger("angr.simos")


class IRange(object):
    """
    A simple range object for testing inclusion. Like xrange but works for huge numbers.
    """
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
        self.syscall_library = None
        self.kernel_base = None

    def syscall(self, state, allow_unsupported=True):
        """
        Given a state, return the procedure corresponding to the current syscall.
        This procedure will have .syscall_number, .display_name, and .addr set.

        :param state:               The state to get the syscall number from
        :param allow_unsupported    Whether to return a "dummy" sycall instead of raising an unsupported exception
        """
        if state.os_name in SYSCALL_CC[state.arch.name]:
            cc = SYSCALL_CC[state.arch.name][state.os_name](state.arch)
        else:
            # Use the default syscall calling convention - it may bring problems
            cc = SYSCALL_CC[state.arch.name]['default'](state.arch)

        sym_num = cc.syscall_num(state)
        possible = state.se.any_n_int(sym_num, 2)

        if len(possible) == 0:
            raise AngrUnsupportedSyscallError("The program state is not satisfiable")
        elif len(possible) == 1:
            num = possible[0]
        elif allow_unsupported:
            num = self.syscall_library.maximum_syscall_number(self.arch.name) + 1 if self.syscall_library else 0
        else:
            raise AngrUnsupportedSyscallError("Got a symbolic syscall number")

        proc = self.syscall_from_number(num, allow_unsupported=allow_unsupported)
        proc.cc = cc
        return proc

    def is_syscall_addr(self, addr):
        if self.kernel_base is None:
            return False
        addr -= self.kernel_base
        return 0 <= addr < 0x4000 # TODO: make this number come from somewhere

    def syscall_from_addr(self, addr, allow_unsupported=True):
        number = addr - self.kernel_base
        return self.syscall_from_number(number, allow_unsupported=allow_unsupported)

    def syscall_from_number(self, number, allow_unsupported=True):
        if not allow_unsupported and not self.syscall_library:
            raise AngrUnsupportedSyscallError("%s does not have a library of syscalls implemented", self.name)

        addr = number + self.kernel_base

        if self.syscall_library is None:
            proc = P['stubs']['syscall']()
        elif not allow_unsupported and not self.syscall_library.has_implementation(number, self.arch):
            raise AngrUnsupportedSyscallError("No implementation for syscall %d" % number)
        else:
            proc = self.syscall_library.get(number, self.arch)

        proc.addr = addr
        return proc

    def configure_project(self):
        """
        Configure the project to set up global settings (like SimProcedures).
        """
        self.return_deadend = self.project.loader.extern_object.allocate()
        self.project.hook(self.return_deadend, P['stubs']['CallReturn']())

        def irelative_resolver(resolver_addr):
            # autohooking runs before this does, might have provided this already
            if self.project.is_hooked(resolver_addr):
                return

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

    def _weak_hook_symbol(self, name, hook, scope=None):
        if scope is None:
            sym = self.project.loader.find_symbol(name)
        else:
            sym = scope.get_symbol(name)

        if sym is not None:
            if self.project.is_hooked(sym.rebased_addr):
                if not self.project.hooked_by(sym.rebased_addr).is_stub:
                    return
            self.project.hook(sym.rebased_addr, hook)

    def state_blank(self, addr=None, initial_prefix=None, stack_size=1024*1024*8, **kwargs):
        """
        Initialize a blank state.

        All parameters are optional.

        :param addr:            The execution start address.
        :param initial_prefix:
        :param stack_size:      The number of bytes to allocate for stack space
        :return:                The initialized SimState.

        Any additional arguments will be passed to the SimState constructor
        """
        # TODO: move ALL of this into the SimState constructor
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
            permissions_backer = (self.project.loader.main_object.execstack, permission_map)
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

    def prepare_function_symbol(self, symbol_name, basic_addr=None):
        """
        Prepare the address space with the data necessary to perform relocations pointing to the given symbol

        Returns a 2-tuple. The first item is the address of the function code, the second is the address of the
        relocation target.
        """
        if basic_addr is None:
            basic_addr = self.project.loader.extern_object.get_pseudo_addr(symbol_name)
        return basic_addr, basic_addr


class SimLinux(SimOS):
    """
    OS-specific configuration for \\*nix-y OSes.
    """

    def __init__(self, *args, **kwargs):
        super(SimLinux, self).__init__(*args, name="Linux", **kwargs)

        self._loader_addr = None
        self._loader_lock_addr = None
        self._loader_unlock_addr = None
        self._vsyscall_addr = None
        self.syscall_library = L['linux']
        self.kernel_base = self.project.loader.kernel_object.mapped_base

    def configure_project(self):
        super(SimLinux, self).configure_project()

        self._loader_addr = self.project.loader.extern_object.allocate()
        self._loader_lock_addr = self.project.loader.extern_object.allocate()
        self._loader_unlock_addr = self.project.loader.extern_object.allocate()
        self._error_catch_tsd_addr = self.project.loader.extern_object.allocate()
        self._vsyscall_addr = self.project.loader.extern_object.allocate()
        self.project.hook(self._loader_addr, P['linux_loader']['LinuxLoader']())
        self.project.hook(self._loader_lock_addr, P['linux_loader']['_dl_rtld_lock_recursive']())
        self.project.hook(self._loader_unlock_addr, P['linux_loader']['_dl_rtld_unlock_recursive']())
        self.project.hook(self._error_catch_tsd_addr, P['linux_loader']['_dl_initial_error_catch_tsd'](static_addr=self.project.loader.extern_object.allocate()))
        self.project.hook(self._vsyscall_addr, P['linux_kernel']['_vsyscall']())

        ld_obj = self.project.loader.linux_loader_object
        if ld_obj is not None:
            # there are some functions we MUST use the simprocedures for, regardless of what the user wants
            self._weak_hook_symbol('__tls_get_addr', L['ld.so'].get('__tls_get_addr', self.arch), ld_obj)
            self._weak_hook_symbol('___tls_get_addr', L['ld.so'].get('___tls_get_addr', self.arch), ld_obj)

            # set up some static data in the loader object...
            _rtld_global = ld_obj.get_symbol('_rtld_global')
            if _rtld_global is not None:
                if isinstance(self.project.arch, ArchAMD64):
                    self.project.loader.memory.write_addr_at(_rtld_global.rebased_addr + 0xF08, self._loader_lock_addr)
                    self.project.loader.memory.write_addr_at(_rtld_global.rebased_addr + 0xF10, self._loader_unlock_addr)
                    self.project.loader.memory.write_addr_at(_rtld_global.rebased_addr + 0x990, self._error_catch_tsd_addr)

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
        if isinstance(self.project.loader.main_object, MetaELF):
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
                        gotaddr = reloc.rebased_addr
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
                        randaddr = self.project.loader.extern_object.allocate()
                        self.project.hook(randaddr, P['linux_loader']['IFuncResolver'](**kwargs))
                        self.project.loader.memory.write_addr_at(gotaddr, randaddr)

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

        last_addr = self.project.loader.main_object.max_addr
        brk = last_addr - last_addr % 0x1000 + 0x1000

        state.register_plugin('posix', SimStateSystem(fs=fs, concrete_fs=concrete_fs, chroot=chroot, brk=brk))

        if self.project.loader.main_object.is_ppc64_abiv1:
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
                    if self.project.loader.main_object.is_ppc64_abiv1:
                        state.registers.store(reg, self.project.loader.main_object.ppc64_initial_rtoc)
                elif val == 'thread_pointer':
                    state.registers.store(reg, self.project.loader.tls_object.user_thread_pointer)
                else:
                    l.warning('Unknown entry point register value indicator "%s"', val)
            else:
                l.error('What the ass kind of default value is %s?', val)

    def state_full_init(self, **kwargs):
        kwargs['addr'] = self._loader_addr
        return super(SimLinux, self).state_full_init(**kwargs)

    def prepare_function_symbol(self, symbol_name, basic_addr=None):
        """
        Prepare the address space with the data necessary to perform relocations pointing to the given symbol.

        Returns a 2-tuple. The first item is the address of the function code, the second is the address of the
        relocation target.
        """
        if self.project.loader.main_object.is_ppc64_abiv1:
            if basic_addr is not None:
                pointer = self.project.loader.memory.read_addr_at(basic_addr)
                return pointer, basic_addr

            pseudo_hookaddr = self.project.loader.extern_object.get_pseudo_addr(symbol_name)
            pseudo_toc = self.project.loader.extern_object.allocate(size=0x18)
            self.project.loader.extern_object.memory.write_addr_at(AT.from_mva(pseudo_toc, self.project.loader.extern_object).to_rva(), pseudo_hookaddr)
            return pseudo_hookaddr, pseudo_toc
        else:
            if basic_addr is None:
                basic_addr = self.project.loader.extern_object.get_pseudo_addr(symbol_name)
            return basic_addr, basic_addr


class SimCGC(SimOS):
    """
    Environment configuration for the CGC DECREE platform
    """
    def __init__(self, *args, **kwargs):
        super(SimCGC, self).__init__(*args, name="CGC", **kwargs)

        self.syscall_library = L['cgcabi']
        self.kernel_base = self.project.loader.kernel_object.mapped_base

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
        s.unicorn.transmit_addr = self.syscall_from_number(2).addr

        return s

    def state_entry(self, **kwargs):
        if isinstance(self.project.loader.main_object, BackedCGC):
            kwargs['permissions_backer'] = (True, self.project.loader.main_object.permissions_map)
        kwargs['add_options'] = {o.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY} | kwargs.get('add_options', set())

        state = super(SimCGC, self).state_entry(**kwargs)

        if isinstance(self.project.loader.main_object, BackedCGC):
            for reg, val in self.project.loader.main_object.initial_register_values():
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
            state.cgc.allocation_base = self.project.loader.main_object.current_allocation_base

            # Do all the writes
            writes_backer = self.project.loader.main_object.writes_backer
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


class SimWindows(SimOS):
    def __init__(self, project):
        super(SimWindows, self).__init__(project)
        self.kernel_base = self.project.loader.kernel_object.mapped_base

    def configure_project(self):
        # here are some symbols which we MUST hook, regardless of what the user wants
        self._weak_hook_symbol('GetProcAddress', L['kernel32.dll'].get('GetProcAddress', self.arch))
        self._weak_hook_symbol('LoadLibraryA', L['kernel32.dll'].get('LoadLibraryA', self.arch))
        self._weak_hook_symbol('LoadLibraryExW', L['kernel32.dll'].get('LoadLibraryExW', self.arch))

    def state_entry(self, args=None, **kwargs):
        if args is None: args = []
        state = super(SimWindows, self).state_entry(**kwargs)
        state.regs.sp = state.regs.sp - 0x80    # give us some stack space to work with...?

        return state

    def state_blank(self, **kwargs):
        if self.project.loader.main_object.supports_nx:
            add_options = kwargs.get('add_options', set())
            add_options.add(o.ENABLE_NX)
            kwargs['add_options'] = add_options
        state = super(SimWindows, self).state_blank(**kwargs)

        # yikes!!!
        fun_stuff_addr = state.libc.mmap_base
        if fun_stuff_addr & 0xffff != 0:
            fun_stuff_addr += 0x10000 - (fun_stuff_addr & 0xffff)
        state.libc.mmap_base = fun_stuff_addr + 0x5000
        state.memory.map_region(fun_stuff_addr, 0x5000, claripy.BVV(3, 3))

        TIB_addr = fun_stuff_addr
        PEB_addr = fun_stuff_addr + 0x1000
        LDR_addr = fun_stuff_addr + 0x2000

        if state.arch.name == 'X86':
            state.mem[TIB_addr + 0].dword = 0 # Initial SEH frame
            state.mem[TIB_addr + 4].dword = state.regs.sp # stack base (high addr)
            state.mem[TIB_addr + 8].dword = state.regs.sp - 0x100000 # stack limit (low addr)
            state.mem[TIB_addr + 0x18].dword = TIB_addr # myself!
            state.mem[TIB_addr + 0x24].dword = 0xbad76ead # thread id
            if self.project.loader.tls_object is not None:
                state.mem[TIB_addr + 0x2c].dword = self.project.loader.tls_object.user_thread_pointer # tls array pointer
            state.mem[TIB_addr + 0x30].dword = PEB_addr # PEB addr, of course

            state.regs.fs = TIB_addr >> 16

            state.mem[PEB_addr + 0xc].dword = LDR_addr

            # OKAY IT'S TIME TO SUFFER
            # http://sandsprite.com/CodeStuff/Understanding_the_Peb_Loader_Data_List.html
            THUNK_SIZE = 0x100
            num_pe_objects = len(self.project.loader.all_pe_objects)
            ALLOC_AREA = LDR_addr + THUNK_SIZE * num_pe_objects
            for i, obj in enumerate(self.project.loader.all_pe_objects):
                # Create a LDR_MODULE, we'll handle the links later...
                obj.module_id = i+1 # HACK HACK HACK HACK
                addr = LDR_addr + (i+1) * THUNK_SIZE
                state.mem[addr+0x18].dword = obj.mapped_base
                state.mem[addr+0x1C].dword = obj.entry

                # Allocate some space from the same region to store the paths
                path = obj.binary # we're in trouble if this is None
                alloc_size = len(path) * 2 + 2
                tail_start = (len(path) - len(os.path.basename(path))) * 2
                state.mem[addr+0x24].short = alloc_size
                state.mem[addr+0x26].short = alloc_size
                state.mem[addr+0x28].dword = ALLOC_AREA
                state.mem[addr+0x2C].short = alloc_size - tail_start
                state.mem[addr+0x2E].short = alloc_size - tail_start
                state.mem[addr+0x30].dword = ALLOC_AREA + tail_start

                for j, c in enumerate(path):
                    # if this segfaults, increase the allocation size
                    state.mem[ALLOC_AREA + j*2].short = ord(c)
                state.mem[ALLOC_AREA + alloc_size - 2].short = 0
                ALLOC_AREA += alloc_size

            # handle the links. we construct a python list in the correct order for each, and then, uh,
            mem_order = sorted(self.project.loader.all_pe_objects, key=lambda x: x.mapped_base)
            init_order = []
            partially_loaded = set()
            def fuck_load(x):
                if x.provides in partially_loaded:
                    return
                partially_loaded.add(x.provides)
                for dep in x.deps:
                    if dep in self.project.loader.shared_objects:
                        depo = self.project.loader.shared_objects[dep]
                        fuck_load(depo)
                        init_order.append(depo)

            fuck_load(self.project.loader.main_object)
            load_order = [self.project.loader.main_object] + init_order

            def link(a, b):
                state.mem[a].dword = b
                state.mem[b+4].dword = a

            # I have genuinely never felt so dead in my life as I feel writing this code
            def link_list(mods, offset):
                if mods:
                    addr_a = LDR_addr + 12
                    addr_b = LDR_addr + THUNK_SIZE * mods[0].module_id
                    link(addr_a + offset, addr_b + offset)
                    for mod_a, mod_b in zip(mods[:-1], mods[1:]):
                        addr_a = LDR_addr + THUNK_SIZE * mod_a.module_id
                        addr_b = LDR_addr + THUNK_SIZE * mod_b.module_id
                        link(addr_a + offset, addr_b + offset)
                    addr_a = LDR_addr + THUNK_SIZE * mods[-1].module_id
                    addr_b = LDR_addr + 12
                    link(addr_a + offset, addr_b + offset)
                else:
                    link(LDR_addr + 12, LDR_addr + 12)

            link_list(load_order, 0)
            link_list(mem_order, 8)
            link_list(init_order, 16)

        return state


os_mapping = defaultdict(lambda: SimOS)


def register_simos(name, cls):
    os_mapping[name] = cls

register_simos('unix', SimLinux)
register_simos('windows', SimWindows)
register_simos('cgc', SimCGC)
