import logging
import struct
from typing import Optional

import angr # for types

import claripy
from archinfo import ArchMIPS32, ArchS390X

from ..errors import (
    AngrCallableError,
    AngrCallableMultistateError,
    AngrSimOSError,
)
from ..sim_state import SimState
from ..state_plugins import SimSystemPosix
from ..calling_conventions import DEFAULT_CC
from ..procedures import SIM_PROCEDURES as P
from .. import sim_options as o
from ..storage.file import SimFileStream, SimFileBase


_l = logging.getLogger(name=__name__)


class SimOS:
    """
    A class describing OS/arch-level configuration.
    """

    def __init__(self, project: 'angr.Project', name=None):
        self.arch = project.arch
        self.project = project
        self.name = name
        self.return_deadend = None
        self.unresolvable_jump_target = None
        self.unresolvable_call_target = None

    def configure_project(self):
        """
        Configure the project to set up global settings (like SimProcedures).
        """
        self.return_deadend = self.project.loader.extern_object.allocate()
        self.project.hook(self.return_deadend, P['stubs']['CallReturn']())

        self.unresolvable_jump_target = self.project.loader.extern_object.allocate()
        self.project.hook(self.unresolvable_jump_target, P['stubs']['UnresolvableJumpTarget']())
        self.unresolvable_call_target = self.project.loader.extern_object.allocate()
        self.project.hook(self.unresolvable_call_target, P['stubs']['UnresolvableCallTarget']())

        def irelative_resolver(resolver_addr):
            # autohooking runs before this does, might have provided this already
            # in that case, we want to advertise the _resolver_ address, since it is now
            # providing the behavior of the actual function
            if self.project.is_hooked(resolver_addr):
                return resolver_addr


            base_state = self.state_blank(addr=0,
                add_options={o.SYMBOL_FILL_UNCONSTRAINED_MEMORY, o.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
            prototype = 'void *x(long)' if isinstance(self.arch, ArchS390X) else 'void *x(void)'
            resolver = self.project.factory.callable(
                resolver_addr,
                concrete_only=True,
                base_state=base_state,
                prototype=prototype)
            try:
                if isinstance(self.arch, ArchS390X):
                    # On s390x ifunc resolvers expect hwcaps.
                    val = resolver(0)
                else:
                    val = resolver()
            except AngrCallableMultistateError:
                _l.error("Resolver at %#x failed to resolve! (multivalued)", resolver_addr)
                return None
            except AngrCallableError:
                _l.error("Resolver at %#x failed to resolve!", resolver_addr)
                return None

            return val._model_concrete.value

        self.project.loader.perform_irelative_relocs(irelative_resolver)

    def _weak_hook_symbol(self, name, hook, scope=None):
        if scope is None:
            sym = self.project.loader.find_symbol(name)
        else:
            sym = scope.get_symbol(name)

        if sym is not None:
            addr, _ = self.prepare_function_symbol(name, basic_addr=sym.rebased_addr)
            if self.project.is_hooked(addr):
                if not self.project.hooked_by(addr).is_stub:
                    return
            self.project.hook(addr, hook)

    def state_blank(self, addr=None, initial_prefix=None, brk=None, stack_end=None, stack_size=1024*1024*8, stdin=None,
                    thread_idx=None, permissions_backer=None, **kwargs):
        """
        Initialize a blank state.

        All parameters are optional.

        :param addr:            The execution start address.
        :param initial_prefix:
        :param stack_end:       The end of the stack (i.e., the byte after the last valid stack address).
        :param stack_size:      The number of bytes to allocate for stack space
        :param brk:             The address of the process' break.
        :return:                The initialized SimState.

        Any additional arguments will be passed to the SimState constructor
        """
        # TODO: move ALL of this into the SimState constructor
        if kwargs.get('mode', None) is None:
            kwargs['mode'] = self.project._default_analysis_mode
        if permissions_backer is not None:
            kwargs['permissions_map'] = permissions_backer[1]
            kwargs['default_permissions'] = 7 if permissions_backer[0] else 3
        if kwargs.get('cle_memory_backer', None) is None:
            kwargs['cle_memory_backer'] = self.project.loader
        if kwargs.get('os_name', None) is None:
            kwargs['os_name'] = self.name
        actual_stack_end = stack_end
        if stack_end is None:
            stack_end = self.arch.initial_sp

        if kwargs.get('permissions_map', None) is None:
            # just a dict of address ranges to permission bits
            permission_map = { }
            for obj in self.project.loader.all_objects:
                for seg in obj.segments:
                    perms = 0
                    # bit values based off of protection bit values from sys/mman.h
                    if seg.is_readable:
                        perms |= 1  # PROT_READ
                    if seg.is_writable:
                        perms |= 2  # PROT_WRITE
                    if seg.is_executable:
                        perms |= 4  # PROT_EXEC
                    permission_map[(seg.min_addr, seg.max_addr)] = perms
            kwargs['permissions_map'] = permission_map
        if self.project.loader.main_object.execstack:
            stack_perms = 1 | 2 | 4  # RWX
        else:
            stack_perms = 1 | 2  # RW

        state = SimState(self.project, stack_end=stack_end, stack_size=stack_size, stack_perms=stack_perms, **kwargs)

        if stdin is not None and not isinstance(stdin, SimFileBase):
            if type(stdin) is type:
                stdin = stdin(name='stdin', has_end=False)
            else:
                if isinstance(stdin, claripy.Bits):
                    num_bytes = len(stdin) // self.project.arch.byte_width
                else:
                    num_bytes = len(stdin)
                _l.warning("stdin is constrained to %d bytes (has_end=True). If you are only providing the first "
                           "%d bytes instead of the entire stdin, please use "
                           "stdin=SimFileStream(name='stdin', content=your_first_n_bytes, has_end=False).",
                           num_bytes, num_bytes)
                stdin = SimFileStream(name='stdin', content=stdin, has_end=True)

        last_addr = self.project.loader.main_object.max_addr
        actual_brk = (last_addr - last_addr % 0x1000 + 0x1000) if brk is None else brk
        state.register_plugin('posix', SimSystemPosix(stdin=stdin, brk=actual_brk))

        if initial_prefix is not None:
            for reg in state.arch.default_symbolic_registers:
                state.registers.store(reg, state.solver.BVS(
                    initial_prefix + "_" + reg,
                    state.arch.bits,
                    explicit_name=True,
                    key=('reg', reg),
                    eternal=True))

        if state.arch.sp_offset is not None:
            state.regs.sp = stack_end

        for reg, val, is_addr, mem_region in state.arch.default_register_values:
            region_base = None  # so pycharm does not complain

            if is_addr:
                if isinstance(mem_region, tuple):
                    # unpack it
                    mem_region, region_base = mem_region
                elif mem_region == 'global':
                    # Backward compatibility
                    region_base = 0
                else:
                    raise AngrSimOSError('You must specify the base address for memory region "%s". ' % mem_region)

            # special case for stack_end overriding sp default
            if actual_stack_end is not None and state.arch.registers[reg][0] == state.arch.sp_offset:
                continue

            if o.ABSTRACT_MEMORY in state.options and is_addr:
                address = claripy.ValueSet(state.arch.bits, mem_region, region_base, val)
                state.registers.store(reg, address)
            else:
                state.registers.store(reg, val)

        if addr is None:
            state.regs.ip = self.project.entry

        thread_name = self.project.loader.main_object.threads[thread_idx] if thread_idx is not None else None
        for reg, val in self.project.loader.main_object.thread_registers(thread_name).items():
            if reg in ('fs', 'gs', 'cs', 'ds', 'es', 'ss') and state.arch.name == 'X86':
                state.registers.store(reg, val >> 16)  # oh boy big hack
            elif reg in state.arch.registers or reg in ('flags', 'eflags', 'rflags'):
                state.registers.store(reg, val)
            elif reg == 'fctrl':
                state.regs.fpround = (val & 0xC00) >> 10
            elif reg == 'fstat':
                state.regs.fc3210 = (val & 0x4700)
            elif reg == 'ftag':
                empty_bools = [((val >> (x * 2)) & 3) == 3 for x in range(8)]
                tag_chars = [claripy.BVV(0 if x else 1, 8) for x in empty_bools]
                for i, tag in enumerate(tag_chars):
                    setattr(state.regs, 'fpu_t%d' % i, tag)
            elif reg in ('fiseg', 'fioff', 'foseg', 'fooff', 'fop'):
                pass
            elif reg == 'mxcsr':
                state.regs.sseround = (val & 0x600) >> 9
            else:
                _l.error("What is this register %s I have to translate?", reg)


        if addr is not None:
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
        prototype = angr.calling_conventions.SimCC.guess_prototype(args, kwargs.pop('prototype', None)).with_arch(self.arch)

        if state is None:
            if stack_base is not None:
                kwargs['stack_end'] = (stack_base + 0x1000) & ~0xfff
            state = self.state_blank(addr=addr, **kwargs)
        else:
            state = state.copy()
            state.regs.ip = addr
        cc.setup_callsite(state, ret_addr, args, prototype, stack_base, alloc_base, grow_like_stack)

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

    def handle_exception(self, successors, engine, exception): # pylint: disable=no-self-use,unused-argument
        """
        Perform exception handling. This method will be called when, during execution, a SimException is thrown.
        Currently, this can only indicate a segfault, but in the future it could indicate any unexpected exceptional
        behavior that can't be handled by ordinary control flow.

        The method may mutate the provided SimSuccessors object in any way it likes, or re-raise the exception.

        :param successors:      The SimSuccessors object currently being executed on
        :param engine:          The engine that was processing this step
        :param exception:       The actual exception object
        """
        raise exception
    # Dummy stuff to allow this API to be used freely

    # pylint: disable=unused-argument, no-self-use
    def syscall(self, state, allow_unsupported=True):
        return None

    def syscall_abi(self, state) -> str:
        return None

    def syscall_cc(self, state) -> Optional[angr.calling_conventions.SimCCSyscall]:
        raise NotImplementedError()

    def is_syscall_addr(self, addr):
        return False

    def syscall_from_addr(self, addr, allow_unsupported=True):
        return None

    def syscall_from_number(self, number, allow_unsupported=True, abi=None):
        return None

    def setup_gdt(self, state, gdt):
        """
        Write the GlobalDescriptorTable object in the current state memory

        :param state: state in which to write the GDT
        :param gdt: GlobalDescriptorTable object
        :return:
        """
        state.memory.store(gdt.addr+8, gdt.table)
        state.regs.gdt = gdt.gdt
        state.regs.cs = gdt.cs
        state.regs.ds = gdt.ds
        state.regs.es = gdt.es
        state.regs.ss = gdt.ss
        state.regs.fs = gdt.fs
        state.regs.gs = gdt.gs

    def generate_gdt(self, fs, gs, fs_size=0xFFFFFFFF, gs_size=0xFFFFFFFF):
        """
        Generate a GlobalDescriptorTable object and populate it using the value of the gs and fs register

        :param fs:      value of the fs segment register
        :param gs:      value of the gs segment register
        :param fs_size: size of the fs segment register
        :param gs_size: size of the gs segment register
        :return: gdt a GlobalDescriptorTable object
        """
        A_PRESENT = 0x80
        A_DATA = 0x10
        A_DATA_WRITABLE = 0x2
        A_PRIV_0 = 0x0
        A_DIR_CON_BIT = 0x4
        F_PROT_32 = 0x4
        S_GDT = 0x0
        S_PRIV_0 = 0x0
        GDT_ADDR = 0x4000
        GDT_LIMIT = 0x1000

        normal_entry = self._create_gdt_entry(0, 0xFFFFFFFF,
                                             A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT,
                                             F_PROT_32)
        stack_entry = self._create_gdt_entry(0, 0xFFFFFFFF, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0,
                                            F_PROT_32)
        fs_entry = self._create_gdt_entry(fs, fs_size,
                                         A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)
        gs_entry = self._create_gdt_entry(gs, gs_size,
                                         A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)

        table = normal_entry + stack_entry + fs_entry + gs_entry
        gdt =  (GDT_ADDR << 16 | GDT_LIMIT)
        selector = self._create_selector(1, S_GDT | S_PRIV_0)
        cs = selector
        ds = selector
        es = selector
        selector = self._create_selector(2, S_GDT | S_PRIV_0)
        ss = selector
        selector = self._create_selector(3, S_GDT | S_PRIV_0)
        fs = selector
        selector = self._create_selector(4, S_GDT | S_PRIV_0)
        gs = selector
        global_descriptor_table = GlobalDescriptorTable(GDT_ADDR, GDT_LIMIT, table, gdt, cs, ds, es, ss, fs, gs)
        return global_descriptor_table

    @staticmethod
    def _create_selector(idx, flags):
        to_ret = flags
        to_ret |= idx << 3
        return to_ret

    @staticmethod
    def _create_gdt_entry(base, limit, access, flags):
        to_ret = limit & 0xffff
        to_ret |= (base & 0xffffff) << 16
        to_ret |= (access & 0xff) << 40
        to_ret |= ((limit >> 16) & 0xf) << 48
        to_ret |= (flags & 0xff) << 52
        to_ret |= ((base >> 24) & 0xff) << 56
        return struct.pack('<Q', to_ret)


class GlobalDescriptorTable:
    def __init__(self, addr, limit, table, gdt_sel, cs_sel, ds_sel, es_sel, ss_sel, fs_sel, gs_sel):
        self.addr = addr
        self.limit = limit
        self.table = table
        self.gdt = gdt_sel
        self.cs = cs_sel
        self.ds = ds_sel
        self.es = es_sel
        self.ss = ss_sel
        self.fs = fs_sel
        self.gs = gs_sel
