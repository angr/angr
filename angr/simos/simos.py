import logging

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
from ..misc import IRange


_l = logging.getLogger("angr.simos.simos")


class SimOS(object):
    """
    A class describing OS/arch-level configuration.
    """

    def __init__(self, project, name=None):
        self.arch = project.arch
        self.project = project
        self.name = name
        self.return_deadend = None
        self.unresolvable_target = None

    def configure_project(self):
        """
        Configure the project to set up global settings (like SimProcedures).
        """
        self.return_deadend = self.project.loader.extern_object.allocate()
        self.project.hook(self.return_deadend, P['stubs']['CallReturn']())

        self.unresolvable_target = self.project.loader.extern_object.allocate()
        self.project.hook(self.unresolvable_target, P['stubs']['UnresolvableTarget']())

        def irelative_resolver(resolver_addr):
            # autohooking runs before this does, might have provided this already
            # in that case, we want to advertise the _resolver_ address, since it is now
            # providing the behavior of the actual function
            if self.project.is_hooked(resolver_addr):
                return resolver_addr

            resolver = self.project.factory.callable(resolver_addr, concrete_only=True)
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
            if self.project.is_hooked(sym.rebased_addr):
                if not self.project.hooked_by(sym.rebased_addr).is_stub:
                    return
            self.project.hook(sym.rebased_addr, hook)

    def state_blank(self, addr=None, initial_prefix=None, stack_size=1024*1024*8,
            stdin=None, **kwargs):
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
                        perms |= 1  # PROT_READ
                    if seg.is_writable:
                        perms |= 2  # PROT_WRITE
                    if seg.is_executable:
                        perms |= 4  # PROT_EXEC
                    permission_map[(seg.min_addr, seg.max_addr)] = perms
            permissions_backer = (self.project.loader.main_object.execstack, permission_map)
            kwargs['permissions_backer'] = permissions_backer
        if kwargs.get('memory_backer', None) is None:
            kwargs['memory_backer'] = self.project.loader.memory
        if kwargs.get('os_name', None) is None:
            kwargs['os_name'] = self.name

        state = SimState(self.project, **kwargs)

        if stdin is not None and not isinstance(stdin, SimFileBase):
            if type(stdin) is type:
                stdin = stdin(name='stdin', has_end=False)
            else:
                stdin = SimFileStream(name='stdin', content=stdin, has_end=True)

        last_addr = self.project.loader.main_object.max_addr
        brk = last_addr - last_addr % 0x1000 + 0x1000
        state.register_plugin('posix', SimSystemPosix(stdin=stdin, brk=brk))


        stack_end = state.arch.initial_sp
        if o.ABSTRACT_MEMORY not in state.options:
            state.memory.mem._preapproved_stack = IRange(stack_end - stack_size, stack_end)

        if o.INITIALIZE_ZERO_REGISTERS in state.options:
            highest_reg_offset, reg_size = max(state.arch.registers.values())
            for i in range(0, highest_reg_offset + reg_size, state.arch.bytes):
                state.registers.store(i, state.solver.BVV(0, state.arch.bits))
        if state.arch.sp_offset is not None:
            state.regs.sp = stack_end

        if initial_prefix is not None:
            for reg in state.arch.default_symbolic_registers:
                state.registers.store(reg, state.solver.BVS(
                    initial_prefix + "_" + reg,
                    state.arch.bits,
                    explicit_name=True,
                    key=('reg', reg),
                    eternal=True))

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

    def handle_exception(self, successors, engine, exception): # pylint: disable=no-self-use,unused-argument
        """
        Perform exception handling. This method will be called when, during execution, a SimException is thrown.
        Currently, this can only indicate a segfault, but in the future it could indicate any unexpected exceptional
        behavior that can't be handled by ordinary control flow.

        The method may mutate the provided SimSuccessors object in any way it likes, or re-raise the exception.

        :param successors:      The SimSuccessors object currently being executed on
        :param engine:          The engine that was processing this step
        :param exc_type:        The value of sys.exc_info()[0] from the error, the type of the exception that was raised
        :param exc_value:       The value of sys.exc_info()[1] from the error, the actual exception object
        :param exc_traceback:   The value of sys.exc_info()[2] from the error, the traceback from the exception
        """
        raise exception
    # Dummy stuff to allow this API to be used freely

    # pylint: disable=unused-argument, no-self-use
    def syscall(self, state, allow_unsupported=True):
        return None

    def syscall_abi(self, state):
        return None

    def is_syscall_addr(self, addr):
        return False

    def syscall_from_addr(self, addr, allow_unsupported=True):
        return None

    def syscall_from_number(self, number, allow_unsupported=True, abi=None):
        return None
