"""
Manage OS-level configuration
"""

import logging
l = logging.getLogger("angr.simos")

from archinfo import ArchARM, ArchMIPS32, ArchX86, ArchAMD64
from simuvex import SimState, SimIRSB, SimStateSystem
from simuvex import s_options as o
from simuvex.s_procedure import SimProcedure, SimProcedureContinuation
from simuvex.s_type import SimTypePointer, SimTypeFunction, SimTypeTop
from cle.metaelf import MetaELF

class SimOS(object):
    """A class describing OS/arch-level configuration"""

    def __init__(self, arch, project):
        self.arch = arch
        self.proj = project
        self.continue_addr = None

    def configure_project(self, proj):
        """Configure the project to set up global settings (like SimProcedures)"""
        self.continue_addr = proj.extern_obj.get_pseudo_addr('angr##simproc_continue')
        proj.hook(self.continue_addr, SimProcedureContinuation)

    def make_state(self, **kwargs):
        """Create an initial state"""
        initial_prefix = kwargs.pop("initial_prefix", None)

        state = SimState(arch=self.arch, **kwargs)
        state.regs.sp = self.arch.initial_sp

        if initial_prefix is not None:
            for reg in self.arch.default_symbolic_registers:
                state.registers.store(reg, state.se.Unconstrained(initial_prefix + "_" + reg,
                                                            self.arch.bits,
                                                            explicit_name=True))

        for reg, val, is_addr, mem_region in self.arch.default_register_values:
            if o.ABSTRACT_MEMORY in state.options and is_addr:
                addr = state.se.ValueSet(region=mem_region, bits=self.arch.bits, val=val)
                state.registers.store(reg, addr)
            else:
                state.registers.store(reg, val)

        state.procedure_data.hook_addr = self.continue_addr
        return state

    def prepare_call_state(self, calling_state, initial_state=None,
                           preserve_registers=(), preserve_memory=()):
        '''
        This function prepares a state that is executing a call instruction.
        If given an initial_state, it copies over all of the critical registers to it from the
        calling_state. Otherwise, it prepares the calling_state for action.

        This is mostly used to create minimalistic for CFG generation. Some ABIs, such as MIPS PIE and
        x86 PIE, require certain information to be maintained in certain registers. For example, for
        PIE MIPS, this function transfer t9, gp, and ra to the new state.
        '''

        if isinstance(self.arch, ArchMIPS32):
            if initial_state is not None:
                initial_state = self.make_state()
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

class SimPosix(SimOS):
    """OS-specific configuration for POSIX-y OSes"""
    def __init__(self, *args, **kwargs):
        super(SimPosix, self).__init__(*args, **kwargs)

        self._loader_addr = None
        self._loader_lock_addr = None
        self._loader_unlock_addr = None
        self._vsyscall_addr = None

    def configure_project(self, proj):
        super(SimPosix, self).configure_project(proj)

        self._loader_addr = proj.extern_obj.get_pseudo_addr('angr##loader')
        self._loader_lock_addr = proj.extern_obj.get_pseudo_addr('angr##loader_lock')
        self._loader_unlock_addr = proj.extern_obj.get_pseudo_addr('angr##loader_unlock')
        self._vsyscall_addr = proj.extern_obj.get_pseudo_addr('angr##vsyscall')
        proj.hook(self._loader_addr, LinuxLoader, kwargs={'ld': proj.ld})
        proj.hook(self._loader_lock_addr, _dl_rtld_lock_recursive)
        proj.hook(self._loader_unlock_addr, _dl_rtld_unlock_recursive)
        proj.hook(self._vsyscall_addr, _vsyscall)

        ld_obj = proj.ld.linux_loader_object
        if ld_obj is not None:
            tlsfunc = ld_obj.get_symbol('__tls_get_addr')
            if tlsfunc is not None:
                proj.hook(tlsfunc.rebased_addr, _tls_get_addr, kwargs={'ld': proj.ld})

            _rtld_global = ld_obj.get_symbol('_rtld_global')
            if _rtld_global is not None:
                if proj.arch.name == 'AMD64':
                    proj.ld.memory.write_addr_at(_rtld_global.rebased_addr + 0xF08, self._loader_lock_addr)
                    proj.ld.memory.write_addr_at(_rtld_global.rebased_addr + 0xF10, self._loader_unlock_addr)

            _rtld_global_ro = ld_obj.get_symbol('_rtld_global_ro')
            if _rtld_global_ro is not None:
                pass

        tls_obj = proj.ld.tls_object
        if tls_obj is not None:
            if proj.arch.name == 'X86':
                proj.ld.memory.write_addr_at(tls_obj.thread_pointer + 0x10, self._vsyscall_addr)


        # Only calls setup_elf_ifuncs() if we are using the ELF backend on AMD64
        if isinstance(proj.main_binary, MetaELF):
            if isinstance(proj.arch, ArchAMD64):
                setup_elf_ifuncs(proj)

    def make_state(self, fs=None, **kwargs):
        s = super(SimPosix, self).make_state(**kwargs) #pylint:disable=invalid-name
        s = setup_elf_tls(self.proj, s)
        s.register_plugin('posix', SimStateSystem(fs=fs))

        return s

class SimLinux(SimPosix): # no, not a conference...
    """OS-specific configuration for Linux"""
    def configure_project(self, proj):
        super(SimLinux, self).configure_project(proj)
        if isinstance(self.arch, ArchARM):
            # set up kernel-user helpers
            pass

    def make_state(self, **kwargs):
        s = super(SimLinux, self).make_state(**kwargs) #pylint:disable=invalid-name

        return s

def setup_elf_tls(proj, s):
    if proj.ld.tls_object is not None:
        if isinstance(s.arch, ArchAMD64):
            s.regs.fs = proj.ld.tls_object.thread_pointer
        elif isinstance(s.arch, ArchX86):
            s.regs.gs = proj.ld.tls_object.thread_pointer >> 16
    return s

def setup_elf_ifuncs(proj):
    for binary in proj.ld.all_objects:
        if not isinstance(binary, MetaELF):
            continue
        for reloc in binary.relocs:
            if reloc.symbol is None or reloc.resolvedby is None:
                continue
            if reloc.resolvedby.type != 'STT_GNU_IFUNC':
                continue
            gotaddr = reloc.addr + binary.rebase_addr
            gotvalue = proj.ld.memory.read_addr_at(gotaddr)
            if proj.is_hooked(gotvalue):
                continue
            # Replace it with a ifunc-resolve simprocedure!
            resolver = make_ifunc_resolver(proj, gotvalue, gotaddr, reloc.symbol.name)
            randaddr = int(hash(('ifunc', gotvalue, gotaddr)) % 2**proj.arch.bits)
            proj.hook(randaddr, resolver)
            proj.ld.memory.write_addr_at(gotaddr, randaddr)

def make_ifunc_resolver(proj, funcaddr, gotaddr, funcname):
    class IFuncResolver(SimProcedure):
        def run(self):
            resolve = Callable(proj, funcaddr, SimTypeFunction((), SimTypePointer(self.state.arch, SimTypeTop())))
            try:
                value = resolve()
            except AngrCallableError:
                l.critical("Ifunc failed to resolve!")
                #import IPython; IPython.embed()
                raise
            self.state.memory.store(gotaddr, value, endness=self.state.arch.memory_endness)
            self.add_successor(self.state, value, self.state.se.true, 'Ijk_Boring')

        def __repr__(self):
            return '<IFuncResolver %s>' % funcname
    return IFuncResolver

class LinuxLoader(SimProcedure):
    # pylint: disable=unused-argument,arguments-differ,attribute-defined-outside-init
    local_vars = ('initializers',)
    def run(self, ld=None):
        self.initializers = ld.get_initializers()
        self.run_initializer(ld)

    def run_initializer(self, ld=None):
        if len(self.initializers) == 0:
            # There's a copy of this block in state_generator.entry_point
            # drop in all the register values at the entry point
            for reg, val in self.state.arch.entry_register_values.iteritems():
                if isinstance(val, (int, long)):
                    self.state.registers.store(reg, val, size=self.state.arch.bytes)
                elif isinstance(val, (str,)):
                    if val == 'argc':
                        self.state.registers.store(reg, self.state.posix.argc, size=self.state.arch.bytes)
                    elif val == 'argv':
                        self.state.registers.store(reg, self.state.posix.argv)
                    elif val == 'envp':
                        self.state.registers.store(reg, self.state.posix.environ)
                    elif val == 'auxv':
                        self.state.registers.store(reg, self.state.posix.auxv)
                    elif val == 'ld_destructor':
                        # a pointer to the dynamic linker's destructor routine, to be called at exit
                        # or NULL. We like NULL. It makes things easier.
                        self.state.registers.store(reg, self.state.BVV(0, self.state.arch.bits))
                    elif val == 'toc':
                        if ld.main_bin.ppc64_initial_rtoc is not None:
                            self.state.registers.store(reg, ld.main_bin.ppc64_initial_rtoc)
                            self.state.libc.ppc64_abiv = 'ppc64_1'
                    else:
                        l.warning('Unknown entry point register value indicator "%s"', val)
                else:
                    l.error('What the ass kind of default value is %s?', val)

            self.jump(ld.main_bin.entry)
        else:
            addr = self.initializers.pop(0)
            self.call(addr, (self.state.posix.argc, self.state.posix.argv, self.state.posix.environ), 'run_initializer')

class _tls_get_addr(SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, ptr, ld=None):
        module_id = self.state.memory.load(ptr, self.state.arch.bytes, endness=self.state.arch.memory_endness).model.value
        offset = self.state.memory.load(ptr+self.state.arch.bytes, self.state.arch.bytes, endness=self.state.arch.memory_endness).model.value
        return self.state.BVV(ld.tls_object.get_addr(module_id, offset), self.state.arch.bits)

class _dl_rtld_lock_recursive(SimProcedure):
    # pylint: disable=arguments-differ, unused-argument
    def run(self, lock):
        # For future reference:
        # ++((pthread_mutex_t *)(lock))->__data.__count;
        self.ret()

class _dl_rtld_unlock_recursive(SimProcedure):
    def run(self):
        self.ret()

class _vsyscall(SimProcedure):
    # This is pretty much entirely copied from SimProcedure.ret
    def run(self):
        if self.cleanup:
            self.state.options.discard(o.AST_DEPS)
            self.state.options.discard(o.AUTO_REFS)

        ret_irsb = self.state.arch.disassemble_vex(self.state.arch.ret_instruction, mem_addr=self.addr)
        ret_simirsb = SimIRSB(self.state, ret_irsb, inline=True, addr=self.addr)
        if not ret_simirsb.flat_successors + ret_simirsb.unsat_successors:
            ret_state = ret_simirsb.default_exit
        else:
            ret_state = (ret_simirsb.flat_successors + ret_simirsb.unsat_successors)[0]

        if self.cleanup:
            self.state.options.add(o.AST_DEPS)
            self.state.options.add(o.AUTO_REFS)

        self.add_successor(ret_state, ret_state.scratch.target, ret_state.scratch.guard, 'Ijk_Sys')

from .surveyors.caller import Callable
from .errors import AngrCallableError

class SimCGC(SimOS):
    def __init__(self, arch, proj):
        arch = ArchX86()
        SimOS.__init__(self, arch, proj)

    def make_state(self, fs=None, **kwargs):
        s = super(SimCGC, self).make_state(**kwargs)  # pylint:disable=invalid-name

        s.register_plugin('posix', SimStateSystem(fs=fs))

        # Create the CGC plugin
        s.get_plugin('cgc')

        # Set CGC-specific options
        #s.options.add(o.CGC_NO_SYMBOLIC_RECEIVE_LENGTH)
        s.options.add(o.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY)

        return s

os_mapping = {
    'unix': SimLinux,
    'unknown': SimOS,
    'windows': SimOS,
    'cgc': SimCGC
}
