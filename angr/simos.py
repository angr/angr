"""
Manage OS-level configuration
"""

import logging
l = logging.getLogger("angr.simos")

from archinfo import ArchARM, ArchMIPS32, ArchX86, ArchAMD64
from simuvex import SimState, s_options, SimProcedure
from simuvex.s_type import SimTypePointer, SimTypeFunction, SimTypeTop
from simuvex.plugins.posix import SimStateSystem
from cle.metaelf import MetaELF

class SimOS(object):
    """A class describing OS/arch-level configuration"""

    def __init__(self, arch, project):
        self.arch = arch
        self.proj = project

    def configure_project(self, proj):
        """Configure the project to set up global settings (like SimProcedures)"""
        pass

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
            if s_options.ABSTRACT_MEMORY in state.options and is_addr:
                addr = state.se.ValueSet(region=mem_region, bits=self.arch.bits, val=val)
                state.registers.store(reg, addr)
            else:
                state.registers.store(reg, val)

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
    def configure_project(self, proj):
        super(SimPosix, self).configure_project(proj)

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
    if isinstance(s.arch, ArchAMD64):
        tls_addr = 0x16000000
        for mod_id, so in enumerate(proj.ld.shared_objects.itervalues()):
            for i, byte in enumerate(so.tls_init_image):
                s.memory.store(tls_addr + i, s.se.BVV(ord(byte), 8))
            s.posix.tls_modules[mod_id] = tls_addr
            tls_addr += len(so.tls_init_image)

        dtv_entry = 0xff000000000
        dtv_base = 0x8000000000000000

        s.regs.fs = 0x9000000000000000

        s.memory.store(dtv_base + 0x00, s.se.BVV(dtv_entry, 64), endness='Iend_LE')
        s.memory.store(dtv_base + 0x08, s.se.BVV(1, 8))

        s.memory.store(s.regs.fs + 0x00, s.regs.fs, endness='Iend_LE') # tcb
        s.memory.store(s.regs.fs + 0x08, s.se.BVV(dtv_base, 64), endness='Iend_LE') # dtv
        s.memory.store(s.regs.fs + 0x10, s.se.BVV(0x12345678, 64)) # self
        s.memory.store(s.regs.fs + 0x18, s.se.BVV(0x1, 32), endness='Iend_LE') # multiple_threads
        s.memory.store(s.regs.fs + 0x28, s.se.BVV(0x5f43414e4152595f, 64), endness='Iend_LE')
    elif isinstance(s.arch, ArchX86):
        # untested :)
        thread_addr = 0x90000000
        dtv_entry = 0x15000000 # let's hope there's nothing here...
        dtv_base = 0x16000000 # same

        s.regs.gs = s.se.BVV(thread_addr >> 16, 16)

        s.memory.store(dtv_base + 0x00, s.se.BVV(dtv_entry, 32), endness='Iend_LE')
        s.memory.store(dtv_base + 0x04, s.se.BVV(1, 8))

        s.memory.store(thread_addr + 0x00, s.se.BVV(thread_addr, 32), endness='Iend_LE') # tcb
        s.memory.store(thread_addr + 0x04, s.se.BVV(dtv_base, 32), endness='Iend_LE') # dtv
        s.memory.store(thread_addr + 0x08, s.se.BVV(0x12345678, 32)) # self
        s.memory.store(thread_addr + 0x0c, s.se.BVV(0x1, 32), endness='Iend_LE') # multiple_threads
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
                import IPython; IPython.embed()
                raise
            self.state.memory.store(gotaddr, value, endness=self.state.arch.memory_endness)
            self.add_successor(self.state, value, self.state.se.true, 'Ijk_Boring')

        def __repr__(self):
            return '<IFuncResolver %s>' % funcname
    return IFuncResolver

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
        #s.options.add(s_options.CGC_NO_SYMBOLIC_RECEIVE_LENGTH)
        s.options.add(s_options.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY)

        return s

os_mapping = {
    'unix': SimLinux,
    'unknown': SimOS,
    'cgc': SimCGC
}
